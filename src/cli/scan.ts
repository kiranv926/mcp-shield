/**
 * taintgate CLI: `scan` command — zero-config static audit of installed MCP servers.
 *
 * `npx taintgate scan` discovers the MCP server configurations a user already has
 * installed across well-known client locations (Claude Desktop, Cursor, Windsurf,
 * VS Code, ...) and risk-scores each declared server with transparent heuristics,
 * printing a readable report and (optionally) machine-readable JSON.
 *
 * SAFETY PROPERTY — this command performs STATIC CONFIG INSPECTION ONLY. It never
 * spawns, executes, or network-connects to any MCP server, and it never runs the
 * `command` it reads out of a config. Everything below is pure string/regex
 * analysis of JSON already sitting on disk, so scanning is side-effect free and
 * safe to run against an untrusted machine.
 */

import { readFileSync, existsSync } from 'node:fs';
import { homedir } from 'node:os';
import { join, resolve, isAbsolute } from 'node:path';

/* ------------------------------------------------------------------------- *
 * Severity model
 * ------------------------------------------------------------------------- */

/** Ordered from least to most alarming; index doubles as the sort/compare rank. */
export const SEVERITY_ORDER = ['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'] as const;
export type Severity = (typeof SEVERITY_ORDER)[number];

/** Numeric rank for a severity (higher = worse). */
function severityRank(sev: Severity): number {
  return SEVERITY_ORDER.indexOf(sev);
}

/* ------------------------------------------------------------------------- *
 * Finding + report shapes
 * ------------------------------------------------------------------------- */

export interface Finding {
  /** Stable machine code for the heuristic that fired, e.g. `secret-in-env`. */
  rule: string;
  severity: Severity;
  /** One-line human explanation of what was detected. */
  message: string;
  /** Actionable remediation hint. */
  remediation: string;
}

export interface ServerReport {
  name: string;
  /** The transport-ish shape we inferred: `stdio` (command) or `remote` (url). */
  kind: 'stdio' | 'remote' | 'unknown';
  command?: string;
  url?: string;
  findings: Finding[];
  /** Highest severity across this server's findings. */
  maxSeverity: Severity;
}

export interface ConfigReport {
  /** Absolute path of the config file scanned. */
  path: string;
  /** Friendly client label, e.g. `Claude Desktop`. */
  client: string;
  servers: ServerReport[];
}

export interface ScanResult {
  configs: ConfigReport[];
  /** Total servers across all configs. */
  serverCount: number;
  /** Count of servers keyed by their highest finding severity. */
  severityCounts: Record<Severity, number>;
  /** Any config paths that existed but failed to parse. */
  parseErrors: Array<{ path: string; error: string }>;
}

/* ------------------------------------------------------------------------- *
 * HEURISTIC TABLE
 *
 * Every risk signal `scan` can emit lives here as data, not scattered magic.
 * To extend detection, add a regex/list and a corresponding branch in
 * `scoreServer`. Kept deliberately explicit and commented so the security
 * rationale of each rule is auditable.
 * ------------------------------------------------------------------------- */

/**
 * Secret-shaped value patterns. Mirrors the token families the runtime redactor
 * cares about; a hit means a live credential is likely sitting in plaintext in a
 * config file (world-readable, synced, backed up, committed...).
 */
const SECRET_VALUE_PATTERNS: ReadonlyArray<{ label: string; re: RegExp }> = [
  { label: 'OpenAI-style key (sk-)', re: /\bsk-[A-Za-z0-9_-]{16,}\b/ },
  { label: 'GitHub token (ghp_/gho_/ghs_/ghr_)', re: /\bgh[posru]_[A-Za-z0-9]{20,}\b/ },
  { label: 'Slack token (xox)', re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/ },
  { label: 'AWS access key id (AKIA)', re: /\bAKIA[0-9A-Z]{16}\b/ },
  { label: 'Google API key (AIza)', re: /\bAIza[0-9A-Za-z_-]{20,}\b/ },
  { label: 'Bearer/JWT-ish token', re: /\bey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{6,}\b/ },
  // Generic high-entropy secret: a long unbroken run of key-ish characters.
  { label: 'long high-entropy string', re: /\b[A-Za-z0-9_\-+/=]{40,}\b/ },
];

/**
 * Env-var NAMES that, regardless of value, indicate a secret is being passed in
 * plaintext. Matched case-insensitively as a substring of the key.
 */
const SECRET_ENV_KEY_HINTS: readonly string[] = [
  'TOKEN',
  'SECRET',
  'PASSWORD',
  'PASSWD',
  'APIKEY',
  'API_KEY',
  'ACCESS_KEY',
  'PRIVATE_KEY',
  'CREDENTIAL',
];

/** Bare env key that only looks secret when it also holds a real-looking value. */
const AMBIGUOUS_SECRET_ENV_KEY_HINTS: readonly string[] = ['KEY', 'AUTH'];

/**
 * Filesystem-scope arguments that grant a filesystem MCP server sweeping reach.
 * An exact match against one of these (after normalizing `$HOME`/`~`) is broad.
 */
const BROAD_FS_PATHS: readonly string[] = ['/', '~', '$HOME', '${HOME}', '%USERPROFILE%'];

/** Commands (basename) that denote a filesystem server whose args are paths. */
const FILESYSTEM_COMMAND_HINTS: readonly string[] = ['server-filesystem', 'filesystem', 'mcp-filesystem'];

/** Package runners that fetch code from the network at launch (supply-chain surface). */
const NETWORK_RUNNERS: readonly string[] = ['npx', 'uvx', 'pnpm', 'bunx', 'yarn', 'pipx'];

/**
 * Command basenames that are database clients / shells / arbitrary executors.
 * `label` feeds the human explanation; `severity` is the floor for that command.
 */
const DANGEROUS_COMMANDS: ReadonlyArray<{ names: readonly string[]; label: string; severity: Severity }> = [
  { names: ['bash', 'sh', 'zsh', 'fish', 'pwsh', 'powershell', 'cmd'], label: 'a raw shell', severity: 'HIGH' },
  { names: ['eval', 'exec'], label: 'an arbitrary code evaluator', severity: 'HIGH' },
  { names: ['psql', 'mysql', 'mongo', 'mongosh', 'redis-cli', 'sqlite3', 'mongod'], label: 'a database client', severity: 'MEDIUM' },
  { names: ['docker', 'kubectl', 'ssh', 'scp', 'curl', 'wget'], label: 'a host/network control tool', severity: 'MEDIUM' },
];

/* ------------------------------------------------------------------------- *
 * Config discovery
 * ------------------------------------------------------------------------- */

interface ConfigLocation {
  client: string;
  path: string;
}

/**
 * Enumerate well-known MCP client config paths for the current platform, plus a
 * couple that are cwd-relative. Existence is checked by the caller — this only
 * builds candidate paths and NEVER throws for an absent one.
 */
function discoverConfigLocations(cwd: string): ConfigLocation[] {
  const home = homedir();
  const appData = process.env['APPDATA'];
  const locations: ConfigLocation[] = [];

  // Claude Desktop — platform specific.
  if (process.platform === 'darwin') {
    locations.push({
      client: 'Claude Desktop',
      path: join(home, 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json'),
    });
  } else if (process.platform === 'win32') {
    if (appData) {
      locations.push({ client: 'Claude Desktop', path: join(appData, 'Claude', 'claude_desktop_config.json') });
    }
  } else {
    locations.push({ client: 'Claude Desktop', path: join(home, '.config', 'Claude', 'claude_desktop_config.json') });
  }

  // Cursor — global + per-project.
  locations.push({ client: 'Cursor', path: join(home, '.cursor', 'mcp.json') });
  locations.push({ client: 'Cursor (project)', path: join(cwd, '.cursor', 'mcp.json') });

  // Windsurf — global.
  locations.push({ client: 'Windsurf', path: join(home, '.codeium', 'windsurf', 'mcp_config.json') });

  // VS Code — per-project.
  locations.push({ client: 'VS Code (project)', path: join(cwd, '.vscode', 'mcp.json') });

  return locations;
}

/* ------------------------------------------------------------------------- *
 * Parsing
 * ------------------------------------------------------------------------- */

/** A single MCP server entry as it appears in a client config (loosely typed). */
interface RawServer {
  command?: unknown;
  args?: unknown;
  env?: unknown;
  url?: unknown;
  type?: unknown;
}

/**
 * Pull the `mcpServers` (or `servers`) map out of a parsed config object.
 * Returns an empty map for anything that doesn't look like a server table.
 */
function extractServers(parsed: unknown): Record<string, RawServer> {
  if (!parsed || typeof parsed !== 'object') return {};
  const obj = parsed as Record<string, unknown>;
  const table = obj['mcpServers'] ?? obj['servers'];
  if (!table || typeof table !== 'object') return {};
  const out: Record<string, RawServer> = {};
  for (const [name, value] of Object.entries(table as Record<string, unknown>)) {
    if (value && typeof value === 'object') out[name] = value as RawServer;
  }
  return out;
}

function asString(v: unknown): string | undefined {
  return typeof v === 'string' ? v : undefined;
}

function asStringArray(v: unknown): string[] {
  return Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : [];
}

function asEnv(v: unknown): Record<string, string> {
  if (!v || typeof v !== 'object') return {};
  const out: Record<string, string> = {};
  for (const [k, val] of Object.entries(v as Record<string, unknown>)) {
    if (typeof val === 'string') out[k] = val;
    else if (typeof val === 'number' || typeof val === 'boolean') out[k] = String(val);
  }
  return out;
}

/** The command basename, stripped of path and extension, lowercased. */
function basename(command: string): string {
  const tail = command.split(/[\\/]/).pop() ?? command;
  return tail.replace(/\.(exe|cmd|bat|sh|mjs|cjs|js)$/i, '').toLowerCase();
}

/* ------------------------------------------------------------------------- *
 * Risk scoring
 * ------------------------------------------------------------------------- */

/** Does an env value look like a real secret? */
function valueLooksSecret(value: string): string | undefined {
  for (const { label, re } of SECRET_VALUE_PATTERNS) {
    if (re.test(value)) return label;
  }
  return undefined;
}

/** Does an env KEY name imply it carries a secret? `strong` keys fire regardless of value. */
function envKeyLooksSecret(key: string): 'strong' | 'ambiguous' | undefined {
  const upper = key.toUpperCase();
  if (SECRET_ENV_KEY_HINTS.some((h) => upper.includes(h))) return 'strong';
  if (AMBIGUOUS_SECRET_ENV_KEY_HINTS.some((h) => upper.includes(h))) return 'ambiguous';
  return undefined;
}

/**
 * Score a single server entry into a list of findings.
 *
 * Pure function of the (already parsed) config data — no I/O, no execution.
 */
function scoreServer(name: string, raw: RawServer): ServerReport {
  const findings: Finding[] = [];
  const command = asString(raw.command);
  const args = asStringArray(raw.args);
  const env = asEnv(raw.env);
  const url = asString(raw.url);
  const kind: ServerReport['kind'] = command ? 'stdio' : url ? 'remote' : 'unknown';

  /* --- Secrets in env ------------------------------------------------------ */
  for (const [key, value] of Object.entries(env)) {
    const valueHit = valueLooksSecret(value);
    const keyHit = envKeyLooksSecret(key);
    if (valueHit) {
      findings.push({
        rule: 'secret-in-env',
        severity: 'HIGH',
        message: `env "${key}" contains a plaintext secret (${valueHit}).`,
        remediation: 'Move this secret out of the config into a runtime-injected env var; do not store live credentials on disk.',
      });
    } else if (keyHit === 'strong' && value.trim() !== '') {
      findings.push({
        rule: 'secret-in-env',
        severity: 'HIGH',
        message: `env "${key}" looks like a credential stored in plaintext.`,
        remediation: 'Inject this at runtime instead of hardcoding it; consider governing the server with `taintgate wrap`.',
      });
    } else if (keyHit === 'ambiguous' && value.trim().length >= 12) {
      findings.push({
        rule: 'secret-in-env',
        severity: 'MEDIUM',
        message: `env "${key}" may hold a credential in plaintext.`,
        remediation: 'If this is a secret, inject it at runtime rather than storing it in the config.',
      });
    }
  }

  /* --- Filesystem scope ---------------------------------------------------- */
  const commandBase = command ? basename(command) : '';
  const looksLikeFsServer =
    FILESYSTEM_COMMAND_HINTS.some((h) => commandBase.includes(h)) ||
    args.some((a) => FILESYSTEM_COMMAND_HINTS.some((h) => a.toLowerCase().includes(h)));
  if (looksLikeFsServer) {
    // Path-shaped args are those that start with / ~ $ % or a drive letter.
    const pathArgs = args.filter((a) => /^([/~]|\$|%|[A-Za-z]:[\\/])/.test(a));
    let flaggedBroad = false;
    for (const p of pathArgs) {
      const normalized = p.replace(/\/+$/, '') || '/';
      const isBroad =
        BROAD_FS_PATHS.includes(p) ||
        BROAD_FS_PATHS.includes(normalized) ||
        normalized === homedir() ||
        normalized === '/Users' ||
        normalized === '/home';
      if (isBroad) {
        flaggedBroad = true;
        findings.push({
          rule: 'filesystem-broad-scope',
          severity: 'HIGH',
          message: `filesystem server is granted a very broad path ("${p}").`,
          remediation: 'Scope this server to the narrowest specific subdirectory it needs instead of the whole drive/home.',
        });
      }
    }
    if (!flaggedBroad && pathArgs.length > 0) {
      findings.push({
        rule: 'filesystem-scoped',
        severity: 'LOW',
        message: `filesystem server is scoped to specific path(s): ${pathArgs.join(', ')}.`,
        remediation: 'Confirm each path is intentional; keep the grant as narrow as possible.',
      });
    }
  }

  /* --- Supply-chain: network package runners ------------------------------- */
  if (command && NETWORK_RUNNERS.includes(commandBase)) {
    // First non-flag arg is the package being pulled (skip -y / --yes / flags).
    const pkg = args.find((a) => !a.startsWith('-'));
    const unscoped = pkg !== undefined && !pkg.startsWith('@');
    const unpinned = pkg !== undefined && !/@[0-9]/.test(pkg.slice(1)); // no @<version> suffix
    if (pkg !== undefined && (unscoped || unpinned)) {
      findings.push({
        rule: 'supply-chain-unpinned',
        severity: 'MEDIUM',
        message: `runs "${commandBase} ${pkg}" which fetches ${unscoped ? 'an unscoped ' : ''}${unpinned ? 'unpinned ' : ''}package from the network at launch.`,
        remediation: 'Pin an exact version (e.g. pkg@1.2.3), prefer a scoped/first-party package, or vendor it locally.',
      });
    }
  }

  /* --- Dangerous commands (shell / db / exec) ------------------------------ */
  if (command) {
    for (const entry of DANGEROUS_COMMANDS) {
      if (entry.names.includes(commandBase)) {
        findings.push({
          rule: 'dangerous-command',
          severity: entry.severity,
          message: `server launches ${entry.label} ("${commandBase}"), giving it direct host/data access.`,
          remediation: 'Restrict what this server can do; governing it with `taintgate wrap` enforces ALLOW/BLOCK/REDACT on its calls.',
        });
        break;
      }
    }
  }

  /* --- Remote URL servers -------------------------------------------------- */
  if (url) {
    let parsedUrl: URL | undefined;
    try {
      parsedUrl = new URL(url);
    } catch {
      parsedUrl = undefined;
    }
    if (parsedUrl) {
      const host = parsedUrl.hostname;
      const isLocal = host === 'localhost' || host === '127.0.0.1' || host === '::1' || host === '0.0.0.0';
      const isHttp = parsedUrl.protocol === 'http:';
      if (isHttp && !isLocal) {
        findings.push({
          rule: 'remote-insecure',
          severity: 'HIGH',
          message: `remote server uses plaintext http:// to a non-local host (${host}); traffic and tokens are exposed.`,
          remediation: 'Use https:// for any non-localhost MCP endpoint.',
        });
      } else if (!isLocal) {
        findings.push({
          rule: 'remote-external',
          severity: 'MEDIUM',
          message: `server connects to an external remote endpoint (${host}); tool traffic leaves your machine.`,
          remediation: 'Confirm this endpoint is trusted; consider fronting it with `taintgate wrap` to govern its tool calls.',
        });
      } else if (isHttp) {
        findings.push({
          rule: 'remote-localhost',
          severity: 'INFO',
          message: `remote server points at localhost (${host}).`,
          remediation: 'Local endpoints are lower risk; no action needed unless the port is externally reachable.',
        });
      }
    }
  }

  /* --- Uncategorized ------------------------------------------------------- */
  if (findings.length === 0) {
    findings.push({
      rule: 'uncategorized',
      severity: 'INFO',
      message:
        kind === 'unknown'
          ? 'server has neither a command nor a url; nothing to assess.'
          : `no known risk signals matched for ${kind === 'remote' ? `url ${url}` : `command "${commandBase}"`}; could not assess.`,
      remediation: 'Review manually. Unknown does not mean safe — verify what this server can access.',
    });
  }

  const maxSeverity = findings.reduce<Severity>(
    (acc, f) => (severityRank(f.severity) > severityRank(acc) ? f.severity : acc),
    'INFO'
  );

  const report: ServerReport = { name, kind, findings, maxSeverity };
  if (command !== undefined) report.command = [command, ...args].join(' ');
  if (url !== undefined) report.url = url;
  return report;
}

/* ------------------------------------------------------------------------- *
 * Orchestration
 * ------------------------------------------------------------------------- */

function scanConfigFile(path: string, client: string, parseErrors: ScanResult['parseErrors']): ConfigReport | undefined {
  let text: string;
  try {
    text = readFileSync(path, 'utf8');
  } catch (err) {
    parseErrors.push({ path, error: `could not read: ${err instanceof Error ? err.message : String(err)}` });
    return undefined;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch (err) {
    parseErrors.push({ path, error: `invalid JSON: ${err instanceof Error ? err.message : String(err)}` });
    return undefined;
  }
  const servers = extractServers(parsed);
  const serverReports = Object.entries(servers).map(([name, raw]) => scoreServer(name, raw));
  return { path, client, servers: serverReports };
}

function emptyCounts(): Record<Severity, number> {
  return { INFO: 0, LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 };
}

/**
 * Run the full scan against either an explicit config path or all discovered
 * locations. Pure orchestration over the pieces above; only reads files.
 */
export function performScan(opts: { explicitConfig?: string; cwd: string }): ScanResult {
  const parseErrors: ScanResult['parseErrors'] = [];
  const configs: ConfigReport[] = [];

  if (opts.explicitConfig) {
    const abs = isAbsolute(opts.explicitConfig) ? opts.explicitConfig : resolve(opts.cwd, opts.explicitConfig);
    if (!existsSync(abs)) {
      parseErrors.push({ path: abs, error: 'file not found' });
    } else {
      const report = scanConfigFile(abs, 'Explicit (--config)', parseErrors);
      if (report) configs.push(report);
    }
  } else {
    for (const loc of discoverConfigLocations(opts.cwd)) {
      if (!existsSync(loc.path)) continue; // guard: never throw on an absent path
      const report = scanConfigFile(loc.path, loc.client, parseErrors);
      if (report) configs.push(report);
    }
  }

  const severityCounts = emptyCounts();
  let serverCount = 0;
  for (const cfg of configs) {
    for (const s of cfg.servers) {
      serverCount += 1;
      severityCounts[s.maxSeverity] += 1;
    }
  }

  return { configs, serverCount, severityCounts, parseErrors };
}

/* ------------------------------------------------------------------------- *
 * Rendering
 * ------------------------------------------------------------------------- */

const SEVERITY_LABEL: Record<Severity, string> = {
  INFO: 'INFO    ',
  LOW: 'LOW     ',
  MEDIUM: 'MEDIUM  ',
  HIGH: 'HIGH    ',
  CRITICAL: 'CRITICAL',
};

function renderHuman(result: ScanResult): string {
  const lines: string[] = [];
  lines.push('taintgate scan — static audit of installed MCP servers (no servers were executed)');
  lines.push('');

  if (result.configs.length === 0 && result.parseErrors.length === 0) {
    lines.push('No MCP client configs found in the well-known locations.');
    lines.push('Nothing to scan. (Use --config <path> to point at a specific file.)');
    lines.push('');
    return lines.join('\n');
  }

  for (const cfg of result.configs) {
    lines.push(`${cfg.client}`);
    lines.push(`  ${cfg.path}`);
    if (cfg.servers.length === 0) {
      lines.push('    (no MCP servers declared)');
      lines.push('');
      continue;
    }
    for (const server of cfg.servers) {
      const target = server.command ?? server.url ?? '(no command/url)';
      lines.push(`    • ${server.name}  [${server.maxSeverity}]`);
      lines.push(`        ${target}`);
      for (const f of server.findings) {
        lines.push(`        [${SEVERITY_LABEL[f.severity]}] ${f.message}`);
        lines.push(`                   ↳ ${f.remediation}`);
      }
    }
    lines.push('');
  }

  if (result.parseErrors.length > 0) {
    lines.push('Could not parse:');
    for (const e of result.parseErrors) {
      lines.push(`  ! ${e.path} — ${e.error}`);
    }
    lines.push('');
  }

  const c = result.severityCounts;
  lines.push('Summary');
  lines.push(
    `  ${result.serverCount} server(s) across ${result.configs.length} config(s): ` +
      `CRITICAL ${c.CRITICAL}, HIGH ${c.HIGH}, MEDIUM ${c.MEDIUM}, LOW ${c.LOW}, INFO ${c.INFO}`
  );
  const failing = c.HIGH + c.CRITICAL;
  if (failing > 0) {
    lines.push(`  ${failing} server(s) at HIGH+ risk. Govern them at runtime with:  taintgate wrap -- <server-command>`);
  } else {
    lines.push('  No HIGH+ risks found. Still, unknown ≠ safe — review INFO/LOW items you did not expect.');
  }
  lines.push('');
  return lines.join('\n');
}

function renderJson(result: ScanResult): string {
  const c = result.severityCounts;
  return (
    JSON.stringify(
      {
        tool: 'taintgate',
        command: 'scan',
        executedServers: false,
        serverCount: result.serverCount,
        configCount: result.configs.length,
        severityCounts: c,
        highOrAbove: c.HIGH + c.CRITICAL,
        configs: result.configs,
        parseErrors: result.parseErrors,
      },
      null,
      2
    ) + '\n'
  );
}

/* ------------------------------------------------------------------------- *
 * CLI entry
 * ------------------------------------------------------------------------- */

const SCAN_HELP = `taintgate scan — audit the MCP servers you already have installed

USAGE
  taintgate scan [options]

WHAT IT DOES
  Statically inspects existing MCP client configs (Claude Desktop, Cursor,
  Windsurf, VS Code) and risk-scores each declared server. It NEVER executes,
  spawns, or connects to any server — it only reads JSON already on disk.

OPTIONS
  --config <path>   Scan a single explicit config file instead of auto-discovery.
  --json            Emit machine-readable JSON instead of the terminal report.
  --no-fail         Always exit 0, even when HIGH/CRITICAL findings exist.
  --help, -h        Show this help.

EXIT CODES
  0  no findings at HIGH or CRITICAL (or --no-fail given)
  1  at least one server scored HIGH or CRITICAL (CI-friendly)
`;

interface ScanFlags {
  config?: string;
  json: boolean;
  noFail: boolean;
  help: boolean;
}

function parseScanFlags(args: string[]): ScanFlags {
  const flags: ScanFlags = { json: false, noFail: false, help: false };
  for (let i = 0; i < args.length; i++) {
    const a = args[i]!;
    const eq = a.indexOf('=');
    const key = eq >= 0 ? a.slice(0, eq) : a;
    const inline = eq >= 0 ? a.slice(eq + 1) : undefined;
    const takeVal = (): string => {
      if (inline !== undefined) return inline;
      const v = args[i + 1];
      if (v === undefined) throw new Error(`missing value for ${key}`);
      i += 1;
      return v;
    };
    switch (key) {
      case '--config':
        flags.config = takeVal();
        break;
      case '--json':
        flags.json = true;
        break;
      case '--no-fail':
        flags.noFail = true;
        break;
      case '--help':
      case '-h':
        flags.help = true;
        break;
      default:
        throw new Error(`unknown scan option: ${key} (try \`taintgate scan --help\`)`);
    }
  }
  return flags;
}

/**
 * Entry point wired from `src/cli/index.ts`. Returns a process exit code:
 * 0 when clean (or `--no-fail`), 1 when any server scored HIGH/CRITICAL.
 * Never throws for absent config paths; only flag-parse errors reject.
 */
export async function runScan(args: string[]): Promise<number> {
  let flags: ScanFlags;
  try {
    flags = parseScanFlags(args);
  } catch (err) {
    process.stderr.write(`taintgate: ${err instanceof Error ? err.message : String(err)}\n`);
    return 2;
  }

  if (flags.help) {
    process.stdout.write(SCAN_HELP);
    return 0;
  }

  const scanOpts: { explicitConfig?: string; cwd: string } = { cwd: process.cwd() };
  if (flags.config !== undefined) scanOpts.explicitConfig = flags.config;
  const result = performScan(scanOpts);

  process.stdout.write(flags.json ? renderJson(result) : renderHuman(result));

  const failing = result.severityCounts.HIGH + result.severityCounts.CRITICAL;
  if (flags.noFail) return 0;
  return failing > 0 ? 1 : 0;
}
