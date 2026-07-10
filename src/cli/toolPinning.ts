/**
 * taintgate: tool-definition pinning (rug-pull / tool-poisoning detection).
 *
 * The top MCP-security concern this module addresses: an MCP server can
 * silently mutate a tool's `description` or `inputSchema` AFTER a user has
 * approved it (a "rug pull"), or ship a poisoned description that steers the
 * agent into exfiltration. Because taintgate observes every `tools/list`
 * response, it can pin the tool definitions the first time it sees them and
 * loudly flag any later drift.
 *
 * The primitive is a deterministic sha256 over the security-relevant fields of
 * each tool (`name`, `description`, `inputSchema`). Determinism is critical:
 * a sloppy hash (e.g. one sensitive to JSON key order) would produce false
 * rug-pull alerts on benign servers and train users to ignore the warning.
 * Canonicalization below sorts every object key recursively so key order never
 * changes the hash.
 *
 * Dependency-free by design: node:crypto + node:fs only.
 */

import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';

/** Current on-disk pin-store schema version. */
export const PIN_STORE_VERSION = 1;

/** Default path for the pin store ("lock file"). */
export const DEFAULT_PIN_FILE = './taintgate.lock.json';

/**
 * Minimal MCP tool definition as it arrives on a `tools/list` response.
 * Only the security-relevant fields are typed; anything else is ignored by the
 * hash (it is deliberately NOT part of the pin so cosmetic metadata churn does
 * not read as a rug pull).
 */
export interface McpToolDefinition {
  name: string;
  description?: string;
  inputSchema?: unknown;
}

/** What to do when advertised tool definitions violate the pinned baseline. */
export type PinPolicy = 'off' | 'warn' | 'block' | 'update';

/** A single pinned tool record. */
export interface PinnedTool {
  /** sha256 hex of the canonical tool definition. */
  hash: string;
  /**
   * The pinned description text, stored in the clear so a diff can show exactly
   * what changed AND so we can attribute a hash change to description vs schema
   * without persisting the whole schema.
   */
  description: string;
  /** ISO-8601 timestamp of when this tool was pinned. */
  pinnedAt: string;
}

/** The persisted pin store ("lock file"). */
export interface PinStore {
  version: number;
  /** Human label for the wrapped server (e.g. the child command). */
  server: string;
  /** Pinned tools keyed by tool name. */
  tools: Record<string, PinnedTool>;
}

// ---------------------------------------------------------------------------
// Canonicalization + hashing
// ---------------------------------------------------------------------------

/**
 * Recursively produce a canonical form of an arbitrary JSON value:
 *   - object keys are sorted lexicographically (so `{a,b}` and `{b,a}` match),
 *   - arrays keep their order (order IS semantically meaningful in JSON Schema,
 *     e.g. `required`/`enum` ordering can matter, and reordering is itself a
 *     change worth flagging),
 *   - primitives pass through untouched.
 *
 * `undefined` values inside objects are dropped by JSON.stringify anyway; we
 * additionally skip keys whose value is `undefined` so an explicit
 * `{description: undefined}` hashes identically to an absent description.
 */
function canonicalize(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map((v) => canonicalize(v));
  }
  if (value !== null && typeof value === 'object') {
    const obj = value as Record<string, unknown>;
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(obj).sort()) {
      const v = obj[key];
      if (v === undefined) continue;
      out[key] = canonicalize(v);
    }
    return out;
  }
  return value;
}

/**
 * Deterministic canonical JSON string for a value. Key-order independent.
 * Exported for testing the canonicalization primitive directly.
 */
export function canonicalJson(value: unknown): string {
  return JSON.stringify(canonicalize(value));
}

/**
 * Stable sha256 (hex) of a tool definition over exactly the security-relevant
 * fields: `name`, `description`, `inputSchema`. Any other property on the tool
 * object is intentionally excluded so it cannot influence the pin.
 *
 * `description` defaults to '' and `inputSchema` to null when absent so a tool
 * that gains/loses a description or schema is detected as a change (rather than
 * two absent-vs-empty forms hashing differently by accident).
 */
export function hashToolDefinition(tool: McpToolDefinition): string {
  const securityRelevant = {
    name: tool.name,
    description: tool.description ?? '',
    inputSchema: tool.inputSchema ?? null,
  };
  return createHash('sha256').update(canonicalJson(securityRelevant), 'utf8').digest('hex');
}

/** Short hash prefix for human-readable logs. */
function shortHash(hash: string): string {
  return hash.slice(0, 12);
}

// ---------------------------------------------------------------------------
// Pin store load / save
// ---------------------------------------------------------------------------

/** Create an empty pin store for a freshly-wrapped server. */
export function createEmptyPinStore(server: string): PinStore {
  return { version: PIN_STORE_VERSION, server, tools: {} };
}

/** Structural validation of a parsed pin store (untrusted on-disk JSON). */
function isPinStore(value: unknown): value is PinStore {
  if (value === null || typeof value !== 'object') return false;
  const v = value as Record<string, unknown>;
  if (typeof v.version !== 'number') return false;
  if (typeof v.server !== 'string') return false;
  if (v.tools === null || typeof v.tools !== 'object') return false;
  for (const entry of Object.values(v.tools as Record<string, unknown>)) {
    if (entry === null || typeof entry !== 'object') return false;
    const e = entry as Record<string, unknown>;
    if (typeof e.hash !== 'string') return false;
    if (typeof e.description !== 'string') return false;
    if (typeof e.pinnedAt !== 'string') return false;
  }
  return true;
}

/**
 * Load the pin store from disk.
 *   - Returns `null` if the file does not exist (first run → trust-on-first-use).
 *   - Throws if the file exists but is not valid JSON / not a valid pin store,
 *     so a corrupt lock file surfaces loudly rather than being silently
 *     overwritten (which would erase the security baseline).
 */
export function loadPinStore(path: string): PinStore | null {
  let raw: string;
  try {
    raw = readFileSync(path, 'utf8');
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') return null;
    throw err;
  }
  const parsed = JSON.parse(raw) as unknown;
  if (!isPinStore(parsed)) {
    throw new Error(`pin store at ${path} is not a valid taintgate.lock.json`);
  }
  return parsed;
}

/** Persist the pin store as pretty-printed JSON (human-diffable in git). */
export function savePinStore(path: string, store: PinStore): void {
  writeFileSync(path, JSON.stringify(store, null, 2) + '\n', 'utf8');
}

// ---------------------------------------------------------------------------
// Diff
// ---------------------------------------------------------------------------

/** A tool advertised now that was never pinned before. */
export interface AddedTool {
  name: string;
  tool: McpToolDefinition;
  hash: string;
}

/** A pinned tool whose current definition no longer matches its pin. */
export interface ChangedTool {
  name: string;
  tool: McpToolDefinition;
  /** Hash of the current (advertised) definition. */
  hash: string;
  /** Hash recorded at pin time. */
  previousHash: string;
  /** Description recorded at pin time. */
  previousDescription: string;
  /** Description advertised now. */
  newDescription: string;
  /**
   * Which security-relevant field(s) changed. A `description` change is the
   * tool-poisoning / rug-pull signal and is treated as the highest concern.
   */
  fields: { description: boolean; schema: boolean };
}

/** Result of diffing advertised tools against the pinned baseline. */
export interface ToolDiff {
  /** New tools (not previously pinned). */
  added: AddedTool[];
  /** Tools whose definition changed since pinning. */
  changed: ChangedTool[];
  /** Tools whose definition matches the pin exactly. */
  unchanged: Array<{ name: string; hash: string }>;
  /** Names of pinned tools no longer offered by the server. */
  removed: string[];
}

/**
 * Diff the tools advertised on a `tools/list` against the pinned baseline.
 *
 * Field attribution for changed tools: the description is stored in the clear,
 * so a description change is a direct string compare. To decide whether the
 * SCHEMA also changed without persisting the whole schema, we recompute the
 * hash substituting the *pinned* description onto the *current* tool. If that
 * still differs from the pinned hash, then something other than the description
 * changed — and since the name is fixed (it is the map key), that "something"
 * is the input schema.
 */
export function diffToolsAgainstPins(tools: McpToolDefinition[], store: PinStore): ToolDiff {
  const added: AddedTool[] = [];
  const changed: ChangedTool[] = [];
  const unchanged: Array<{ name: string; hash: string }> = [];
  const seen = new Set<string>();

  for (const tool of tools) {
    const name = tool.name;
    seen.add(name);
    const hash = hashToolDefinition(tool);
    const pin = store.tools[name];

    if (pin === undefined) {
      added.push({ name, tool, hash });
      continue;
    }
    if (pin.hash === hash) {
      unchanged.push({ name, hash });
      continue;
    }

    const newDescription = tool.description ?? '';
    const descriptionChanged = newDescription !== pin.description;
    // Re-hash with the OLD description onto the CURRENT schema. If it matches
    // the pin, only the description moved; if not, the schema moved too.
    const hashWithOldDescription = hashToolDefinition({ ...tool, description: pin.description });
    const schemaChanged = hashWithOldDescription !== pin.hash;

    changed.push({
      name,
      tool,
      hash,
      previousHash: pin.hash,
      previousDescription: pin.description,
      newDescription,
      fields: { description: descriptionChanged, schema: schemaChanged },
    });
  }

  const removed = Object.keys(store.tools).filter((name) => !seen.has(name));
  return { added, changed, unchanged, removed };
}

// ---------------------------------------------------------------------------
// Policy
// ---------------------------------------------------------------------------

/** The verdict of applying a {@link PinPolicy} to a {@link ToolDiff}. */
export interface PinDecision {
  policy: PinPolicy;
  /** True → do NOT forward this tools/list; return a JSON-RPC error instead. */
  block: boolean;
  /** True → the pin store should be written back to disk (TOFU / update). */
  persist: boolean;
  /** True → the diff contained any added/changed/removed tool. */
  violations: boolean;
  /** Human-readable lines to log to stderr (no `[taintgate]` prefix). */
  messages: string[];
  /** Concise reason string surfaced to the client when `block` is true. */
  blockReason?: string;
}

/** Format the descriptive diff lines shared by warn/block/update policies. */
function describeDiff(diff: ToolDiff): string[] {
  const lines: string[] = [];

  for (const c of diff.changed) {
    const which = [c.fields.description ? 'DESCRIPTION' : null, c.fields.schema ? 'SCHEMA' : null]
      .filter((x): x is string => x !== null)
      .join(' + ');
    const severity = c.fields.description
      ? 'possible tool poisoning / rug pull'
      : 'schema drift';
    lines.push(`pin: CHANGED tool "${c.name}" — ${which} changed (${severity})`);
    if (c.fields.description) {
      lines.push(`  pinned:  ${JSON.stringify(c.previousDescription)}`);
      lines.push(`  current: ${JSON.stringify(c.newDescription)}`);
    }
    lines.push(`  hash ${shortHash(c.previousHash)} -> ${shortHash(c.hash)}`);
  }
  for (const name of diff.removed) {
    lines.push(`pin: REMOVED tool "${name}" — was pinned, no longer offered by server`);
  }
  for (const a of diff.added) {
    lines.push(`pin: NEW tool "${a.name}" — recording hash ${shortHash(a.hash)} (trust-on-first-use)`);
  }
  return lines;
}

/**
 * Decide what to do about a diff under a given policy.
 *
 *   off    — never blocks, never persists, stays silent.
 *   warn   — logs the diff and allows; records newly-added tools (TOFU).
 *   block  — fail-closed: if any pinned tool CHANGED, refuse to forward the
 *            tools/list (return a JSON-RPC error); description changes are
 *            called out as the highest concern. New tools are still recorded.
 *   update — trust-on-first-use / re-trust: record new AND changed hashes,
 *            prune removed tools, and allow.
 */
export function applyPinPolicy(diff: ToolDiff, policy: PinPolicy): PinDecision {
  const hasAdded = diff.added.length > 0;
  const hasChanged = diff.changed.length > 0;
  const hasRemoved = diff.removed.length > 0;
  const violations = hasAdded || hasChanged || hasRemoved;

  if (policy === 'off') {
    return { policy, block: false, persist: false, violations, messages: [] };
  }

  const messages = describeDiff(diff);

  if (policy === 'warn') {
    if (hasChanged || hasRemoved) {
      messages.unshift('pin: tool-definition drift detected against pinned baseline (policy=warn, allowing)');
    }
    return { policy, block: false, persist: hasAdded, violations, messages };
  }

  if (policy === 'update') {
    if (violations) {
      messages.unshift('pin: updating pinned baseline to current tool definitions (policy=update)');
    }
    return { policy, block: false, persist: hasAdded || hasChanged || hasRemoved, violations, messages };
  }

  // policy === 'block'
  if (hasChanged) {
    const descChanged = diff.changed.filter((c) => c.fields.description);
    messages.unshift(
      'pin: BLOCK — refusing to forward tools/list; tool definition(s) changed since pinning (policy=block)'
    );
    const blockReason =
      descChanged.length > 0
        ? `tool description changed since pinning (possible tool poisoning / rug pull): ${descChanged
            .map((c) => c.name)
            .join(', ')}`
        : `tool schema changed since pinning: ${diff.changed.map((c) => c.name).join(', ')}`;
    return { policy, block: true, persist: false, violations, messages, blockReason };
  }
  // No changed tools: added tools are still trusted-on-first-use, removed tools
  // are logged but do not block (a vanished tool cannot poison the agent).
  return { policy, block: false, persist: hasAdded, violations, messages };
}

/**
 * Produce the next pin store after applying a diff under a policy.
 *
 *   - Newly-added tools are ALWAYS recorded (trust-on-first-use), regardless of
 *     policy (except `off`, which never calls this).
 *   - Under `update`, changed tools are re-pinned to their current definition
 *     and removed tools are pruned from the store.
 *   - Under any other policy, changed and removed pins are left intact so the
 *     drift keeps being reported until a human intervenes.
 */
export function recordDiffIntoStore(
  store: PinStore,
  diff: ToolDiff,
  policy: PinPolicy,
  now: Date = new Date()
): PinStore {
  const pinnedAt = now.toISOString();
  const tools: Record<string, PinnedTool> = { ...store.tools };

  for (const a of diff.added) {
    tools[a.name] = { hash: a.hash, description: a.tool.description ?? '', pinnedAt };
  }

  if (policy === 'update') {
    for (const c of diff.changed) {
      tools[c.name] = { hash: c.hash, description: c.newDescription, pinnedAt };
    }
    for (const name of diff.removed) {
      delete tools[name];
    }
  }

  return { version: store.version, server: store.server, tools };
}
