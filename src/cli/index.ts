#!/usr/bin/env node
/**
 * taintgate — a governance proxy for the Model Context Protocol (MCP).
 *
 * Drop `taintgate wrap -- <server cmd>` in front of any stdio MCP server and it
 * transparently enforces ALLOW / BLOCK / REDACT governance on tool calls between
 * the MCP client (e.g. Claude Desktop) and the server.
 */

import { getVersion } from './version';
import { runWrap, parseWrapPinFlag, type WrapOptions } from './wrap';
import { runScan } from './scan';
import { writeInitConfig, DEFAULT_POLICY_FILENAME } from './defaultPolicy';

/** User-facing error that should print cleanly without a stack trace. */
class CliError extends Error {}

const HELP = `taintgate — governance proxy for the Model Context Protocol (MCP)

USAGE
  taintgate wrap [options] -- <server-command> [server-args...]
  taintgate scan [options]
  taintgate init-config [path]
  taintgate --help | --version

COMMANDS
  wrap          Sit transparently between an MCP client and server, enforcing
                ALLOW / BLOCK / REDACT governance on tools/call traffic.
  scan          Statically audit already-installed MCP server configs (Claude
                Desktop, Cursor, ...) and flag risky ones. No proxy setup.
  init-config   Write a starter policy file (default: ./${DEFAULT_POLICY_FILENAME}).

WRAP OPTIONS
  --policy <path>   Policy JSON file. If omitted, fail-closed defaults apply
                    (risk thresholds: allow < 0.3, block >= 0.7).
  --log <dir>       Directory for JSONL audit logs (default: ./taintgate-logs).
  --fail-closed     On governance/internal error, BLOCK the request (default).
  --fail-open       On governance/internal error, pass the request through.
  --pin             Pin tool definitions and detect rug-pulls / tool poisoning
                    (a server silently changing a tool's description or schema).
  --pin-file <path> Pin store location (default: ./taintgate.lock.json).
  --pin-policy <p>  off | warn (default) | block | update. "block" refuses to
                    forward a tools/list whose pinned definitions changed.

EXAMPLE (claude_desktop_config.json)
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "taintgate", "wrap", "--",
               "npx", "-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
    }
  }
`;

function printHelp(): void {
  process.stdout.write(HELP);
}

/** Split `wrap` args at the `--` terminator into flags vs the child command. */
function splitDoubleDash(argv: string[]): { flags: string[]; command: string[] } {
  const idx = argv.indexOf('--');
  if (idx === -1) return { flags: argv, command: [] };
  return { flags: argv.slice(0, idx), command: argv.slice(idx + 1) };
}

function parseWrapFlags(flags: string[]): WrapOptions {
  const opts: WrapOptions = { logDir: './taintgate-logs', failMode: 'closed' };
  for (let i = 0; i < flags.length; i++) {
    const f = flags[i]!;
    const eq = f.indexOf('=');
    const key = eq >= 0 ? f.slice(0, eq) : f;
    const inlineVal = eq >= 0 ? f.slice(eq + 1) : undefined;
    const takeVal = (): string => {
      if (inlineVal !== undefined) return inlineVal;
      const v = flags[i + 1];
      if (v === undefined) throw new CliError(`missing value for ${key}`);
      i += 1;
      return v;
    };
    switch (key) {
      case '--policy':
        opts.policyPath = takeVal();
        break;
      case '--log':
        opts.logDir = takeVal();
        break;
      case '--fail-open':
        opts.failMode = 'open';
        break;
      case '--fail-closed':
        opts.failMode = 'closed';
        break;
      default:
        if (!parseWrapPinFlag(key, takeVal, opts)) {
          throw new CliError(`unknown wrap option: ${key} (try --help)`);
        }
    }
  }
  return opts;
}

function runInitConfig(path?: string): void {
  const written = writeInitConfig(path);
  process.stdout.write(`taintgate: wrote starter policy to ${written}\n`);
}

async function main(): Promise<void> {
  const argv = process.argv.slice(2);
  const first = argv[0];

  if (first === undefined || first === '--help' || first === '-h' || first === 'help') {
    printHelp();
    return;
  }
  if (first === '--version' || first === '-v') {
    process.stdout.write(`${getVersion()}\n`);
    return;
  }
  if (first === 'scan') {
    // runScan owns its exit code (0 clean / 1 HIGH+ finding / 2 flag error).
    process.exit(await runScan(argv.slice(1)));
  }
  if (first === 'init-config') {
    runInitConfig(argv[1]);
    return;
  }
  if (first === 'wrap') {
    const { flags, command } = splitDoubleDash(argv.slice(1));
    if (command.length === 0) {
      throw new CliError('wrap requires a server command after `--`, e.g. `wrap -- node server.js`');
    }
    const opts = parseWrapFlags(flags);
    const [cmd, ...cargs] = command;
    await runWrap(cmd!, cargs, opts);
    return;
  }

  throw new CliError(`unknown command: ${first} (try --help)`);
}

main().catch((err) => {
  process.stderr.write(`taintgate: ${err instanceof Error ? err.message : String(err)}\n`);
  process.exit(1);
});
