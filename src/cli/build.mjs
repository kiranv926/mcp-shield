// taintgate CLI bundler.
//
// The rest of the compiled `dist/` uses extensionless / directory ESM imports
// that plain `node` cannot resolve at runtime. To ship a bin that runs with a
// bare `node dist/cli/index.js`, we bundle the CLI (and its in-repo deps) into a
// single self-contained ESM file. Node built-ins stay external automatically for
// platform:node. `tsc` still type-checks the whole project in the build script.
import { build } from 'esbuild';
import { chmodSync } from 'node:fs';

await build({
  entryPoints: ['src/cli/index.ts'],
  outfile: 'dist/cli/index.js',
  bundle: true,
  platform: 'node',
  format: 'esm',
  target: 'node18',
  // esbuild preserves the entry file's hashbang (src/cli/index.ts starts with
  // `#!/usr/bin/env node`), so no banner is needed — adding one would duplicate it.
  logLevel: 'info',
});

chmodSync('dist/cli/index.js', 0o755);
console.log('taintgate: bundled dist/cli/index.js');
