'use strict';

/**
 * Injectable command runner.
 *
 * Uses `execFile` (NOT `exec`), so arguments are an argv array that never goes
 * through a shell — no command-string interpolation, no shell-injection
 * surface. Never rejects: always resolves to a result with `ok`, so callers
 * can fail closed.
 */

const { execFile } = require('node:child_process');

function makeRunner(baseOpts = {}) {
  return function run(file, args = [], opts = {}) {
    return new Promise((resolve) => {
      execFile(
        file,
        args,
        { timeout: 4000, maxBuffer: 1 << 20, windowsHide: true, ...baseOpts, ...opts },
        (error, stdout, stderr) => {
          resolve({
            ok: !error,
            code: error && typeof error.code === 'number' ? error.code : error ? 1 : 0,
            stdout: stdout ? String(stdout) : '',
            stderr: stderr ? String(stderr) : '',
            error: error || null,
          });
        },
      );
    });
  };
}

const run = makeRunner();

module.exports = { run, makeRunner };
