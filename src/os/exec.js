'use strict';

/**
 * Injectable command runner.
 *
 * Uses `execFile` (NOT `exec`) so arguments are passed as an argv array and
 * never go through a shell — there is no command-string interpolation and thus
 * no shell-injection surface, even though some inputs (e.g. a gateway IP) are
 * derived from the environment.
 *
 * The runner never rejects: it always resolves to a result object with `ok`.
 * Callers decide what a failed probe means (HereOnly's verifier fails closed).
 */

const { execFile } = require('node:child_process');

/**
 * @typedef {Object} RunResult
 * @property {boolean} ok      - true if the process exited 0
 * @property {number}  code    - exit code (or 1 on spawn error / timeout)
 * @property {string}  stdout
 * @property {string}  stderr
 * @property {Error|null} error
 */

function makeRunner(baseOpts = {}) {
  /**
   * @param {string} file
   * @param {string[]} [args]
   * @param {object} [opts]
   * @returns {Promise<RunResult>}
   */
  return function run(file, args = [], opts = {}) {
    return new Promise((resolve) => {
      execFile(
        file,
        args,
        {
          timeout: 4000,
          maxBuffer: 1 << 20, // 1 MiB — neighbor tables are small
          windowsHide: true,
          ...baseOpts,
          ...opts,
        },
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
