'use strict';

/** Tiny leveled logger. No deps; injectable sink for testing. */

const LEVELS = { silent: 0, error: 1, warn: 2, info: 3, debug: 4 };

function createLogger(opts = {}) {
  const level = opts.level || 'info';
  const prefix = opts.prefix || '[hereonly]';
  const sink = opts.sink || console;
  const threshold = LEVELS[level] != null ? LEVELS[level] : LEVELS.info;

  function emit(lvl, args) {
    if (threshold === 0 || (LEVELS[lvl] || 0) > threshold) return;
    const fn = sink[lvl] || sink.log || (() => {});
    fn.call(sink, prefix, ...args);
  }
  return {
    level,
    error: (...a) => emit('error', a),
    warn: (...a) => emit('warn', a),
    info: (...a) => emit('info', a),
    debug: (...a) => emit('debug', a),
  };
}

const noopLogger = { level: 'silent', error() {}, warn() {}, info() {}, debug() {} };

module.exports = { createLogger, noopLogger, LEVELS };
