'use strict';
// Temporary directories for tests: removed when the process exits (also on
// Ctrl-C, kill or a failed assertion that calls process.exit). Set
// KEEP_TMP=1 to keep them for a look afterwards; their paths are printed.

const fs = require('fs');
const os = require('os');
const path = require('path');

const dirs = [];

function tempDir(prefix) {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  if (!dirs.length) {
    process.on('exit', cleanup);
    for (const [sig, code] of [['SIGINT', 130], ['SIGTERM', 143], ['SIGHUP', 129]]) {
      process.on(sig, () => process.exit(code));
    }
  }
  dirs.push(d);
  return d;
}

function cleanup() {
  if (process.env.KEEP_TMP) {
    for (const d of dirs) if (fs.existsSync(d)) console.log(`kept ${d}`);
    return;
  }
  for (const d of dirs.splice(0)) {
    try { fs.rmSync(d, { recursive: true, force: true }); } catch (e) { /* busy or gone */ }
  }
}

module.exports = { tempDir, cleanup };
