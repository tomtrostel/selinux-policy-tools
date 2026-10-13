// File labels: which file-context line gives a path its label, as libselinux
// (matchpathcon, restorecon, setfiles) decides it. Pure: no file access.
//
// libselinux reads file_contexts, then .homedirs, then .local, moves the
// specs without regex characters after the others (stable), and lets the LAST
// match win. It relies on the files being sorted by specificity, which
// semodule (and refpolicy's fc_sort.py) does; a plain concatenation of module
// .fc files (a tree build's tmp/all_mods.fc) is not, and a general line such
// as `/usr/.*` there can win over `/usr/bin(/.*)?`.

/** Path flag of a file-context line → the object class it applies to. */
const FLAG_MODES = { '--': 'file', '-d': 'dir', '-l': 'lnk_file', '-c': 'chr_file', '-b': 'blk_file', '-s': 'sock_file', '-p': 'fifo_file' };
const MODE_FLAGS = Object.fromEntries(Object.entries(FLAG_MODES).map(([f, m]) => [m, f]));
const MODE_LABELS = { file: 'regular file', dir: 'directory', lnk_file: 'symbolic link', chr_file: 'character device', blk_file: 'block device', sock_file: 'socket', fifo_file: 'named pipe' };
const META = new Set(['.', '^', '$', '?', '*', '+', '|', '[', '(', '{']);

/**
 * Lines of a file_contexts file: [{ spec, flag, mode, context, type, l, file, module }].
 * Comments, blank lines and m4 leftovers are skipped; l is 0-based.
 */
function parseSpecs(text, file = null, module = null) {
  const out = [];
  const lines = String(text || '').split('\n');
  for (let l = 0; l < lines.length; l++) {
    const line = lines[l].trim();
    if (!line || line.startsWith('#')) continue;
    const m = /^(\S+)\s+(?:(-[-dlcbsp])\s+)?(\S+)\s*$/.exec(line);
    if (!m) continue;
    const ctx = m[3];
    const type = ctx === '<<none>>' ? null : (ctx.split(':')[2] || null);
    out.push({ spec: m[1], flag: m[2] || null, mode: m[2] ? FLAG_MODES[m[2]] : null, context: ctx, type, l, file, module, ...specificity(m[1]) });
  }
  return out;
}

/** fc_sort.py's measures: has regex characters, length before the first one, length (escapes count once). */
function specificity(spec) {
  let meta = false; let stem = 0; let len = 0;
  for (let i = 0; i < spec.length; i++) {
    const ch = spec[i];
    if (META.has(ch)) meta = true;
    if (!meta) stem++;
    len++;
    if (ch === '\\') i++;
  }
  return { meta, stem, len };
}

/** fc_sort.py / libsemanage order: less specific first. */
function compareSpecs(a, b) {
  if (a.meta !== b.meta) return a.meta ? -1 : 1;
  if (a.stem !== b.stem) return a.stem - b.stem;
  if (a.len !== b.len) return a.len - b.len;
  if (!a.flag !== !b.flag) return a.flag ? 1 : -1;
  return 0;
}

/** Sorted as semodule writes file_contexts (stable). */
const sortSpecs = (specs) => specs.slice().sort(compareSpecs);

/**
 * libselinux's lookup order for the files it loads (in this order: file_contexts,
 * .homedirs, .local): concatenated, then specs without regex characters moved
 * to the end, keeping their order. The last match wins.
 */
function lookupOrder(...lists) {
  const all = lists.flat();
  return [...all.filter(s => s.meta), ...all.filter(s => !s.meta)];
}

/** Text for matchpathcon -f / setfiles, in fc_sort.py's format. */
const renderSpecs = (specs) => specs.map(s => (s.flag ? `${s.spec}\t\t${s.flag}\t${s.context}` : `${s.spec}\t\t${s.context}`)).join('\n') + '\n';

/** file_contexts.subs(_dist): [[from, to]]. */
function parseSubs(text) {
  const out = [];
  for (const raw of String(text || '').split('\n')) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const [from, to] = line.split(/\s+/);
    if (from && to) out.push([from.replace(/\/+$/, '') || '/', to.replace(/\/+$/, '') || '/']);
  }
  return out;
}

function subOnce(p, subs) {
  // libselinux prepends each line to its list, so later lines are tried first
  // (/run/systemd/generator before /run).
  for (let i = subs.length - 1; i >= 0; i--) {
    const [from, to] = subs[i];
    // A target of / (a chroot labeled like the root) keeps the rest as is: /var/chroot/ro/etc → /etc.
    if (p === from || (p.startsWith(from) && p[from.length] === '/')) return to === '/' ? (p.slice(from.length) || '/') : to + p.slice(from.length);
  }
  return null;
}

/** libselinux's substitution: the local subs, then the distribution's on the result (or on the path). */
function applySubs(p, local = [], dist = []) {
  const a = subOnce(p, local);
  const b = subOnce(a == null ? p : a, dist);
  return b != null ? b : a != null ? a : p;
}

const POSIX_CLASSES = { alnum: 'a-zA-Z0-9', alpha: 'a-zA-Z', digit: '0-9', lower: 'a-z', upper: 'A-Z', space: '\\s', xdigit: '0-9A-Fa-f', punct: '!-\\/:-@\\[-`{-~', blank: ' \\t', word: '\\w' };

/** The spec as an anchored JS regex (PCRE syntax is close; POSIX classes translated), or null. */
function specRegex(s) {
  if (s._re !== undefined) return s._re;
  const src = s.spec.replace(/\[:(\w+):\]/g, (m, n) => POSIX_CLASSES[n] || m);
  try { s._re = new RegExp(`^(?:${src})$`); } catch { s._re = null; }
  return s._re;
}

/**
 * Lines that match `p` for an object of class `mode` (null: any), in lookup
 * order with the winner first: [{ ...spec }]. `specs` must be in lookup order.
 */
function matches(specs, p, mode = null, limit = 12) {
  const out = [];
  for (let i = specs.length - 1; i >= 0 && out.length < limit; i--) {
    const s = specs[i];
    if (s.mode && mode && s.mode !== mode) continue;
    const re = specRegex(s);
    if (re && re.test(p)) out.push(s);
  }
  return out;
}

/**
 * Home directory template lines (HOME_DIR, HOME_ROOT, USER, %{USERID} …) as
 * genhomedircon would write them for ordinary users under /home. Returns
 * [specs (expanded, template: true), others].
 */
function splitHomeTemplates(specs, homeRoot = '/home') {
  const tpl = []; const rest = [];
  const HOME = /HOME_DIR|HOME_ROOT|\bUSER\b|%\{USERID\}|%\{USERNAME\}|\bROLE\b/;
  for (const s of specs) {
    if (!HOME.test(s.spec)) { rest.push(s); continue; }
    const spec = s.spec.replace(/HOME_DIR/g, `${homeRoot}/[^/]+`).replace(/HOME_ROOT/g, homeRoot)
      .replace(/%\{USERID\}/g, '[0-9]+').replace(/%\{USERNAME\}|\bUSER\b/g, '[^/]+');
    tpl.push({ ...s, spec, template: s.spec, ...specificity(spec), _re: undefined });
  }
  return [tpl, rest];
}

/** The object class of an lstat mode (fs.Stats). */
function modeOf(st) {
  if (!st) return null;
  if (st.isSymbolicLink()) return 'lnk_file';
  if (st.isDirectory()) return 'dir';
  if (st.isCharacterDevice()) return 'chr_file';
  if (st.isBlockDevice()) return 'blk_file';
  if (st.isSocket()) return 'sock_file';
  if (st.isFIFO()) return 'fifo_file';
  return 'file';
}

/* ----- what the policy lets happen to a type (from policy_query's fileinfo) ----- */

const READ_PERMS = new Set(['read', 'getattr', 'open', 'search', 'lock', 'ioctl', 'map', 'listen', 'read_file', 'lnk_read']);
const WRITE_PERMS = new Set(['write', 'append', 'create', 'unlink', 'rename', 'link', 'add_name', 'remove_name', 'reparent', 'rmdir', 'setattr', 'swapon', 'mounton', 'quotaon']);
const EXEC_PERMS = new Set(['execute', 'execute_no_trans', 'entrypoint', 'execmod']);
const LABEL_PERMS = new Set(['relabelfrom', 'relabelto']);

/** One-line summary of permissions on a type: 'read write execute relabel' etc. */
function permLevels(perms) {
  const has = (set) => perms.some(p => set.has(p));
  const out = [];
  if (has(READ_PERMS)) out.push('read');
  if (has(WRITE_PERMS)) out.push(perms.includes('create') && perms.includes('unlink') ? 'manage' : 'write');
  if (has(EXEC_PERMS)) out.push(perms.includes('entrypoint') ? 'enter' : 'execute');
  if (has(LABEL_PERMS)) out.push('relabel');
  if (!out.length && perms.length) out.push('other');
  return out;
}

const LEVEL_RANK = { relabel: 6, manage: 5, write: 4, enter: 3, execute: 2, read: 1, other: 0 };

module.exports = {
  FLAG_MODES, MODE_FLAGS, MODE_LABELS, parseSpecs, specificity, compareSpecs, sortSpecs, lookupOrder, renderSpecs,
  parseSubs, applySubs, specRegex, matches, splitHomeTemplates, modeOf, permLevels, LEVEL_RANK,
};
