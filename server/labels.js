'use strict';
/*
 * Labeling coverage for a service module, on a host (this one or a target):
 * which of the program's package files the policy leaves under a generic
 * label (and the file kind that would give them the service's own type),
 * which files on disk disagree with the policy (restorecon's dry run), and
 * which paths the module labels do not exist there.
 *
 *   coverageScript(programs, dirs, paths)  a `sh -s` script: the programs'
 *       packages and their files with kinds and current labels, `restorecon
 *       -nv -R` over the module's directories, existence of the module's paths.
 *   parseCoverage(out) → facts
 *   assess(facts, opts) → { generic, disagree, missing, covered, skipped, notes }
 *     opts: { name, kinds (service.catalog().fileKinds), moduleTypes (Set),
 *       expected: Map path → type (the policy's label for each package file),
 *       modelPaths: [{ path, kind }], programs: [paths] }
 */
const { sameProgram, splitSections, shq } = require('./prefill');

/* Labels that are the file system's defaults, not a service's own. */
const GENERIC = new Set(['default_t', 'file_t', 'unlabeled_t', 'var_t', 'var_lib_t', 'var_log_t', 'var_run_t', 'var_spool_t', 'var_cache_t', 'var_lock_t', 'etc_t', 'etc_runtime_t', 'tmp_t', 'var_tmp_t', 'usr_t', 'root_t', 'mnt_t', 'srv_t', 'bin_t', 'systemd_unit_file_t', 'initrc_exec_t', 'init_script_file_t']);
/* Read-only data, programs, libraries and documentation: generic labels are right there. */
const SKIP = /^\/usr\/(share|lib|lib64|libexec|include|src)\/|^\/usr\/s?bin\/|^\/s?bin\/|^\/(boot|proc|sys|dev)\//;
/* Files other programs read: not the service's own even when named after it. */
const OTHERS = /^\/etc\/(logrotate\.d|sysconfig|default|cron\.d|cron\.(hourly|daily|weekly|monthly)|rc\.d\/init\.d|systemd|dbus-1|pam\.d|bash_completion\.d|profile\.d|xdg|ld\.so\.conf\.d|rsyslog\.d|tmpfiles\.d|sysusers\.d|modprobe\.d|udev)\//;

/** The script. programs, dirs, paths: absolute paths (validated by the caller). */
function coverageScript(programs, dirs, paths) {
  const list = (xs) => [...new Set(xs)].filter(p => /^\/[^\n\t]*$/.test(p)).map(shq).join(' ');
  return `
sec() { printf '### %s\\n' "$1"; }
sec uid; id -u
sec pkgs
for p in ${list(programs) || "''"}; do [ -n "$p" ] || continue; r=$(realpath "$p" 2>/dev/null || printf '%s' "$p"); k=$(rpm -qf --qf '%{NAME}\\n' -- "$r" 2>/dev/null </dev/null | head -1); case "$k" in *"not owned"*|error*) k= ;; esac; printf '%s\\t%s\\n' "$p" "$k"; done
sec files
for p in ${list(programs) || "''"}; do [ -n "$p" ] || continue; r=$(realpath "$p" 2>/dev/null || printf '%s' "$p"); k=$(rpm -qf --qf '%{NAME}\\n' -- "$r" 2>/dev/null </dev/null | head -1); case "$k" in *"not owned"*|error*|"") continue ;; esac
  rpm -ql -- "$k" 2>/dev/null </dev/null | while IFS= read -r f; do
    if [ -L "$f" ]; then t=l; elif [ -d "$f" ]; then t=d; elif [ -e "$f" ]; then t=f; else continue; fi
    printf '%s\\t%s\\t%s\\t%s\\n' "$k" "$t" "$(stat -c %C -- "$f" 2>/dev/null)" "$f"; done; done | sort -u -t '\t' -k4,4
sec restorecon
${dirs.length ? `restorecon -nv -R ${list(dirs)} 2>&1 </dev/null | sed -n 's/^Would relabel //p'` : ''}
sec exist
for p in ${list(paths) || "''"}; do [ -n "$p" ] || continue; if [ -e "$p" ]; then printf '%s\\t1\\n' "$p"; else printf '%s\\t0\\n' "$p"; fi; done
sec done
`;
}

/** coverageScript's output → { uid, pkgs: Map program → pkg, files: [{ pkg, kind, label, path }], relabel: [{ path, from, to }], exist: Map path → bool, done }. */
function parseCoverage(out) {
  const s = splitSections(out);
  const pkgs = new Map();
  for (const l of (s.pkgs || '').split('\n')) { const f = l.split('\t'); if (f.length === 2 && f[0]) pkgs.set(f[0], f[1] || null); }
  const files = [];
  for (const l of (s.files || '').split('\n')) {
    const f = l.split('\t');
    if (f.length !== 4 || !f[3].startsWith('/')) continue;
    const ctx = f[2].split(':');
    files.push({ pkg: f[0], kind: f[1], label: ctx.length >= 3 ? ctx[2] : (f[2] || null), path: f[3] });
  }
  const relabel = [];
  for (const l of (s.restorecon || '').split('\n')) {
    // /path from system_u:object_r:a_t:s0 to system_u:object_r:b_t:s0
    const m = /^(.*) from (\S+) to (\S+)$/.exec(l.trim());
    if (!m) continue;
    const t = (c) => { const p = c.split(':'); return p.length >= 3 ? p[2] : c; };
    relabel.push({ path: m[1], from: t(m[2]), to: t(m[3]) });
  }
  const exist = new Map();
  for (const l of (s.exist || '').split('\n')) { const f = l.split('\t'); if (f.length === 2 && f[0]) exist.set(f[0], f[1] === '1'); }
  return { uid: parseInt((s.uid || '').trim(), 10), pkgs, files, relabel, exist, done: s.done != null };
}

/** The file kind (id) and path a package file would get in the form, or null. name: the module name, or a list of names (module, packages). */
function kindFor(file, name, kinds) {
  const names = (Array.isArray(name) ? name : [name]).filter(Boolean);
  const mine = (component) => names.some(n => sameProgram(component.replace(/\..*$/, ''), n) || sameProgram(component, n));
  const p = file.path;
  if (/\/systemd\/system\/[^/]+\.(service|socket|timer|path)$/.test(p)) return kinds.some(k => k.id === 'unit') ? { kind: 'unit', path: p } : null;
  if (/^\/etc\/rc\.d\/init\.d\/[^/]+$/.test(p)) return kinds.some(k => k.id === 'initrc') ? { kind: 'initrc', path: p } : null;
  if (OTHERS.test(p)) return null;
  let best = null;
  for (const k of kinds) {
    if (!k.where || k.where === 'tmpfs' || k.id === 'other' || k.id === 'unit' || k.id === 'initrc') continue;
    if (!p.startsWith(k.where + '/')) continue;
    const rest = p.slice(k.where.length + 1).split('/');
    if (!mine(rest[0])) continue;
    if (!best || k.where.length > best.k.where.length) best = { k, rest };
  }
  if (best) {
    const isDir = file.kind === 'd' || best.rest.length > 1;
    return { kind: best.k.id, path: isDir ? `${best.k.where}/${best.rest[0]}/` : p };
  }
  const m = /^(\/(?:srv|opt|var\/www|var\/local|usr\/local\/(?:etc|var))\/[^/]+)/.exec(p);
  if (m && mine(m[1].split('/').pop())) return { kind: 'other', path: `${m[1]}/` };
  return null;
}

/**
 * The assessment. generic: package files the policy labels generically (with the kind that would give them the
 * service's type); disagree: files on disk labeled otherwise than the policy says (restorecon's dry run, and
 * package files whose label differs from the policy's); missing: the module's paths that do not exist.
 */
function assess(facts, opts) {
  // The program's names: the module's, and the packages' (chrony owns chronyd: /etc/chrony.keys is its).
  const name = [opts.name || '', ...[...(facts.pkgs || new Map()).values()].filter(Boolean)].filter(Boolean);
  const kinds = opts.kinds || [];
  const types = opts.moduleTypes || new Set();
  const expected = opts.expected || new Map();
  const programs = new Set(opts.programs || []);
  const generic = [], disagree = [], missing = [], notes = [];
  let covered = 0, skipped = 0;
  const seen = new Set();
  for (const f of facts.files) {
    if (seen.has(f.path)) continue;
    seen.add(f.path);
    if (f.kind === 'l' || programs.has(f.path)) continue;
    const exp = expected.get(f.path) || null;
    if (exp && types.has(exp)) { covered++; if (f.label && f.label !== exp && f.label !== 'unlabeled_t') disagree.push({ path: f.path, from: f.label, to: exp, pkg: f.pkg }); continue; }
    if (exp && !GENERIC.has(exp)) continue; // another module's type: theirs
    const sug = kindFor(f, name, kinds);
    // Unit files and init scripts have a kind even under /usr/lib; everything else there is read-only data.
    if (!sug || (SKIP.test(f.path) && sug.kind !== 'unit' && sug.kind !== 'initrc')) { skipped++; continue; }
    // One row per suggested path (a directory stands for its files).
    const key = sug.path;
    const row = generic.find(g => g.suggest.path === key);
    if (row) { row.files.push(f.path); continue; }
    generic.push({ path: f.path, current: f.label || null, expected: exp, pkg: f.pkg, suggest: sug, files: [f.path], label: (kinds.find(k => k.id === sug.kind) || { label: sug.kind }).label });
  }
  const seenR = new Set(disagree.map(d => d.path));
  for (const r of facts.relabel) if (!seenR.has(r.path) && r.from !== r.to) { seenR.add(r.path); disagree.push({ path: r.path, from: r.from, to: r.to, pkg: null }); }
  for (const { path: p, kind } of opts.modelPaths || []) {
    const bare = p.endsWith('/') && p.length > 1 ? p.slice(0, -1) : p;
    if (facts.exist.has(bare) && !facts.exist.get(bare)) missing.push({ path: p, kind });
  }
  generic.sort((a, b) => a.suggest.path.localeCompare(b.suggest.path));
  disagree.sort((a, b) => a.path.localeCompare(b.path));
  if (!facts.files.length) notes.push(programs.size ? `No package owns ${[...programs].join(', ')} on the host (or rpm is not there): only the module's own paths were checked.` : 'No program paths to look at.');
  if (facts.uid !== 0) notes.push('Not root on the host: labels of files it may not read are unknown, and restorecon could not check every directory.');
  if (!facts.done) notes.push('The look at the host did not run to its end.');
  return { generic, disagree, missing, covered, skipped, notes };
}

module.exports = { coverageScript, parseCoverage, assess, kindFor, GENERIC, SKIP, OTHERS };
