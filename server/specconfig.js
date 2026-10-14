'use strict';
/*
 * Derive full-tree build settings from a Fedora/RHEL selinux-policy.spec.
 *
 * The spec builds each policy variant with
 *   %makeCmds <NAME> <TYPE> <UNK_PERMS>          (make bare/conf, copy booleans and users)
 *   %makeModulesConf <conf> [<base> <contrib>]    (write policy/modules.conf)
 *   %installCmds ...                              (make base.pp validate modules ...)
 * and `%common_params` for the shared make variables. We read those lines,
 * not the shell in the macro bodies, and map the copied files onto
 * selinux.build.tree.files entries. Two layouts:
 *  - RHEL 9 / older Fedora: booleans-NAME.conf, users-NAME and
 *    modules-CONF-base.conf [+ modules-CONF-contrib.conf] next to the spec;
 *  - RHEL 10 / newer Fedora: dist/NAME/booleans.conf and dist/NAME/users in
 *    the tree, and modules.conf = dist/CONF/modules.conf with the modules in
 *    list files (modules-dropped.lst, for some variants also
 *    modules-extra.lst) turned off by process-modules-filtered.py
 *    ("disabled" mode), expressed as { from, disable } (build.overlaySource).
 */
const fs = require('fs');
const path = require('path');

function parseSpec(text) {
  const defs = new Map();
  for (const m of text.matchAll(/^%(?:define|global)\s+(\w+)\s+(.*)$/gm)) {
    if (!defs.has(m[1])) defs.set(m[1], m[2].trim());
  }
  const expand = (s, depth = 0) => depth > 5 ? s : s.replace(/%\{(\w+)\}|%(\w+)\b/g, (all, a, b) => {
    const k = a || b;
    return defs.has(k) ? expand(defs.get(k), depth + 1) : all;
  });
  // A parametric macro's body: the lines after `%define name() \` while they end in a backslash.
  const body = (name) => {
    const lines = text.split('\n');
    const start = lines.findIndex(l => new RegExp(`^%define\\s+${name}\\(\\)`).test(l));
    if (start < 0) return '';
    const out = [];
    for (let i = start; i < lines.length && /\\\s*$/.test(lines[i]); i++) out.push(lines[i + 1] || '');
    return out.join('\n');
  };
  const makeCmds = body('makeCmds'), modulesConf = body('makeModulesConf');
  // SourceN: file names (URLs and macros reduced to the basename).
  const sources = new Map();
  for (const m of text.matchAll(/^Source(\d*):\s*(\S+)/gm)) sources.set(m[1] || '0', path.basename(expand(m[2])));
  const src = (ref) => { const m = /%\{SOURCE(\d+)\}/.exec(ref); return m ? sources.get(m[1]) || null : null; };
  // `<filter script> <list> <modules.conf> disabled`: the lists whose modules the filter turns off.
  const filterLists = (s) => [...s.matchAll(/%\{SOURCE\d+\}\s+(%\{SOURCE\d+\})\s+\S+\s+(disabled|enabled)/g)].map(m => ({ list: src(m[1]), mode: m[2] }));
  const common = defs.has('common_params') ? expand(defs.get('common_params')).split(/\s+/).filter(a => /^\w+=/.test(a)) : [];

  const variants = [];
  const lines = text.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const mc = /^%makeCmds\s+(\S+)\s+(\S+)\s+(\S+)/.exec(lines[i]);
    if (!mc) continue;
    const v = { name: mc[1], type: mc[2], unkPerms: mc[3], modulesConf: null, extraFilters: [] };
    for (let j = i + 1; j < lines.length && !/^%makeCmds\s/.test(lines[j]) && !/^%installCmds\s/.test(lines[j]); j++) {
      const mm = /^%makeModulesConf\s+(\S+)(?:\s+(\S+))?(?:\s+(\S+))?/.exec(lines[j]);
      if (mm) { v.modulesConf = { conf: mm[1], base: mm[2] || null, contrib: mm[3] || null }; continue; }
      // RHEL 10 minimum/automotive filter the result once more (e.g. modules-extra.lst).
      if (v.modulesConf) v.extraFilters.push(...filterLists(lines[j]));
    }
    variants.push(v);
  }
  return {
    common, variants,
    copiesBooleans: /booleans-%1\.conf\s+\.\/policy\/booleans\.conf/.test(makeCmds),
    copiesUsers: /users-%1\s+\.\/policy\/users/.test(makeCmds),
    concatContrib: /modules-%1-%3\.conf\s*>>\s*\.\/policy\/modules\.conf/.test(modulesConf),
    // RHEL 10 layout
    distBooleans: /\.\/dist\/%1\/booleans\.conf\s+\.\/policy\/booleans\.conf/.test(makeCmds),
    distUsers: /\.\/dist\/%1\/users\s+\.\/policy\/users/.test(makeCmds),
    distModulesConf: /\.\/dist\/%1\/modules\.conf/.test(modulesConf.replace(/^\s*#.*$/gm, '')),
    modulesFilters: filterLists(modulesConf.replace(/^\s*#.*$/gm, '')),
  };
}

/*
 * CLIP (github.com/sealingtech/CLIP, packages/selinux-policy): the spec has
 * no %makeCmds; it builds with `%installCmds NAME TYPE DIRECT_INITRC POLY
 * UNKNOWN`, whose first make line (base.pp) carries every variable, and
 * APPS_MODS="%{enable_modules} %{separatePkgs}" comes from the Makefile next
 * to it (SEPARATE_PKGS / ENABLE_MODULES, passed in by `make rpm`). The tree's
 * own modules.conf, booleans and users are used as they are.
 */
function makeVars(text) {
  const vars = new Map();
  let skip = 0;   // depth inside a conditional that is off by default
  const depth = [];
  for (let line of text.replace(/\\\n/g, ' ').split('\n')) {
    line = line.replace(/(^|[^\\])#.*$/, '$1').trim();
    if (!line) continue;
    const cond = /^(ifn?eq|ifn?def)\b(.*)$/.exec(line);
    if (cond) {
      // `ifeq/ifneq (A,B)` over plain variables (and $(strip …)) is decided
      // with what's set so far (unset = empty: the defaults); anything else
      // counts as on.
      let off = false;
      const pm = /^\s*\((.*),(.*)\)\s*$/.exec(cond[2]);
      if (pm && /^ifn?eq$/.test(cond[1])) {
        const ev = (s) => s.replace(/\$\(strip\s+\$\((\w+)\)\)|\$\((\w+)\)/g, (all, a, b) => vars.get(a || b) || '').trim();
        const a = ev(pm[1]), b = ev(pm[2]);
        if (!/\$\(/.test(a + b)) off = (a === b) === (cond[1] === 'ifneq');
      }
      depth.push(off); if (off) skip++;
      continue;
    }
    if (/^else\b/.test(line)) { const d = depth.length - 1; if (d >= 0) { skip += depth[d] ? -1 : 1; depth[d] = !depth[d]; } continue; }
    if (/^endif\b/.test(line)) { if (depth.pop()) skip--; continue; }
    if (skip) continue;
    const m = /^([A-Za-z_]\w*)\s*(\+=|:=|\?=|=)\s*(.*)$/.exec(line);
    if (!m) continue;
    const val = m[3].replace(/\$\((\w+)\)/g, (all, k) => vars.get(k) || '').replace(/\s+/g, ' ').trim();
    if (m[2] === '+=') vars.set(m[1], `${vars.get(m[1]) || ''} ${val}`.trim());
    else if (m[2] !== '?=' || !vars.has(m[1])) vars.set(m[1], val);
  }
  return vars;
}

function clipBuildConfigs(specPath, text) {
  const dir = path.dirname(specPath);
  const lines = text.split('\n');
  const start = lines.findIndex(l => /^%define\s+installCmds\(\)/.test(l));
  const call = lines.map(l => /^%installCmds\s+(.+)$/.exec(l)).find(Boolean);
  if (start < 0 || !call) return null;
  let make = null;
  for (let i = start + 1; i < lines.length && /\\\s*$/.test(lines[i - 1]); i++) if (/^\s*make\b.*\bbase\.pp\b/.test(lines[i])) { make = lines[i].replace(/\\\s*$/, ''); break; }
  if (!make) return null;
  const mkPath = path.join(dir, 'Makefile');
  const mk = fs.existsSync(mkPath) ? makeVars(fs.readFileSync(mkPath, 'utf8')) : new Map();
  // CLIP's top-level CONFIG_BUILD sets the policy type for the whole build.
  const top = path.join(dir, '..', '..', 'CONFIG_BUILD');
  const topVars = fs.existsSync(top) ? makeVars(fs.readFileSync(top, 'utf8')) : new Map();
  const notes = [];
  if (!fs.existsSync(mkPath)) notes.push('no Makefile next to the spec: APPS_MODS (SEPARATE_PKGS) left empty');
  const defs = new Map();
  for (const m of text.matchAll(/^%(?:define|global)\s+(\w+)\s+(.*)$/gm)) if (!defs.has(m[1])) defs.set(m[1], m[2].trim());
  defs.set('nil', '');
  defs.set('type', topVars.get('CONFIG_BUILD_SELINUX_POL_TYPE') || mk.get('CONFIG_BUILD_SELINUX_POL_TYPE') || 'mcs');
  defs.set('separatePkgs', mk.get('SEPARATE_PKGS') || '');
  // ENABLE_MODULES already includes SEPARATE_PKGS (`ENABLE_MODULES := $(ENABLE_MODULES) $(SEPARATE_PKGS)`).
  defs.set('enable_modules', mk.get('ENABLE_MODULES') || '');
  const expand = (s, depth = 0) => depth > 5 ? s : s.replace(/%\{\?[^}]*\}/g, '').replace(/%\{(\w+)\}/g, (all, k) => defs.has(k) ? expand(defs.get(k), depth + 1) : all);
  const args = expand(call[1]).trim().split(/\s+/);
  const body = expand(make.replace(/%([1-9])/g, (all, n) => args[n - 1] || ''));
  const makeArgs = [];
  for (const m of body.matchAll(/(\w+)=("([^"]*)"|'([^']*)'|\S*)/g)) {
    if (m[1] === 'DESTDIR') continue;
    let v = m[3] != null ? m[3] : m[4] != null ? m[4] : m[2];
    if (m[1] === 'APPS_MODS') v = [...new Set(v.split(/\s+/).filter(Boolean))].join(' ');
    else v = v.trim();
    makeArgs.push(`${m[1]}=${v}`);
  }
  const name = (makeArgs.find(a => a.startsWith('NAME=')) || 'NAME=clip').slice(5);
  return [{ variant: name, makeArgs, files: {}, missing: [], notes, clip: true }];
}

/**
 * Build settings for each variant of the spec at `specPath`:
 * { makeArgs, files: { 'policy/modules.conf': [abs paths], ... }, missing: [abs paths] }.
 */
function specBuildConfigs(specPath, treeRoot = null) {
  const dir = path.dirname(specPath);
  const text = fs.readFileSync(specPath, 'utf8');
  const spec = parseSpec(text);
  if (!spec.variants.length) return clipBuildConfigs(specPath, text) || [];
  return spec.variants.map((v) => {
    const files = {}, notes = [];
    // Tree-relative paths (dist/...) are resolved against the tree root by the build.
    if (spec.copiesBooleans) files['policy/booleans.conf'] = [path.join(dir, `booleans-${v.name}.conf`)];
    else if (spec.distBooleans) files['policy/booleans.conf'] = [`dist/${v.name}/booleans.conf`];
    if (spec.copiesUsers) files['policy/users'] = [path.join(dir, `users-${v.name}`)];
    else if (spec.distUsers) files['policy/users'] = [`dist/${v.name}/users`];
    if (v.modulesConf) {
      const mc = v.modulesConf;
      if (spec.distModulesConf) {
        const filters = [...spec.modulesFilters, ...v.extraFilters];
        for (const f of filters) if (f.mode !== 'disabled' || !f.list) notes.push(`a modules.conf filter in "${f.mode}" mode isn't supported; ${f.list || 'its list'} was ignored`);
        const disable = filters.filter(f => f.mode === 'disabled' && f.list).map(f => path.join(dir, f.list));
        files['policy/modules.conf'] = [disable.length ? { from: `dist/${mc.conf}/modules.conf`, disable } : `dist/${mc.conf}/modules.conf`];
      } else if (mc.base) {
        files['policy/modules.conf'] = [path.join(dir, `modules-${mc.conf}-${mc.base}.conf`)];
        if (mc.contrib === 'contrib' && spec.concatContrib) files['policy/modules.conf'].push(path.join(dir, `modules-${mc.conf}-contrib.conf`));
      }
    }
    const abs = (p) => (path.isAbsolute(p) ? p : treeRoot ? path.join(treeRoot, p) : null);
    const paths = Object.values(files).flat().flatMap(x => (typeof x === 'string' ? [x] : [x.from, ...x.disable]));
    const missing = paths.filter(p => abs(p) && !fs.existsSync(abs(p)));
    return {
      variant: v.name,
      makeArgs: [...spec.common, `UNK_PERMS=${v.unkPerms}`, `NAME=${v.name}`, `TYPE=${v.type}`],
      files, missing, notes,
    };
  });
}

module.exports = { parseSpec, specBuildConfigs, makeVars };
