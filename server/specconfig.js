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

/**
 * Build settings for each variant of the spec at `specPath`:
 * { makeArgs, files: { 'policy/modules.conf': [abs paths], ... }, missing: [abs paths] }.
 */
function specBuildConfigs(specPath, treeRoot = null) {
  const dir = path.dirname(specPath);
  const spec = parseSpec(fs.readFileSync(specPath, 'utf8'));
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

module.exports = { parseSpec, specBuildConfigs };
