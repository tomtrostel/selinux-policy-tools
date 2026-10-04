'use strict';
/*
 * Derive full-tree build settings from a Fedora/RHEL selinux-policy.spec.
 *
 * The spec builds each policy variant with
 *   %makeCmds <NAME> <TYPE> <UNK_PERMS>          (make bare/conf, copy booleans-NAME.conf, users-NAME)
 *   %makeModulesConf <conf> <base> <contrib>      (modules.conf = modules-conf-base.conf [+ modules-conf-contrib.conf])
 *   %installCmds ...                              (make base.pp validate modules ...)
 * and `%common_params` for the shared make variables. We read those lines,
 * not the shell in the macro bodies, and map the copied files onto
 * selinux.build.tree.files entries pointing at the spec's directory (where an
 * unpacked source RPM or a dist-git checkout keeps them).
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
  const common = defs.has('common_params') ? expand(defs.get('common_params')).split(/\s+/).filter(a => /^\w+=/.test(a)) : [];

  const variants = [];
  const lines = text.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const mc = /^%makeCmds\s+(\S+)\s+(\S+)\s+(\S+)/.exec(lines[i]);
    if (!mc) continue;
    const v = { name: mc[1], type: mc[2], unkPerms: mc[3], modulesConf: null };
    for (let j = i + 1; j < lines.length && !/^%makeCmds\s/.test(lines[j]); j++) {
      const mm = /^%makeModulesConf\s+(\S+)\s+(\S+)(?:\s+(\S+))?/.exec(lines[j]);
      if (mm) { v.modulesConf = { conf: mm[1], base: mm[2], contrib: mm[3] || null }; break; }
    }
    variants.push(v);
  }
  return {
    common, variants,
    copiesBooleans: /booleans-%1\.conf\s+\.\/policy\/booleans\.conf/.test(makeCmds),
    copiesUsers: /users-%1\s+\.\/policy\/users/.test(makeCmds),
    concatContrib: /modules-%1-%3\.conf\s*>>\s*\.\/policy\/modules\.conf/.test(modulesConf),
  };
}

/**
 * Build settings for each variant of the spec at `specPath`:
 * { makeArgs, files: { 'policy/modules.conf': [abs paths], ... }, missing: [abs paths] }.
 */
function specBuildConfigs(specPath) {
  const dir = path.dirname(specPath);
  const spec = parseSpec(fs.readFileSync(specPath, 'utf8'));
  return spec.variants.map((v) => {
    const files = {};
    if (spec.copiesBooleans) files['policy/booleans.conf'] = [path.join(dir, `booleans-${v.name}.conf`)];
    if (spec.copiesUsers) files['policy/users'] = [path.join(dir, `users-${v.name}`)];
    if (v.modulesConf) {
      const mc = v.modulesConf;
      files['policy/modules.conf'] = [path.join(dir, `modules-${mc.conf}-${mc.base}.conf`)];
      if (mc.contrib === 'contrib' && spec.concatContrib) files['policy/modules.conf'].push(path.join(dir, `modules-${mc.conf}-contrib.conf`));
    }
    const missing = Object.values(files).flat().filter(p => !fs.existsSync(p));
    return {
      variant: v.name,
      makeArgs: [...spec.common, `UNK_PERMS=${v.unkPerms}`, `NAME=${v.name}`, `TYPE=${v.type}`],
      files, missing,
    };
  });
}

module.exports = { parseSpec, specBuildConfigs };
