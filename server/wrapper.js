'use strict';
/*
 * Wrapped programs: users of a chroot'ed login run wrapper programs; each
 * wrapper (its own domain) is the only domain that may run a protected copy
 * of a program, kept in a directory the user can't list, and the copy runs
 * in the original program's domain, with its privileges.
 *
 *   user (R, U) --runs--> wrapper W_exec_t --> W_t --execve--> copy C --> T (the original's domain)
 *
 * The copy's type C is a plain file type: not exec_type or entry_type, so the
 * rules other domains have on those attributes (executing any program,
 * domain_entry_file_spec_domtrans) don't reach it. Only W may execute it, and
 * only T may be entered through it. T keeps the rules it has on the
 * original's executable type, copied to C, and the role R gets T and the
 * domains T starts on its own (type_transition), so the program works as it
 * does outside the chroot.
 *
 * Paths: with the chroot labeled like / (an equivalence: semanage fcontext
 * -e / CHROOT, or a line of file_contexts.subs_dist), file contexts are
 * written for the paths as seen inside the chroot, so the protected directory
 * and the wrappers must use paths the host itself doesn't have. Without it,
 * the lines carry the chroot prefix and the rest of the chroot is labeled by
 * whoever set it up.
 *
 * Pure: no file access. ctx: { has(iface), optional(iface), moduleArgs,
 * typeExists(t), roleExists(r), moduleExists(m) }.
 */

const NAME_RE = /^[a-z][a-z0-9_]*$/;
const FILE_RE = /^[A-Za-z0-9._+-]+$/;
const PATH_RE = /^\/[^\s'"`$\\]*$/;
/** What every wrapper domain needs for an execve hop (where the tree has them). */
const DEFAULT_IFACES = ['libs_use_ld_so', 'libs_use_shared_libs', 'miscfiles_read_localization', 'userdom_use_user_terminals', 'domain_use_interactive_fds'];
const LOCAL_HEADER = '# Local additions (kept by the wrapper editor)';

function newModel() {
  return { name: '', summary: '', version: '1.0.0', chroot: '', likeRoot: true, protectedDir: '', wrapperDir: '', role: '', domain: '', logins: '', programs: [] };
}

/** The Linux logins of the chroot's users (for the checks): names, %groups. */
const loginList = (s) => String(s || '').split(/[\s,]+/).filter(Boolean);
const LOGIN_RE = /^%?[A-Za-z0-9_.][A-Za-z0-9_.-]*$/;

/*
 * The copy and the protected directory are security files where the policy has the interface:
 * broad rules on non-security files (RHEL: every user domain may getattr their directories)
 * then don't reach them, so the users can't even stat them.
 */
const fileDecl = (ctx) => (ctx.has && ctx.has('files_security_file') ? 'files_security_file' : 'files_type');

function newProgram(original, ctx) {
  const base = String(original || '').split('/').pop() || '';
  const stem = base.toLowerCase().replace(/[^a-z0-9_]+/g, '_').replace(/^[^a-z]+/, '').replace(/_+$/, '');
  return { stem, original: original || '', wrapper: base, copy: base ? `${base}.real` : '', pkg: null, origType: '', target: '', roles: [], selfRules: [],
    ifaces: ctx ? DEFAULT_IFACES.filter(n => ctx.has(n)) : DEFAULT_IFACES.slice() };
}

/** Type names of a program: wrapper domain W, its executable WE, the copy's type C; and the protected directory's type D. */
function names(model, p) {
  const n = model.name || 'NAME';
  const s = (p && p.stem) || 'PROG';
  return { W: `${n}_${s}_t`, WE: `${n}_${s}_exec_t`, C: `${n}_${s}_real_exec_t`, D: `${n}_protected_t` };
}

const trimDir = (d) => (d || '').trim().replace(/\/+$/, '');
const insideWrapper = (model, p) => `${trimDir(model.wrapperDir)}/${p.wrapper}`;
const insideCopy = (model, p) => `${trimDir(model.protectedDir)}/${p.copy}`;
/** The host path of a path inside the chroot. */
const hostPath = (model, inside) => `${trimDir(model.chroot)}${inside}`;
const escapeRe = (s) => s.replace(/[.+?*()[\]{}^$|\\]/g, (c) => `\\${c}`);
const unescapeRe = (s) => s.replace(/\\(.)/g, '$1');
/** A file-context path for a path inside the chroot. */
const fcSpec = (model, inside) => escapeRe(model.likeRoot ? inside : hostPath(model, inside));

/* ---------------- render ---------------- */

function call(ctx, n, arg) {
  return ctx.optional && ctx.optional(n) ? [`optional_policy(\``, `\t${n}(${arg})`, `')`] : [`${n}(${arg})`];
}

function renderTe(model, ctx) {
  const L = [];
  const R = model.role, U = model.domain;
  const progs = model.programs || [];
  const ext = new Set([U]);
  for (const p of progs) { if (p.target) ext.add(p.target); for (const d of p.roles || []) ext.add(d); }
  L.push(ctx.moduleArgs === 1 ? `policy_module(${model.name})` : `policy_module(${model.name}, ${model.version || '1.0.0'})`, '');
  L.push('########################################', '#', `# Wrapped programs${model.summary ? `: ${model.summary}` : ''}`, '#',
    `# Users in ${R} (${U}) run the wrappers in ${trimDir(model.wrapperDir)}. Each wrapper`,
    `# is the only domain that may run its protected copy in ${trimDir(model.protectedDir)},`,
    '# which then runs in the original program\'s domain.', '#',
    `# wrapper-chroot: ${trimDir(model.chroot)}`,
    `# wrapper-labels: ${model.likeRoot ? 'like /' : 'own'}`,
    `# wrapper-protected: ${trimDir(model.protectedDir)}`,
    `# wrapper-dir: ${trimDir(model.wrapperDir)}`,
    `# wrapper-user: ${R} ${U}`,
    ...(loginList(model.logins).length ? [`# wrapper-logins: ${loginList(model.logins).join(' ')}`] : []), '#', '');
  L.push('gen_require(`', `\trole ${R};`, `\ttype ${[...ext].filter(Boolean).join(', ')};`, '\')', '');
  const { D } = names(model);
  const decl = fileDecl(ctx);
  L.push(`type ${D};`, `${decl}(${D})`, '');
  for (const p of progs) {
    const { W, WE, C } = names(model, p);
    L.push('########################################', '#', `# ${p.stem}: ${p.original}, copied to ${insideCopy(model, p)}${p.pkg ? ` (package ${p.pkg})` : ''}`, '#', '');
    L.push(`type ${W};`, `type ${WE};`, `type ${C};`, `domain_type(${W})`, `domain_entry_file(${W}, ${WE})`, `${decl}(${C})`, `role ${R} types ${W};`, '');
    L.push(`# ${U} runs the wrapper.`, `domtrans_pattern(${U}, ${WE}, ${W})`, '');
    L.push('# The wrapper runs the protected copy.', `allow ${W} ${D}:dir search_dir_perms;`);
    if (p.target) L.push(`domtrans_pattern(${W}, ${C}, ${p.target})`);
    else L.push(`can_exec(${W}, ${C})`);
    for (const n of p.ifaces || []) L.push(...call(ctx, n, W));
    L.push('');
    if (p.target) {
      L.push(`# The copy runs as ${p.target}, like ${p.original}${p.origType ? ` (${p.origType})` : ''}.`,
        `allow ${p.target} ${C}:file { entrypoint mmap_exec_file_perms ioctl lock };`);
      for (const r of p.selfRules || []) L.push(`allow ${p.target} ${C}:${r.c} { ${r.perms.join(' ')} };`);
      const roleTypes = [p.target, ...(p.roles || []).filter(d => d !== p.target)];
      L.push(`role ${R} types ${roleTypes.length > 1 ? `{ ${roleTypes.join(' ')} }` : roleTypes[0]};`, '');
    } else {
      L.push(`# The copy runs in the wrapper's domain: ${p.original}${p.origType ? ` (${p.origType})` : ''} has no domain of its own.`, '');
    }
  }
  return L.join('\n').replace(/\n+$/, '\n');
}

function renderFc(model) {
  const { D } = names(model);
  const L = [`# ${model.name}: wrappers, the protected directory and its copies${model.likeRoot ? ` (paths inside ${trimDir(model.chroot)}, labeled like /)` : ''}.`];
  const gc = (t) => `gen_context(system_u:object_r:${t},s0)`;
  for (const p of model.programs || []) L.push(`${fcSpec(model, insideWrapper(model, p))}\t\t--\t${gc(names(model, p).WE)}`);
  L.push(`${fcSpec(model, trimDir(model.protectedDir))}\t\t-d\t${gc(D)}`);
  for (const p of model.programs || []) L.push(`${fcSpec(model, insideCopy(model, p))}\t\t--\t${gc(names(model, p).C)}`);
  return L.join('\n') + '\n';
}

function renderIf(model) {
  return `## <summary>Wrapped programs${model.summary ? `: ${model.summary}` : ''}</summary>
## <desc>
##	<p>
##	Users in ${model.role} run wrappers in ${trimDir(model.wrapperDir)} (inside ${trimDir(model.chroot)});
##	each wrapper is the only domain that may run its protected copy, which
##	runs in the original program's domain.
##	</p>
## </desc>
`;
}

function render(model, ctx) {
  return { te: renderTe(model, ctx), if: renderIf(model), fc: renderFc(model) };
}

/* ---------------- read back ---------------- */

/** The model of a module this editor wrote: { model } or { error }. */
function recognize(texts) {
  const te = texts.te || '';
  const head = (k) => { const m = new RegExp(`^# wrapper-${k}: (.*)$`, 'm').exec(te); return m ? m[1].trim() : null; };
  const chroot = head('chroot');
  if (chroot == null) return { error: 'This module wasn\'t written by the wrapper editor (no "# wrapper-chroot:" line).' };
  const model = newModel();
  const pm = /policy_module\(\s*(\w+)\s*(?:,\s*([^)\s]+))?\s*\)/.exec(te);
  model.name = pm ? pm[1] : '';
  model.version = (pm && pm[2]) || '1.0.0';
  const sm = /^# Wrapped programs(?:: (.*))?$/m.exec(te);
  model.summary = sm && sm[1] ? sm[1].trim() : '';
  model.chroot = chroot;
  model.likeRoot = head('labels') !== 'own';
  model.protectedDir = head('protected') || '';
  model.wrapperDir = head('dir') || '';
  const [R, U] = (head('user') || '').split(/\s+/);
  model.role = R || ''; model.domain = U || '';
  model.logins = head('logins') || '';
  const body = te.split(LOCAL_HEADER)[0];
  const blocks = body.split(/^########################################\n#\n# (?=\w+: \/)/m).slice(1);
  const fcLines = (texts.fc || '').split('\n');
  for (const b of blocks) {
    const hm = /^(\w+): (\S+), copied to (\S+?)(?: \(package (\S+)\))?$/m.exec(b);
    if (!hm) continue;
    const p = { stem: hm[1], original: hm[2], wrapper: '', copy: hm[3].split('/').pop(), pkg: hm[4] || null, origType: '', target: '', roles: [], selfRules: [], ifaces: [] };
    const { W, WE, C } = names(model, p);
    const dm = new RegExp(`domtrans_pattern\\(${W}, ${C}, (\\w+)\\)`).exec(b);
    p.target = dm ? dm[1] : '';
    const om = /^# The copy runs (?:as \w+, like \S+|in the wrapper's domain: \S+) \((\w+)\)/m.exec(b);
    if (om) p.origType = om[1];
    for (const m of b.matchAll(new RegExp(`^\\s*(\\w+)\\(${W}\\)\\s*$`, 'gm'))) if (m[1] !== 'domain_type') p.ifaces.push(m[1]);
    if (p.target) {
      for (const m of b.matchAll(new RegExp(`^allow ${p.target} ${C}:(\\w+) \\{ ([^}]*) \\};$`, 'gm'))) {
        if (/\bentrypoint\b/.test(m[2]) && /mmap_exec_file_perms/.test(m[2])) continue;
        p.selfRules.push({ c: m[1], perms: m[2].trim().split(/\s+/) });
      }
      const rm = new RegExp(`^role ${R} types (?:\\{ ([^}]*) \\}|(\\w+));$`, 'm');
      for (const m of b.matchAll(new RegExp(rm.source, 'gm'))) {
        const ts = (m[1] || m[2]).trim().split(/\s+/);
        if (ts.includes(W)) continue;
        p.roles = ts.filter(t => t !== p.target);
      }
    }
    const wl = fcLines.find(l => l.includes(`:${WE},`));
    if (wl) p.wrapper = unescapeRe(wl.split(/\s+/)[0]).split('/').pop();
    model.programs.push(p);
  }
  return { model };
}

/* ---------------- edits ---------------- */

/** Lines of `text` (before any local section) that `base` doesn't produce, and the local section's own lines. */
function keptLines(text, base) {
  if (text == null) return [];
  const [pre, local] = text.split(LOCAL_HEADER);
  const counts = new Map();
  for (const l of base.split('\n')) counts.set(l, (counts.get(l) || 0) + 1);
  const out = [];
  const preLines = pre.split('\n');
  // The local section's banner ('#####' and '#') before the header belongs to it.
  if (local != null) while (preLines.length && /^#*$/.test(preLines[preLines.length - 1].trim())) preLines.pop();
  for (const l of preLines) {
    if (!l.trim()) continue;
    const n = counts.get(l) || 0;
    if (n > 0) counts.set(l, n - 1); else out.push(l);
  }
  if (local != null) for (const l of local.split('\n').slice(1)) if (l.trim() && !/^#$/.test(l.trim())) out.push(l);
  return out;
}

/**
 * The module's texts for the model: rendered, plus lines of the existing
 * files the model doesn't describe (hand edits), kept in a local section at
 * the end. The .if is written for new modules only.
 */
function plan(model, ctx, old = null) {
  const out = render(model, ctx);
  if (!old) return { ...out, kept: [] };
  const rec = recognize(old);
  const base = rec.error ? { te: '', fc: '' } : render(rec.model, ctx);
  const keptTe = keptLines(old.te, base.te);
  const keptFc = keptLines(old.fc, base.fc);
  if (keptTe.length) out.te += `\n########################################\n#\n${LOCAL_HEADER}\n#\n\n${keptTe.join('\n')}\n`;
  if (keptFc.length) out.fc += `${LOCAL_HEADER}\n${keptFc.join('\n')}\n`;
  if (old.if != null && old.if !== '') out.if = old.if;
  return { ...out, kept: [...keptTe.map(text => ({ file: 'te', text })), ...keptFc.map(text => ({ file: 'fc', text }))] };
}

/* ---------------- checks ---------------- */

/**
 * Problems with the model ("Note: …" ones don't block).
 * opts: { isNew, hostExists(path) (the host's own file system), typeExists, roleExists }.
 */
function validate(model, ctx, opts = {}) {
  const P = [];
  const has = (n) => ctx.has(n);
  if (!NAME_RE.test(model.name || '')) P.push('The module name must start with a lowercase letter and use only lowercase letters, digits and _.');
  else if (opts.isNew && ctx.moduleExists && ctx.moduleExists(model.name)) P.push(`A module named ${model.name} already exists.`);
  const chroot = trimDir(model.chroot);
  if (!PATH_RE.test(model.chroot || '') || !chroot || /\/\.\.?(\/|$)/.test(chroot)) P.push('The chroot must be an absolute path other than / (e.g. /var/chroot/ro), without spaces or quotes.');
  for (const [what, v] of [['protected directory', model.protectedDir], ['wrapper directory', model.wrapperDir]]) {
    if (!PATH_RE.test(v || '') || !trimDir(v) || /\/\.\.?(\/|$)/.test(trimDir(v))) P.push(`The ${what} must be an absolute path inside the chroot other than / (as the user sees it, e.g. /.protected), without spaces or quotes.`);
  }
  const pd = trimDir(model.protectedDir), wd = trimDir(model.wrapperDir);
  if (pd && wd && (pd === wd || wd.startsWith(`${pd}/`) || pd.startsWith(`${wd}/`))) P.push('The wrappers and the protected copies need separate directories (the user may list the wrappers, not the copies).');
  if (!model.role || !model.domain) P.push('Pick the user (role and domain) that runs the wrappers.');
  else {
    if (opts.roleExists && !opts.roleExists(model.role)) P.push(`There is no role ${model.role}.`);
    if (opts.typeExists && !opts.typeExists(model.domain)) P.push(`There is no domain ${model.domain} in this policy (or its module is turned off).`);
  }
  const bad = loginList(model.logins).filter(l => !LOGIN_RE.test(l));
  if (bad.length) P.push(`Logins are Linux login names or %groups: ${bad.join(', ')} isn't one.`);
  else if (!loginList(model.logins).length) P.push('Note: give the Linux logins of the chroot\'s users (e.g. %chrootusers) to check after every build that they reach the programs\' domains only through the wrappers.');
  const progs = model.programs || [];
  if (!progs.length) P.push('Add at least one program to wrap.');
  const seen = { stem: new Set(), wrapper: new Set(), copy: new Set() };
  for (const p of progs) {
    const who = p.original || p.stem || 'a program';
    if (!NAME_RE.test(p.stem || '')) P.push(`${who}: its short name must start with a lowercase letter and use only lowercase letters, digits and _ (it names the types).`);
    if (!PATH_RE.test(p.original || '')) P.push(`${who}: the program must be an absolute path on this system.`);
    for (const k of ['wrapper', 'copy']) {
      if (!FILE_RE.test(p[k] || '')) P.push(`${who}: the ${k === 'wrapper' ? 'wrapper' : 'copy'}'s file name may use letters, digits, ., _, + and - only.`);
      else if (seen[k].has(p[k])) P.push(`Two programs use the ${k === 'wrapper' ? 'wrapper' : 'copy'} name ${p[k]}.`);
      seen[k].add(p[k]);
    }
    if (p.stem) { if (seen.stem.has(p.stem)) P.push(`Two programs have the short name ${p.stem}.`); seen.stem.add(p.stem); }
    if (p.target && opts.typeExists && !opts.typeExists(p.target)) P.push(`${who}: there is no domain ${p.target} in this policy (or its module is turned off).`);
    for (const d of p.roles || []) if (opts.typeExists && !opts.typeExists(d)) P.push(`${who}: there is no domain ${d}.`);
    for (const n of p.ifaces || []) if (!has(n)) P.push(`${who}: there is no interface ${n}${ctx.standalone ? ' in this host\'s devel headers' : ''}.`);
    for (const r of p.selfRules || []) if (!/^\w+$/.test(r.c) || !r.perms.every(x => /^\w+$/.test(x))) P.push(`${who}: a rule copied from the original has an odd class or permission.`);
    if (opts.isNew !== false && opts.typeExists && NAME_RE.test(p.stem || '') && NAME_RE.test(model.name || '')) {
      const { W, WE, C } = names(model, p);
      for (const t of [W, WE, C]) if (opts.typeExists(t) && opts.isNew) P.push(`${t} already exists in the policy.`);
    }
    if (!p.target && p.original) P.push(`Note: ${p.original} has no domain of its own, so its copy runs in the wrapper's domain ${names(model, p).W} with the rights the wrapper gets (add interfaces for it, or give the program a domain with New Service…).`);
  }
  // With the chroot labeled like /, a line for a path inside it also labels the same path on the host.
  if (model.likeRoot && opts.hostExists && pd && wd) {
    if (opts.hostExists(pd)) P.push(`${pd} exists on the host too: with the chroot labeled like /, its file-context line would label the host's ${pd} as well. Choose a name the host doesn't use (e.g. /.${model.name || 'wrapped'}).`);
    for (const p of progs) {
      const w = insideWrapper(model, p);
      if (p.wrapper && opts.hostExists(w)) P.push(`${w} exists on the host too: with the chroot labeled like /, its line would relabel the host's file. Choose a wrapper directory the host doesn't use (e.g. /opt/${model.name || 'wrapped'}/bin).`);
    }
  }
  return P;
}

/** Lines for selinux.checks: what must stay true. */
function checksText(model) {
  const { D } = names(model);
  const progs = model.programs || [];
  const logins = loginList(model.logins);
  const L = [`# Wrapped programs (${model.name}): ${model.domain} can't run, read or even see the protected copies${logins.length ? ',' : '.'}`];
  if (logins.length) L.push(`# and its logins reach the programs' domains only through their wrappers.`);
  if (progs.length) L.push(`never ${model.domain} may { execute read getattr } ${progs.map(p => names(model, p).C).join(' ')}:file`);
  L.push(`never ${model.domain} may { getattr search read } ${D}:dir`);
  // Role-aware: what the users' sessions can reach (their SELinux user, roles and ways in), not every type path.
  if (logins.length) for (const p of progs) if (p.target) L.push(`never login ${logins.join(' ')} reaches ${p.target} except through ${names(model, p).W}`);
  return L.join('\n') + '\n';
}

/** Shell commands that put the copies in place and label the chroot (host paths). */
function setupCommands(model) {
  const q = (s) => `'${String(s).replace(/'/g, "'\\''")}'`;
  const chroot = trimDir(model.chroot);
  const L = [];
  if (model.likeRoot) L.push(`semanage fcontext -a -e / ${q(chroot)}`);
  L.push(`install -d -m 0711 ${q(hostPath(model, trimDir(model.protectedDir)))}`);
  for (const p of model.programs || []) L.push(`cp -p ${q(p.original)} ${q(hostPath(model, insideCopy(model, p)))}`);
  L.push(`restorecon -R ${q(chroot)}`);
  return L;
}

module.exports = {
  NAME_RE, DEFAULT_IFACES, LOCAL_HEADER, newModel, newProgram, names, render, recognize, plan, validate, checksText, setupCommands,
  insideWrapper, insideCopy, hostPath, fcSpec, trimDir,
};
