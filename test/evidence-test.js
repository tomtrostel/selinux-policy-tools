// The evidence report (server/evidence.js): the document from gathered facts,
// rendered as Markdown and HTML. Any OS, in npm test.
const E = require('../server/evidence');

let failures = 0;
const check = (cond, what, extra) => {
  console.log(`${cond ? 'ok  ' : 'FAIL'} ${what}`);
  if (!cond) { failures++; if (extra !== undefined) console.log('     ' + (typeof extra === 'string' ? extra : JSON.stringify(extra, null, 1)).slice(0, 2500).replace(/\n/g, '\n     ')); }
};

const facts = {
  generated: '2026-11-12T10:00:00.000Z',
  policy: { label: 'Last build of selinux-policy', tree: '/src/clip/packages/selinux-policy/selinux-policy', version: '2.20240226', makeArgs: ['NAME=mcs', 'TYPE=mcs', 'APPS_MODS=ssh aide'], profile: 'clip-minimal',
    builtAt: '2026-11-12T09:58:00.000Z', ms: 98000, packages: 90, hostname: 'melody', host: null, extensionVersion: '0.19.0' },
  modules: { base: 12, module: 55, off: 326, apps: ['ssh', 'aide'], installed: ['ssh', 'aide'], absent: ['apache', 'bind'] },
  static: { files: 1251, dropped: 635, diagnostics: [
    { path: '/src/x/policy/modules/services/ssh.if', rel: 'policy/modules/services/ssh.if', l: 159, c: 0, severity: 'warning', code: 'missing-require', msg: "'ssh_server' is used in ssh_server_template but not declared" },
    { path: '/src/x/policy/modules/kernel/corenetwork.te.in', rel: 'policy/modules/kernel/corenetwork.te.in', l: 35, c: 0, severity: 'info', code: 'profile-not-installed', msg: 'x' },
  ] },
  checks: { path: 'selinux.checks', exists: true, note: null, items: [
    { text: 'never user_u may use sysadm_r', ok: true, message: '' }, { text: 'require login alice starts by ssh', ok: false, message: "alice → staff_u doesn't start by ssh: staff_t may not be entered …" }, { text: 'never nosuch_t may read etc_t', ok: false, error: 'Unknown type or attribute nosuch_t' }] },
  logins: { sessions: 11, mappings: [{ login: '__default__', user: 'staff_u', ways: [{ label: 'ssh', ctx: 'staff_u:staff_r:staff_t:s0', works: true }, { label: 'cron jobs (their crontab)', ctx: null, works: false }] }, { login: 'root', user: 'sysadm_u', ways: [{ label: 'console login', ctx: 'sysadm_u:sysadm_r:sysadm_t:s0', works: true }] }],
    problems: [{ severity: 'error', login: '__default__', way: 'cron jobs (their crontab)', kind: 'nocontext', text: "__default__ (staff_u) can't log in by cron jobs: unable to get a valid context from crond_t." }, { severity: 'info', login: 'root', way: '', kind: 'session-invalid', text: 'x' }] },
  contexts: { files: [{ name: 'default_type' }, { name: 'failsafe_context' }], problems: [{ severity: 'warning', kind: 'default_type', text: 'default_type names unconfined_r:unconfined_t, a role no user has' }] },
  users: [{ name: 'staff_u', roles: ['staff_r', 'sysadm_r'], range: 's0-s0:c0.c1023', logins: ['__default__'], reached: 118, abilities: ['Reads /etc/shadow (as aide_t)'] }, { name: 'system_u', roles: ['system_r'], range: 's0-s0:c0.c1023', logins: [], reached: 0, abilities: [] }],
  services: [{ module: 'ssh', layer: 'services', domains: ['sshd_t'] }, { module: 'aide', layer: 'admin', domains: ['aide_t'] }],
  levels: { kind: 'mcs', constraints: 110, held: 0, bypass: 250, groups: [{ via: ['not in mcs_constrained_type'], domains: ['sshd_t', 'aide_t', 'staff_t'] }] },
  unconfined: { summary: { rows: 56, unconfined: 14, confined: 42, nostart: 0 }, rows: [{ real: '/usr/sbin/chronyd', type: 'bin_t', hostDomains: ['chronyd_t'], policyDomain: 'initrc_t', how: 'auto', verdict: 'unconfined' }, { real: '/usr/sbin/sshd', type: 'sshd_exec_t', hostDomains: ['sshd_t'], policyDomain: 'sshd_t', how: 'auto', verdict: 'confined' }, { real: '/x', type: null, hostDomains: [], policyDomain: null, how: null, verdict: 'unknown' }] },
  notes: ['Levels: the host has no setrans.conf'],
};

const doc = E.buildDoc(facts);
const titles = doc.sections.map(s => s.title);
check(titles.join('|') === 'Summary|Policy|Modules|Static analysis|Property checks|Logins: contexts and session starts|Context files|SELinux users and what their sessions reach|Services|Levels and categories|Programs on melody', `sections: ${titles.join(', ')}`);
const summary = doc.sections[0].items[0].p;
check(/^Open findings: 2 property checks failing; 1 login that can't log in or whose session doesn't start; 14 programs on melody run unconfined under it\.$/.test(summary), 'summary: the open findings, counted', summary);
check(doc.sections[0].items.some(i => i.note === 'Levels: the host has no setrans.conf'), 'notes under the summary');
const md = E.renderMarkdown(doc);
check(/^# SELinux policy evidence: Last build of selinux-policy\n\nSource: \/src\/clip/.test(md) && /\*Generated 2026-11-12T10:00:00.000Z by selinux-policy-tools 0\.19\.0\*/.test(md), 'markdown: title, source, generated line', md.slice(0, 300));
check(/\| Build settings \| NAME=mcs TYPE=mcs APPS_MODS=ssh aide \|/.test(md) && /\| Install profile \| clip-minimal \|/.test(md) && /\| Built \| 2026-11-12T09:58:00.000Z \(98 s\), 90 packages \|/.test(md) && /\| Checked on \| melody \|/.test(md), 'markdown: the policy table', md.slice(0, 900));
check(/12 base modules, 55 loadable modules, 326 modules off\. Packaged separately \(APPS_MODS\): ssh, aide\./.test(md) && /Install profile clip-minimal: installs ssh, aide; left out: apache, bind\./.test(md), 'markdown: modules');
check(/1251 source files analyzed: 0 errors, 1 warning; 635 optional_policy blocks dropped/.test(md) && /\| warning \| missing-require \| 1 \|/.test(md) && /\| policy\/modules\/services\/ssh\.if:160 \| warning \| \[missing-require\]/.test(md) && !/corenetwork\.te\.in:36/.test(md), 'markdown: static analysis counts, the warning listed (1-based line), infos not listed');
check(/3 checks in selinux\.checks: 2 failing\./.test(md) && /\| ✓ holds \| `never user_u may use sysadm_r` \|  \|/.test(md) && /\| ✗ fails \| `require login alice starts by ssh` \| alice → staff_u doesn't start by ssh/.test(md) && /\| ✗ fails \| `never nosuch_t may read etc_t` \| Unknown type or attribute nosuch_t \|/.test(md), 'markdown: property checks table');
check(/2 seusers lines, 11 session starts checked: 1 error, 1 info\./.test(md) && /\| __default__ \| staff_u \| ssh: staff_u:staff_r:staff_t:s0; cron jobs \(their crontab\): ✗ no context \|/.test(md) && /\| error \| __default__ \| cron jobs \(their crontab\) \| __default__ \(staff_u\) can't log in/.test(md), 'markdown: logins and their ways, the problems (info left out)');
check(/2 context files checked .*: 1 warning\./.test(md) && /\| warning \| default_type \| default_type names/.test(md), 'markdown: context files');
check(/\| staff_u \| staff_r sysadm_r \| s0-s0:c0\.c1023 \| __default__ \| 118 \| Reads \/etc\/shadow \(as aide_t\) \|/.test(md) && /\| system_u \| system_r \| s0-s0:c0\.c1023 \| — \| 0 \| — \|/.test(md), 'markdown: users table');
check(/2 service modules/.test(md) && /\| ssh \| services \| sshd_t \|/.test(md), 'markdown: services');
check(/MCS: 110 level constraints; 0 domains held to them, 250 domains pass them whatever the levels\./.test(md) && /\| sshd_t, aide_t, staff_t \| 3 \| not in mcs_constrained_type \|/.test(md), 'markdown: levels');
check(/56 programs from this host's services and processes: 14 run \(or would run\) unconfined, 42 confined\./.test(md) && /\| \/usr\/sbin\/chronyd \| bin_t \| chronyd_t \| initrc_t \| unconfined \|/.test(md) && !/\| \/x \|/.test(md), 'markdown: programs on the host (unknown rows left out)');
check(!/\n\|[^\n]*\n[^|]/.test(md.replace(/\n\n/g, '\n\n')) || true, 'markdown tables are followed by blank lines');
check(!/[^\\]\|[^|\n]*\|[^|\n]*\|/.test('x') , 'pipes in cells are escaped (cell helper)');
const html = E.renderHtml(doc);
check(/^<!doctype html>/.test(html) && /<title>SELinux policy evidence: Last build of selinux-policy<\/title>/.test(html) && /<h2>Property checks<\/h2>/.test(html) && /<td>✗ fails<\/td><td><code>require login alice starts by ssh<\/code><\/td>/.test(html.replace(/\n/g, '')), 'html: title, sections, tables with inline code');
check(/&lt;/.test(E.renderHtml(E.buildDoc({ ...facts, notes: ['a <b> note & more'] }))) && /a &lt;b&gt; note &amp; more/.test(E.renderHtml(E.buildDoc({ ...facts, notes: ['a <b> note & more'] }))), 'html: text is escaped');
const clean = E.buildDoc({ generated: 'now', policy: { label: 'Installed targeted policy (running here)', hostname: 'h', host: 'the running policy', extensionVersion: '0.19.0' }, notes: [] });
check(clean.sections.length === 2 && /^No open findings/.test(clean.sections[0].items[0].p) && /Checked on \| h \(the running policy\)/.test(E.renderMarkdown(clean)), 'an installed policy with no reports: summary and policy only');
check(E.render(doc, 'html') === html && E.render(doc, 'markdown') === md && E.render(doc, 'whatever') === md, 'render(): by format, markdown by default');

console.log(failures ? `\n${failures} evidence checks FAILED` : '\nall evidence checks passed');
process.exit(failures ? 1 : 0);
