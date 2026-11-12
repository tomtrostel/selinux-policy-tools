'use strict';
/*
 * Evidence report (pure): one document about a policy as the extension sees
 * it, for the accreditation paperwork a locked-down system needs. The
 * server gathers the facts (buildReport) into a document model of sections
 * with paragraphs, tables and lists; render() writes it as Markdown or
 * HTML. Everything in it comes from reports the panels already compute.
 *
 * Document model: { title, subtitle, generated, sections: [{ title, items:
 * [{ p } | { table: { head, rows } } | { list } | { pre } | { note }] }] }.
 */

const esc = (s) => String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
const cell = (s) => String(s == null ? '' : s).replace(/\|/g, '\\|').replace(/\r?\n/g, ' ');

function renderMarkdown(doc) {
  const out = [`# ${doc.title}`, ''];
  if (doc.subtitle) out.push(doc.subtitle, '');
  if (doc.generated) out.push(`*${doc.generated}*`, '');
  for (const s of doc.sections) {
    out.push(`## ${s.title}`, '');
    for (const it of s.items) {
      if (it.p != null) out.push(it.p, '');
      else if (it.note != null) out.push(`> ${it.note}`, '');
      else if (it.pre != null) out.push('```', it.pre, '```', '');
      else if (it.list) { for (const l of it.list) out.push(`- ${l}`); out.push(''); }
      else if (it.table) {
        const t = it.table;
        if (!t.rows.length) { out.push(t.empty || '*none*', ''); continue; }
        out.push(`| ${t.head.map(cell).join(' | ')} |`, `| ${t.head.map(() => '---').join(' | ')} |`);
        for (const r of t.rows) out.push(`| ${r.map(cell).join(' | ')} |`);
        out.push('');
      }
    }
  }
  return out.join('\n');
}

function renderHtml(doc) {
  const out = [`<!doctype html><html><head><meta charset="utf-8"><title>${esc(doc.title)}</title><style>`,
    'body{font-family:system-ui,sans-serif;max-width:60em;margin:2em auto;padding:0 1em;color:#222}h1{border-bottom:2px solid #888}h2{margin-top:1.6em;border-bottom:1px solid #ccc}',
    'table{border-collapse:collapse;margin:.5em 0;font-size:.95em}th,td{border:1px solid #ccc;padding:.25em .6em;text-align:left;vertical-align:top}th{background:#f3f3f3}',
    'code,pre{font-family:ui-monospace,monospace;font-size:.92em}pre{background:#f7f7f7;padding:.6em;overflow:auto}blockquote{border-left:4px solid #ccc;margin:.5em 0;padding:.2em .8em;color:#555}',
    '.ok{color:#2a7a2a}.bad{color:#b02020}.warn{color:#9a6a00}', '</style></head><body>', `<h1>${esc(doc.title)}</h1>`];
  if (doc.subtitle) out.push(`<p>${esc(doc.subtitle)}</p>`);
  if (doc.generated) out.push(`<p><em>${esc(doc.generated)}</em></p>`);
  const inline = (s) => esc(s).replace(/`([^`]+)`/g, '<code>$1</code>').replace(/\*\*([^*]+)\*\*/g, '<b>$1</b>');
  for (const s of doc.sections) {
    out.push(`<h2>${esc(s.title)}</h2>`);
    for (const it of s.items) {
      if (it.p != null) out.push(`<p>${inline(it.p)}</p>`);
      else if (it.note != null) out.push(`<blockquote>${inline(it.note)}</blockquote>`);
      else if (it.pre != null) out.push(`<pre>${esc(it.pre)}</pre>`);
      else if (it.list) out.push('<ul>', ...it.list.map(l => `<li>${inline(l)}</li>`), '</ul>');
      else if (it.table) {
        const t = it.table;
        if (!t.rows.length) { out.push(`<p><em>${esc(t.empty || 'none')}</em></p>`); continue; }
        out.push('<table><tr>', ...t.head.map(h => `<th>${esc(h)}</th>`), '</tr>');
        for (const r of t.rows) out.push('<tr>', ...r.map(c => `<td>${inline(c)}</td>`), '</tr>');
        out.push('</table>');
      }
    }
  }
  out.push('</body></html>');
  return out.join('\n');
}

function render(doc, format) { return format === 'html' ? renderHtml(doc) : renderMarkdown(doc); }

const plural = (n, w) => `${n} ${w}${n === 1 ? '' : 's'}`;
const sevCounts = (problems) => ['error', 'warning', 'info'].map(s => [s, (problems || []).filter(p => p.severity === s).length]).filter(([, n]) => n).map(([s, n]) => plural(n, s)).join(', ') || 'none';

/**
 * The document from the gathered facts:
 * { policy: { label, tree, version, makeArgs, variant, profile, builtAt, ms, packages, host, hostname, extensionVersion },
 *   modules: { base, module, off, apps: [] } | null, static: { files, diagnostics: [], dropped: n } | null,
 *   checks: { path, items: [{ text, ok, message, error }] } | null, logins: { mappings: [{ login, user, ways: [{ label, ctx, works }] }], problems } | null,
 *   contexts: { files: [{ name, exists, problems }], problems } | null, users: [{ name, roles, range, logins, reached, abilities: [] }] | null,
 *   services: [{ module, layer, domains }] | null, levels: { kind, constraints, held, groups: [{ via, domains }] } | null,
 *   unconfined: { summary, rows } | null, notes: [] }
 */
function buildDoc(f) {
  const p = f.policy || {};
  const sections = [];
  const S = (title, items) => sections.push({ title, items: items.filter(Boolean) });
  const verdicts = [];
  // 1. Identity.
  S('Policy', [
    { table: { head: ['', ''], rows: [
      ['Policy', p.label || '?'], p.tree ? ['Source tree', `${p.tree}${p.version ? ` (refpolicy ${p.version})` : ''}`] : null,
      p.makeArgs && p.makeArgs.length ? ['Build settings', p.makeArgs.join(' ')] : null, p.variant ? ['Variant', p.variant] : null, p.profile ? ['Install profile', p.profile] : null,
      p.builtAt ? ['Built', `${p.builtAt}${p.ms ? ` (${(p.ms / 1000).toFixed(0)} s)` : ''}${p.packages ? `, ${plural(p.packages, 'package')}` : ''}`] : null,
      p.hostname ? ['Checked on', `${p.hostname}${p.host ? ` (${p.host})` : ''}`] : null, p.extensionVersion ? ['Tool', `selinux-policy-tools ${p.extensionVersion}`] : null,
    ].filter(Boolean) } },
  ]);
  // 2. Modules.
  if (f.modules) {
    const m = f.modules;
    S('Modules', [
      { p: `${plural(m.base, 'base module')}, ${plural(m.module, 'loadable module')}, ${plural(m.off, 'module')} off.${m.apps && m.apps.length ? ` Packaged separately (APPS_MODS): ${m.apps.join(', ')}.` : ''}` },
      m.installed ? { p: `Install profile ${p.profile}: ${m.installed.length ? `installs ${m.installed.join(', ')}` : 'installs none of them'}${m.absent && m.absent.length ? `; left out: ${m.absent.join(', ')}` : ''}.` } : null,
    ]);
  }
  // 3. Static analysis.
  if (f.static) {
    const st = f.static;
    const by = {};
    for (const d of st.diagnostics || []) by[`${d.severity}:${d.code}`] = (by[`${d.severity}:${d.code}`] || 0) + 1;
    const errs = (st.diagnostics || []).filter(d => d.severity === 'error').length, warns = (st.diagnostics || []).filter(d => d.severity === 'warning').length;
    verdicts.push(errs ? `${plural(errs, 'static error')}` : null);
    S('Static analysis', [
      { p: `${plural(st.files, 'source file')} analyzed: ${plural(errs, 'error')}, ${plural(warns, 'warning')}${st.dropped != null ? `; ${plural(st.dropped, 'optional_policy block')} dropped by the linker in this configuration` : ''}.` },
      { table: { head: ['Severity', 'Kind', 'Count'], rows: Object.entries(by).sort().map(([k, n]) => [...k.split(':'), String(n)]), empty: 'No findings.' } },
      (st.diagnostics || []).filter(d => d.severity !== 'info').length ? { table: { head: ['Where', 'Severity', 'Finding'], rows: (st.diagnostics || []).filter(d => d.severity !== 'info').slice(0, 60).map(d => [`${d.rel}:${d.l + 1}`, d.severity, `[${d.code}] ${d.msg}`]) } } : null,
    ]);
  }
  // 4. Property checks.
  if (f.checks) {
    const c = f.checks;
    const failed = c.items.filter(x => !x.ok).length;
    verdicts.push(failed ? `${plural(failed, 'property check')} failing` : null);
    S('Property checks', [
      { p: c.items.length ? `${plural(c.items.length, 'check')} in ${c.path}: ${failed ? `${failed} failing` : 'all hold'}${c.note ? ` (${c.note})` : ''}.` : `No checks (${c.path} ${c.exists ? 'is empty' : 'does not exist'}).` },
      c.items.length ? { table: { head: ['Result', 'Check', 'Finding'], rows: c.items.map(x => [x.ok ? '✓ holds' : '✗ fails', `\`${x.text}\``, x.error || x.message || '']) } } : null,
    ]);
  }
  // 5. Logins.
  if (f.logins) {
    const l = f.logins;
    const errs = (l.problems || []).filter(x => x.severity === 'error').length;
    verdicts.push(errs ? `${plural(errs, 'login')} that can't log in or whose session doesn't start` : null);
    S('Logins: contexts and session starts', [
      { p: `${plural((l.mappings || []).length, 'seusers line')}, ${plural((l.sessions || 0), 'session start')} checked: ${sevCounts(l.problems)}.` },
      { table: { head: ['Login', 'SELinux user', 'Ways in → session context'], rows: (l.mappings || []).map(m => [m.login, m.user, (m.ways || []).map(w => `${w.label}: ${w.works ? w.ctx : '✗ ' + (w.ctx || 'no context')}`).join('; ')]) } },
      (l.problems || []).length ? { table: { head: ['Severity', 'Login', 'Way', 'Problem'], rows: (l.problems || []).filter(x => x.severity !== 'info').slice(0, 60).map(x => [x.severity, x.login || '', x.way || '', x.text]) } } : null,
    ]);
  }
  // 6. Context files.
  if (f.contexts) {
    const c = f.contexts;
    const errs = (c.problems || []).filter(x => x.severity === 'error').length;
    verdicts.push(errs ? `${plural(errs, 'context')} that won't load` : null);
    S('Context files', [
      { p: `${plural((c.files || []).length, 'context file')} checked (file_contexts, home directories, the application context files): ${sevCounts(c.problems)}.` },
      (c.problems || []).filter(x => x.severity !== 'info').length ? { table: { head: ['Severity', 'Kind', 'Problem'], rows: (c.problems || []).filter(x => x.severity !== 'info').slice(0, 60).map(x => [x.severity, x.kind, x.text]) } } : null,
    ]);
  }
  // 7. Users.
  if (f.users) {
    S('SELinux users and what their sessions reach', [
      { table: { head: ['User', 'Roles', 'Range', 'Logins', 'Domains reached', 'Risky abilities'], rows: f.users.map(u => [u.name, (u.roles || []).join(' '), u.range || '', (u.logins || []).join(', ') || '—', String(u.reached || 0), (u.abilities || []).join('; ') || '—']) } },
    ]);
  }
  // 8. Services.
  if (f.services) {
    S('Services', [
      { p: `${plural(f.services.length, 'service module')} (domains started by init, D-Bus, inetd, cron or a template).` },
      { table: { head: ['Module', 'Layer', 'Domains'], rows: f.services.map(s => [s.module, s.layer || '', (s.domains || []).join(', ')]) } },
    ]);
  }
  // 9. Levels.
  if (f.levels) {
    const lv = f.levels;
    S('Levels and categories', [
      { p: lv.kind ? `${lv.kind.toUpperCase()}: ${plural(lv.constraints || 0, 'level constraint')}; ${plural(lv.held || 0, 'domain')} held to them, ${plural(lv.bypass || 0, 'domain')} pass them whatever the levels.` : 'No levels (the policy has no MLS/MCS).' },
      lv.groups && lv.groups.length ? { table: { head: ['Domains that ignore levels', 'How many', 'Why'], rows: lv.groups.slice(0, 20).map(g => [(g.domains || []).slice(0, 8).join(', ') + ((g.domains || []).length > 8 ? ', …' : ''), String((g.domains || []).length), (g.via || []).join('; ')]) } } : null,
    ]);
  }
  // 10. Unconfined programs on this host.
  if (f.unconfined) {
    const u = f.unconfined;
    verdicts.push(u.summary.unconfined ? `${plural(u.summary.unconfined, 'program')} on ${p.hostname || 'this host'} run unconfined under it` : null);
    S(`Programs on ${p.hostname || 'this host'}`, [
      { p: `${plural(u.summary.rows, 'program')} from this host's services and processes: ${u.summary.unconfined} run (or would run) unconfined, ${u.summary.confined} confined${u.summary.nostart ? `, ${u.summary.nostart} the policy can't start` : ''}.` },
      u.rows.length ? { table: { head: ['Program', 'Label', 'Runs as', 'Under this policy', 'Verdict'], rows: u.rows.filter(r => r.verdict !== 'unknown').slice(0, 80).map(r => [r.real, r.type || '—', (r.hostDomains || []).join(', ') || '—', r.policyDomain || r.how || '—', r.verdict]) } } : null,
    ]);
  }
  const v = verdicts.filter(Boolean);
  sections.unshift({ title: 'Summary', items: [{ p: v.length ? `Open findings: ${v.join('; ')}.` : 'No open findings: the static analysis, the build, the property checks, the logins and the context files are clean.' },
    ...(f.notes || []).map(n => ({ note: n }))] });
  return { title: `SELinux policy evidence: ${p.label || 'policy'}`, subtitle: p.tree ? `Source: ${p.tree}` : null, generated: `Generated ${f.generated || new Date().toISOString()} by selinux-policy-tools${p.extensionVersion ? ` ${p.extensionVersion}` : ''}`, sections };
}

module.exports = { buildDoc, render, renderMarkdown, renderHtml };
