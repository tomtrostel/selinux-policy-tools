'use strict';
/*
 * The confinement checklist for one service module: the loop from a written
 * module to a service running enforced on a target host with nothing denied,
 * as steps with a state each, computed from facts the server gathers
 * (server.js `selinux/confineStatus`).
 *
 *   steps(facts) → [{ id, title, state, text, detail? }]
 *     state: done | todo | bad | unknown | skip
 *   verdict(result) → { ok, text, problems } for a verify run
 *     (selinux/confineVerify): enforced, restarted, exercised, nothing denied.
 *
 * facts: {
 *   module: { name, domain, files: { te, if, fc }, layer, standalone } | null,
 *   build: { kind: 'tree' | 'module', ok, at (ms), stale: [changed sources], error, packaged } | null,
 *   target: { id, mode, root, permissive: [domains] } | null,
 *   push: { state: 'same' | 'differs' | 'new' | null, error, lastPush: { at, ok, modules, rolledBack } | null } | null,
 *   services: [{ real, units: [{ id, active }], pids, hostDomains, listens, permissive }] (the module's programs on the target),
 *   denials: { count, since, error, note, text } | null,
 *   exercise: { ran: [{ cmd, code }] } | null (the webview's last run),
 *   verified: an enforce-and-verify run happened for this module on this target (this session),
 * }
 */

const STEP_TITLES = {
  module: 'Policy written',
  build: 'Built',
  target: 'Target host connected',
  push: 'Pushed to the target',
  permissive: 'Permissive for the test run',
  running: 'Running in its domain',
  exercise: 'Exercised',
  denials: 'Denials read into the form',
  verify: 'Enforced and verified',
};

const plural = (n, w) => `${n} ${n === 1 ? w : w.endsWith('s') ? `${w}es` : `${w}s`}`;

function steps(facts) {
  const out = [];
  const add = (id, state, text, detail) => out.push({ id, title: STEP_TITLES[id], state, text, detail: detail || null });
  const m = facts.module;
  const D = m ? m.domain : null;
  // 1. The module.
  if (!m) { add('module', 'todo', 'No module yet: create the service in the service editor (New Service…), then come back here.'); }
  else add('module', 'done', `${m.name} (${m.layer ? `${m.layer}, ` : ''}${m.standalone ? 'standalone, ' : ''}domain ${D}).`);
  // 2. The build.
  const b = facts.build;
  if (!m) add('build', 'skip', 'Nothing to build yet.');
  else if (!b) add('build', 'todo', 'Not built yet: build the tree (or the module) so there is a package to push.');
  else if (!b.ok) add('build', 'bad', `The last build failed${b.error ? `: ${b.error}` : ''}. Fix the errors in the Problems panel and build again.`);
  else if (b.stale && b.stale.length) add('build', 'todo', `Sources changed since the last build (${b.stale.slice(0, 3).join(', ')}${b.stale.length > 3 ? ', …' : ''}): build again before pushing.`);
  else add('build', 'done', `${b.kind === 'tree' ? 'Tree build' : 'Module build'} ok${b.at ? ` (${new Date(b.at).toLocaleTimeString()})` : ''}${b.kind === 'module' && !b.packaged ? '; it is packaged when pushed' : ''}.`);
  // 3. The target.
  const t = facts.target;
  if (!t) add('target', 'todo', 'Connect a target host to push to and test on (SELinux: Connect to Target Host…). A test machine, not the production host.');
  else if (!t.root) add('target', 'bad', `${t.id} is connected but not as root: pushing a policy, restarting services and reading the audit log need root there.`);
  else add('target', 'done', `${t.id}${t.mode ? ` (${t.mode.toLowerCase()})` : ''}, as root.`);
  // 4. The push.
  const p = facts.push;
  if (!m || !t || !t.root) add('push', 'skip', 'Needs the module built and a target.');
  else if (!b || !b.ok) add('push', 'skip', 'Needs a good build first.');
  else if (!p || p.error) add('push', 'bad', p && p.error ? p.error : 'Could not compare the build with the target.');
  else if (p.state === 'same') add('push', 'done', `The target runs this build of ${m.name}${p.lastPush && p.lastPush.ok ? ` (pushed ${new Date(p.lastPush.at * 1000).toLocaleTimeString()})` : ''}.`);
  else if (p.state === 'new') add('push', 'todo', `${m.name} is not installed on ${t.id}: push it.`);
  else if (p.state === 'differs') add('push', 'todo', `The build's ${m.name} differs from the module installed on ${t.id}: push it${b.stale && b.stale.length ? ' (after building)' : ''}.`);
  else add('push', 'unknown', `${m.name} is not among the build's packages (part of base?).`);
  // 5. Permissive.
  const perm = t && D ? (t.permissive || []).includes(D) : false;
  if (!m || !t) add('permissive', 'skip', 'Needs a target.');
  else if (t.mode === 'Permissive') add('permissive', 'done', `${t.id} is permissive as a whole: every denial is logged, nothing is stopped.`);
  else if (perm) add('permissive', 'done', `${D} is permissive on ${t.id}: its denials are logged, nothing is stopped. Enforce it again at the end (the last step does).`);
  else add('permissive', 'todo', `${D} is enforced on ${t.id}. Make it permissive for the test run, so one missing rule does not hide the next.`);
  // 6. Running in its domain.
  const svc = facts.services || [];
  const units = svc.flatMap(r => r.units || []);
  const pids = svc.flatMap(r => r.pids || []);
  const doms = [...new Set(svc.flatMap(r => r.hostDomains || []))];
  if (!m || !t) add('running', 'skip', 'Needs a target.');
  else if (!svc.length) add('running', 'unknown', `No program of ${m.name} was found on ${t.id} (no unit starts it and nothing of it is running). Install the program there, or check the module's program paths.`);
  else if (!pids.length) add('running', units.length ? 'todo' : 'unknown', units.length ? `${units.map(u => `${u.id} (${u.active || 'not running'})`).join(', ')}: not running. Start or restart it.` : `${svc.map(r => r.real).join(', ')}: not running, and no unit starts it.`);
  else if (D && doms.length && !doms.includes(D)) add('running', 'todo', `Running as ${doms.join(', ')}, not ${D}: restart the service so it starts under the pushed policy${p && p.state !== 'same' ? ' (push first)' : ''}.`);
  else if (D && doms.includes(D)) add('running', 'done', `${plural(pids.length, 'process')} in ${D}${units.length ? ` (${units.map(u => u.id).join(', ')})` : ''}${svc.some(r => r.listens && r.listens.length) ? `; listening on ${[...new Set(svc.flatMap(r => (r.listens || []).map(l => `${l.proto} ${l.port}`)))].join(', ')}` : ''}.`);
  else add('running', 'unknown', `${plural(pids.length, 'process')} running; the domain could not be read.`);
  // 7. Exercise.
  const ex = facts.exercise;
  if (!m || !t) add('exercise', 'skip', 'Needs a target.');
  else if (!ex || !ex.ran || !ex.ran.length) add('exercise', 'todo', 'Run the service through its paces on the target: the commands below (a client request, a reload, whatever it does in production), so every code path meets the policy.');
  else {
    const failed = ex.ran.filter(x => x.code !== 0);
    add('exercise', failed.length ? 'bad' : 'done', failed.length ? `${plural(failed.length, 'command')} failed on ${t.id}: ${failed.map(x => `${x.cmd} (exit ${x.code})`).join('; ')}.` : `${plural(ex.ran.length, 'command')} ran on ${t.id}${ex.at ? ` (${new Date(ex.at).toLocaleTimeString()})` : ''}.`);
  }
  // 8. Denials.
  const d = facts.denials;
  if (!m || !t) add('denials', 'skip', 'Needs a target.');
  else if (!d) add('denials', 'unknown', 'Not read yet.');
  else if (d.error) add('denials', 'bad', d.error);
  else if (d.note) add('denials', 'bad', d.note);
  else if (d.count) add('denials', 'todo', `${plural(d.count, 'denial')} of ${D} since ${d.since}: apply them to the form, build, push, test again.`);
  else add('denials', 'done', `Nothing denied to ${D} since ${d.since}.`);
  // 9. Verified.
  const enforced = t && (t.mode === 'Enforcing') && !perm;
  const clean = d && !d.error && !d.note && d.count === 0;
  const runs = D && doms.includes(D);
  if (!m || !t) add('verify', 'skip', 'Needs a target.');
  else if (enforced && runs && clean && p && p.state === 'same' && !facts.verified) add('verify', 'todo', `Everything is in place (${D} enforced, running in its domain, nothing denied since ${d.since}), but no verify run happened yet in this session: Enforce and verify restarts the service, runs the exercise commands and reads what was denied while enforcing.`);
  else if (enforced && runs && clean && p && p.state === 'same') {
    add('verify', 'done', `${D} is enforced on ${t.id}, the service runs in it and nothing was denied since ${d.since}.`);
    // The test run is over and the domain is enforced again: that is what the permissive step was for.
    const ps = out.find(s => s.id === 'permissive');
    if (ps && ps.state === 'todo') { ps.state = 'done'; ps.text = `${D} is enforced again on ${t.id}: the test run is over. Make it permissive again to test more changes.`; }
  } else add('verify', 'todo', [p && p.state !== 'same' ? 'push the build' : null, !runs ? 'start the service in its domain' : null, !enforced ? `enforce ${D}` : null, !clean ? 'get the denials to zero' : null].filter(Boolean).join(', ').replace(/^./, c => c.toUpperCase()) + '. Enforce and verify does it in one go: enforce the domain, restart, exercise, read what was denied.');
  return out;
}

/** The verdict of a verify run: { ok, text, problems }. */
function verdict(r) {
  const problems = [];
  if (r.error) return { ok: false, text: r.error, problems: [r.error] };
  if (r.enforce && r.enforce.error) problems.push(`Could not enforce the domain: ${r.enforce.error}`);
  for (const u of (r.restart && r.restart.units) || []) if (u.state !== 'active') problems.push(`${u.unit} is ${u.state} after the restart.`);
  if (r.restart && r.restart.error) problems.push(r.restart.error);
  for (const x of (r.exercise || [])) if (x.code !== 0) problems.push(`${x.cmd}: exit ${x.code}${x.out ? ` (${x.out.trim().split('\n').slice(-1)[0].slice(0, 120)})` : ''}`);
  if (r.denials && r.denials.error) problems.push(r.denials.error);
  else if (r.denials && r.denials.count) problems.push(`${plural(r.denials.count, 'denial')} of ${r.domain} while enforcing: the service would fail here. Make it permissive again, apply them to the form, push, verify again.`);
  if (r.running && r.domain && r.running.domains.length && !r.running.domains.includes(r.domain)) problems.push(`The service runs as ${r.running.domains.join(', ')}, not ${r.domain}.`);
  if (r.running && r.units && r.units.length && !r.running.pids.length) problems.push('No process of the service is running after the restart.');
  const ok = !problems.length;
  return { ok, problems, text: ok ? `${r.domain} enforced on ${r.target}: ${r.units && r.units.length ? `${r.units.join(', ')} restarted and active, ` : ''}${r.exercise && r.exercise.length ? `${plural(r.exercise.length, 'command')} ran, ` : ''}nothing denied.` : `${plural(problems.length, 'problem')} while verifying ${r.domain} on ${r.target}.` };
}

module.exports = { steps, verdict, STEP_TITLES };
