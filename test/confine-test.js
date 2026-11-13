'use strict';
// The confinement checklist (server/confine.js), any OS: the steps computed
// from facts at every stage of the loop, and the verdict of a verify run.
//   node test/confine-test.js
const C = require('../server/confine');

let failures = 0;
const check = (cond, what, extra) => {
  console.log(`${cond ? 'ok  ' : 'FAIL'} ${what}`);
  if (!cond) { failures++; if (extra !== undefined) console.log('     ' + JSON.stringify(extra, null, 1).slice(0, 2500).replace(/\n/g, '\n     ')); }
};
const by = (steps) => Object.fromEntries(steps.map(s => [s.id, s]));
const states = (steps) => steps.map(s => `${s.id}:${s.state}`).join(' ');

const mod = { name: 'mydaemon', domain: 'mydaemon_t', files: { te: '/t/mydaemon.te', if: '/t/mydaemon.if', fc: '/t/mydaemon.fc' }, layer: 'contrib', standalone: false };
const target = { id: 'root@box', mode: 'Enforcing', root: true, permissive: [] };
const unit = { id: 'mydaemon.service', active: 'active' };

// 1. Nothing yet.
let st = C.steps({ module: null });
check(st.length === 9 && st.every(s => s.title && s.text && s.state) && states(st) === 'module:todo build:skip target:todo push:skip permissive:skip running:skip exercise:skip denials:skip verify:skip', 'no module: write it first, connect a target; the rest waits', states(st));
check(/New Service/.test(by(st).module.text), 'the first step points to the service editor');

// 2. Module written, not built, no target.
st = C.steps({ module: mod, build: null, target: null });
check(states(st) === 'module:done build:todo target:todo push:skip permissive:skip running:skip exercise:skip denials:skip verify:skip' && /mydaemon \(contrib, domain mydaemon_t\)/.test(by(st).module.text), 'module written: build and connect are the next steps', states(st));

// 3. Built, stale, failed.
st = C.steps({ module: mod, build: { kind: 'tree', ok: true, at: Date.now(), stale: [], packaged: true }, target: null });
check(by(st).build.state === 'done' && /Tree build ok/.test(by(st).build.text), 'a good tree build');
st = C.steps({ module: mod, build: { kind: 'tree', ok: true, at: Date.now(), stale: ['mydaemon.te'], packaged: true }, target });
check(by(st).build.state === 'todo' && /changed since the last build \(mydaemon\.te\)/.test(by(st).build.text), 'sources changed since the build: build again');
st = C.steps({ module: mod, build: { kind: 'module', ok: false, at: Date.now(), stale: [], error: 'unknown type foo_t', packaged: false }, target });
check(by(st).build.state === 'bad' && /failed: unknown type foo_t/.test(by(st).build.text) && by(st).push.state === 'skip', 'a failed build: bad, with the first error; no push');
st = C.steps({ module: { ...mod, standalone: true }, build: { kind: 'module', ok: true, at: Date.now(), stale: [], packaged: false }, target: null });
check(by(st).build.state === 'done' && /Module build ok.*packaged when pushed/.test(by(st).build.text) && /standalone/.test(by(st).module.text), 'a standalone module built but not packaged yet');

// 4. Target connected, not root.
const built = { kind: 'tree', ok: true, at: Date.now(), stale: [], packaged: true };
st = C.steps({ module: mod, build: built, target: { ...target, root: false } });
check(by(st).target.state === 'bad' && /not as root/.test(by(st).target.text) && by(st).push.state === 'skip', 'a target without root: said, no push');

// 5. Push states.
const base = { module: mod, build: built, target, services: [], denials: { count: 0, since: 'today', error: null, text: '' } };
st = C.steps({ ...base, push: { state: 'new', error: null, lastPush: null } });
check(by(st).push.state === 'todo' && /not installed on root@box: push it/.test(by(st).push.text) && by(st).target.state === 'done' && /root@box \(enforcing\), as root/.test(by(st).target.text), 'module new on the target: push', by(st).push);
st = C.steps({ ...base, push: { state: 'differs', error: null, lastPush: null } });
check(by(st).push.state === 'todo' && /differs from the module installed/.test(by(st).push.text), 'module differs: push');
st = C.steps({ ...base, push: { state: 'same', error: null, lastPush: { at: 1700000000, ok: true, modules: [{ name: 'mydaemon' }] } } });
check(by(st).push.state === 'done' && /runs this build of mydaemon \(pushed/.test(by(st).push.text), 'module the same: done, with the push time');
st = C.steps({ ...base, push: { state: null, error: 'The build is policy version 33 but root@box runs version 31', lastPush: null } });
check(by(st).push.state === 'bad' && /policy version 33/.test(by(st).push.text), 'a plan error (version) is the push step\'s text');
st = C.steps({ ...base, push: { state: null, error: null, lastPush: null } });
check(by(st).push.state === 'unknown' && /part of base/.test(by(st).push.text), 'module not among the packages: unknown');

// 6. Permissive, running, denials, verify through the loop.
const pushed = { ...base, push: { state: 'same', error: null, lastPush: null } };
st = C.steps(pushed);
check(by(st).permissive.state === 'todo' && /mydaemon_t is enforced on root@box. Make it permissive/.test(by(st).permissive.text) && by(st).running.state === 'unknown' && /No program of mydaemon was found/.test(by(st).running.text) && by(st).exercise.state === 'todo' && by(st).denials.state === 'done' && /Nothing denied to mydaemon_t since today/.test(by(st).denials.text) && by(st).verify.state === 'todo' && /Start the service in its domain/.test(by(st).verify.text),
  'pushed, enforcing, nothing running: make permissive, start it; verify lists what is left', states(st));
const permT = { ...target, permissive: ['mydaemon_t'] };
st = C.steps({ ...pushed, target: permT, services: [{ real: '/usr/sbin/mydaemon', units: [unit], pids: [], hostDomains: [], listens: [], permissive: true }] });
check(by(st).permissive.state === 'done' && /is permissive on root@box/.test(by(st).permissive.text) && by(st).running.state === 'todo' && /mydaemon\.service \(active\): not running/.test(by(st).running.text), 'permissive; a unit but no process: restart', states(st));
st = C.steps({ ...pushed, target: permT, services: [{ real: '/usr/sbin/mydaemon', units: [unit], pids: [42], hostDomains: ['init_t'], listens: [], permissive: true }] });
check(by(st).running.state === 'todo' && /Running as init_t, not mydaemon_t: restart/.test(by(st).running.text), 'running in another domain: restart');
st = C.steps({ ...pushed, target: permT, services: [{ real: '/usr/sbin/mydaemon', units: [unit], pids: [42, 43], hostDomains: ['mydaemon_t'], listens: [{ proto: 'tcp', port: 8080 }], permissive: true }] });
check(by(st).running.state === 'done' && /2 processes in mydaemon_t \(mydaemon\.service\); listening on tcp 8080/.test(by(st).running.text), 'running in its domain with its port', by(st).running);
st = C.steps({ ...pushed, target: permT, services: [{ real: '/usr/sbin/mydaemon', units: [unit], pids: [42], hostDomains: ['mydaemon_t'], listens: [], permissive: true }], exercise: { ran: [{ cmd: 'curl x', code: 0 }, { cmd: 'false', code: 1 }], at: Date.now() } });
check(by(st).exercise.state === 'bad' && /1 command failed on root@box: false \(exit 1\)/.test(by(st).exercise.text), 'a failed exercise command');
st = C.steps({ ...pushed, target: permT, services: [{ real: '/usr/sbin/mydaemon', units: [unit], pids: [42], hostDomains: ['mydaemon_t'], listens: [], permissive: true }], exercise: { ran: [{ cmd: 'curl x', code: 0 }], at: Date.now() }, denials: { count: 7, since: 'the last push', error: null, text: 'type=AVC …' } });
check(by(st).exercise.state === 'done' && by(st).denials.state === 'todo' && /7 denials of mydaemon_t since the last push: apply them to the form/.test(by(st).denials.text) && by(st).verify.state === 'todo' && /Enforce mydaemon_t, get the denials to zero/.test(by(st).verify.text), 'denials logged: into the form; verify waits', { d: by(st).denials, v: by(st).verify });
st = C.steps({ ...pushed, denials: { count: 0, since: 'today', error: 'auditd on the target suspended logging (low disk space)', text: '' } });
check(by(st).denials.state === 'bad' && /suspended logging/.test(by(st).denials.text), 'an audit log that cannot be read: bad, with the reason');
st = C.steps({ ...pushed, services: [{ real: '/usr/sbin/mydaemon', units: [unit], pids: [42], hostDomains: ['mydaemon_t'], listens: [], permissive: false }], exercise: { ran: [{ cmd: 'curl x', code: 0 }] } });
check(by(st).verify.state === 'done' && /mydaemon_t is enforced on root@box, the service runs in it and nothing was denied since today/.test(by(st).verify.text) && st.filter(s => s.state === 'done').length === 8 && by(st).permissive.state === 'todo',
  'enforced, running in its domain, nothing denied, pushed: verified (permissive is the only open step, as it should be)', states(st));
st = C.steps({ ...pushed, target: { ...target, mode: 'Permissive' }, services: [{ real: '/usr/sbin/mydaemon', units: [unit], pids: [42], hostDomains: ['mydaemon_t'], listens: [], permissive: false }] });
check(by(st).permissive.state === 'done' && /permissive as a whole/.test(by(st).permissive.text) && by(st).verify.state === 'todo' && /Enforce mydaemon_t/.test(by(st).verify.text), 'a permissive host: the domain counts as permissive; not verified');

// 7. The verdict of a verify run.
let v = C.verdict({ domain: 'mydaemon_t', target: 'root@box', units: ['mydaemon.service'], enforce: { ok: true }, restart: { ok: true, units: [{ unit: 'mydaemon.service', state: 'active' }] }, exercise: [{ cmd: 'curl x', code: 0, out: '' }], denials: { count: 0, text: '', error: null }, running: { pids: [42], domains: ['mydaemon_t'] } });
check(v.ok && !v.problems.length && /mydaemon_t enforced on root@box: mydaemon\.service restarted and active, 1 command ran, nothing denied/.test(v.text), 'a clean run', v);
v = C.verdict({ domain: 'mydaemon_t', target: 'root@box', units: ['mydaemon.service'], enforce: { ok: true }, restart: { ok: false, units: [{ unit: 'mydaemon.service', state: 'failed' }] }, exercise: [{ cmd: 'curl x', code: 7, out: 'curl: (7) Failed to connect' }], denials: { count: 3, text: 'type=AVC …', error: null }, running: { pids: [], domains: [] } });
check(!v.ok && v.problems.length === 4 && /mydaemon\.service is failed/.test(v.problems[0]) && /curl x: exit 7 \(curl: \(7\) Failed to connect\)/.test(v.problems[1]) && /3 denials of mydaemon_t while enforcing/.test(v.problems[2]) && /No process of the service is running/.test(v.problems[3]) && /4 problems/.test(v.text),
  'a failing run: the unit, the command, the denials, no process', v.problems);
v = C.verdict({ domain: 'mydaemon_t', target: 'root@box', units: [], enforce: { ok: false, error: 'semanage permissive failed on root@box: …' }, restart: { ok: true, units: [] }, exercise: [], denials: { count: 0, text: '', error: null }, running: { pids: [1], domains: ['init_t'] } });
check(!v.ok && /Could not enforce the domain/.test(v.problems[0]) && /runs as init_t, not mydaemon_t/.test(v.problems[1]), 'enforce failed and the wrong domain');
v = C.verdict({ error: 'Not connected to root@box.' });
check(!v.ok && v.text === 'Not connected to root@box.', 'an error is the verdict');
check(Object.keys(C.STEP_TITLES).length === 9, 'nine steps');

console.log(failures ? `\n${failures} confine checks FAILED` : '\nall confine checks passed');
process.exit(failures ? 1 : 0);
