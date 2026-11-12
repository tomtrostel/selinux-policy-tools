'use strict';
/**
 * Connections to target hosts (see target.js for the pure parts). One ssh
 * ControlMaster per target: the password (or key) is used once to open it,
 * every later command and copy rides on that connection. Nothing is written
 * to disk but the password file for the seconds the master takes to open,
 * mode 0600 in the server's private scratch area, removed right after.
 * The target's /etc/selinux/NAME essentials are mirrored into that area so
 * the policy can be analyzed here like an installed one.
 */
const cp = require('child_process');
const fs = require('fs');
const path = require('path');
const target = require('./target');

const hasSetsid = () => { try { cp.execFileSync('which', ['setsid'], { stdio: 'ignore' }); return true; } catch { return false; } };

/** ssh's own error line, without the chatter. */
const sshError = (stderr, code) => {
  const lines = String(stderr || '').split('\n').map(l => l.trim()).filter(l => l && !/^Warning: Permanently added/.test(l));
  const m = lines.find(l => /denied|refused|timed out|not resolve|No route|unreachable|Host key|REMOTE HOST IDENTIFICATION|Connection closed|Too many/i.test(l)) || lines[0];
  return m ? m.replace(/^ssh: /, '') : `ssh exited with ${code}`;
};

class TargetHosts {
  /** dirFor(id) → a private directory per target (the ControlMaster socket, the mirror); log(text). */
  constructor({ dirFor, log = () => {}, knownHosts = null }) {
    this.dirFor = dirFor;
    this.log = log;
    this.knownHosts = knownHosts;
    this.targets = new Map();
    this.onChange = () => {};
    // The master closes itself after ControlPersist seconds idle (so a crashed server leaves none behind): a ping keeps a connected one open.
    this.keepalive = setInterval(() => { for (const e of this.targets.values()) if (e.state === 'connected') this.run(e.id, 'true', { timeout: 20000 }); }, 240000);
    if (this.keepalive.unref) this.keepalive.unref();
  }

  get(id) { return this.targets.get(id) || null; }
  list() { return [...this.targets.values()].map(e => this.summary(e)); }
  summary(e) {
    const p = e.lastPush;
    return { id: e.id, host: e.t.host, user: e.t.user, port: e.t.port, state: e.state, error: e.error || null, facts: e.facts || null, notes: e.notes || [], mirror: e.mirror ? { root: e.mirror.root, policy: e.mirror.policy, name: e.mirror.name } : null, at: e.at, label: target.describe(e.t, e.facts),
      lastPush: p ? { at: p.at, atLocal: p.atLocal, ok: p.ok, modules: p.modules.map(m => m.name), rolledBack: !!p.rolledBack, dir: p.dir } : null };
  }

  /**
   * Open the connection ({ spec: 'user@host[:port]' | {user, host, port}, password?, keyOnly? }),
   * gather the facts and mirror the policy. Resolves to the summary, or { error }.
   */
  async connect({ spec, password = null, keyOnly = false }) {
    if (process.platform === 'win32') return { error: 'Target hosts need a Linux host running the extension (use Remote-SSH): the connection is made from there.' };
    // A password logs in as root unless a user is given; a key as ssh's own choice (its config's User, else the local user).
    const user = keyOnly || password == null ? null : 'root';
    const t = typeof spec === 'string' ? target.parseSpec(spec, { user }) : spec && spec.host ? { user: spec.user || user, host: spec.host, port: spec.port || 22 } : null;
    if (!t) return { error: `Not a host: "${spec}". Use host, user@host or user@host:port.` };
    const id = target.targetId(t);
    const old = this.targets.get(id);
    if (old && old.state === 'connected') { await this.disconnect(id); }
    const dir = this.dirFor(id);
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    try { fs.chmodSync(dir, 0o700); } catch { /* keep going */ }
    const e = { id, t, dir, control: path.join(dir, 'cm'), state: 'connecting', error: null, facts: null, notes: [], mirror: null, at: Date.now() };
    this.targets.set(id, e);
    this.onChange();
    const r = await this.openMaster(e, password, keyOnly);
    if (r.error) { e.state = 'error'; e.error = r.error; this.onChange(); return { error: r.error, id }; }
    e.state = 'connected';
    const f = await this.refresh(id);
    if (f.error) { e.state = 'error'; e.error = f.error; this.onChange(); return { error: f.error, id }; }
    this.onChange();
    return this.summary(e);
  }

  /** The ControlMaster: `ssh … true`, the askpass helper answering the one password prompt. */
  openMaster(e, password, keyOnly) {
    return new Promise((resolve) => {
      const env = { ...process.env };
      let pwFile = null;
      if (password != null && !keyOnly) {
        pwFile = path.join(e.dir, 'pw');
        const helper = path.join(e.dir, 'askpass.sh');
        fs.writeFileSync(pwFile, `${password}\n`, { mode: 0o600 });
        fs.writeFileSync(helper, target.ASKPASS_SCRIPT, { mode: 0o700 });
        env.SSH_ASKPASS = helper;
        env.SSH_ASKPASS_REQUIRE = 'force';
        env.SELINUX_TARGET_PW_FILE = pwFile;
        if (!env.DISPLAY) env.DISPLAY = ':0'; // OpenSSH < 8.4 uses the helper only with a DISPLAY
      }
      const args = [...target.sshArgs(e.t, { control: e.control, master: true, knownHosts: this.knownHosts, keyOnly: keyOnly || password == null }), 'true'];
      // No controlling terminal, so ssh asks the helper instead of /dev/tty.
      const useSetsid = hasSetsid();
      const proc = cp.spawn(useSetsid ? 'setsid' : 'ssh', useSetsid ? ['-w', 'ssh', ...args] : args, { env, stdio: ['ignore', 'pipe', 'pipe'] });
      let stderr = '';
      proc.stderr.on('data', d => { stderr += d; });
      proc.stdout.on('data', () => {});
      const timer = setTimeout(() => { try { proc.kill('SIGKILL'); } catch { /* gone */ } }, 45000);
      const done = (code) => {
        clearTimeout(timer);
        if (pwFile) { try { fs.unlinkSync(pwFile); } catch { /* already gone */ } }
        if (code === 0) resolve({ ok: true });
        else resolve({ error: `Could not connect to ${e.id}: ${sshError(stderr, code)}` });
      };
      proc.on('error', (err) => { stderr += err.code === 'ENOENT' ? `${useSetsid ? 'setsid' : 'ssh'} is not installed here (${err.message})` : err.message; done(-1); });
      proc.on('close', done);
    });
  }

  /** Run a command on the target over the open connection → { code, stdout, stderr }; `input` goes to its stdin. */
  run(id, cmd, { input = null, timeout = 60000, maxBuffer = 64 << 20 } = {}) {
    const e = this.targets.get(id);
    if (!e || e.state !== 'connected') return Promise.resolve({ code: -1, stdout: '', stderr: `Not connected to ${id}.`, lost: true });
    return new Promise((resolve) => {
      const proc = cp.spawn('ssh', [...target.sshArgs(e.t, { control: e.control, knownHosts: this.knownHosts }), cmd], { stdio: [input == null ? 'ignore' : 'pipe', 'pipe', 'pipe'] });
      let stdout = '', stderr = '';
      proc.stdout.on('data', d => { if (stdout.length < maxBuffer) stdout += d; });
      proc.stderr.on('data', d => { stderr += d; });
      const timer = setTimeout(() => { try { proc.kill('SIGKILL'); } catch { /* gone */ } stderr += '\n(timed out)'; }, timeout);
      proc.on('error', (err) => { clearTimeout(timer); resolve({ code: -1, stdout, stderr: err.message }); });
      proc.on('close', (code) => {
        clearTimeout(timer);
        const lost = code === 255 && /Control socket|Connection (closed|refused|reset)|Broken pipe|No such file/i.test(stderr);
        if (lost) { e.state = 'lost'; e.error = `Connection to ${id} lost: ${sshError(stderr, code)}`; this.onChange(); }
        resolve({ code, stdout, stderr, lost });
      });
      if (input != null) { proc.stdin.on('error', () => {}); proc.stdin.end(input); }
    });
  }

  /** Re-read the target's facts and mirror its policy files. */
  async refresh(id) {
    const e = this.targets.get(id);
    if (!e) return { error: `No target ${id}.` };
    const r = await this.run(id, 'sh -s', { input: target.FACTS_SCRIPT, timeout: 90000 });
    if (r.lost || (r.code !== 0 && !r.stdout.trim())) return { error: r.stderr.trim() || `The facts script failed on ${id} (exit ${r.code}).` };
    const facts = target.parseFacts(r.stdout);
    e.facts = facts;
    e.notes = facts.notes.slice();
    e.at = Date.now();
    if (facts.policy) {
      const m = await this.mirror(e, facts.policy);
      if (m.error) e.notes.push(m.error); else e.mirror = m;
    }
    return this.summary(e);
  }

  /** The target's /etc/selinux essentials into <dir>/mirror/etc/selinux via tar over the connection. */
  mirror(e, policy) {
    return new Promise((resolve) => {
      const root = path.join(e.dir, 'mirror', 'etc', 'selinux');
      fs.rmSync(path.join(e.dir, 'mirror'), { recursive: true, force: true });
      fs.mkdirSync(root, { recursive: true, mode: 0o700 });
      const ssh = cp.spawn('ssh', [...target.sshArgs(e.t, { control: e.control, knownHosts: this.knownHosts }), target.mirrorCommand(policy.name, policy.file)], { stdio: ['ignore', 'pipe', 'pipe'] });
      const tar = cp.spawn('tar', ['xzf', '-', '-C', root], { stdio: ['pipe', 'ignore', 'pipe'] });
      ssh.stdout.pipe(tar.stdin);
      let err = '';
      ssh.stderr.on('data', d => { err += d; });
      tar.stderr.on('data', d => { err += d; });
      let left = 2;
      const finish = () => {
        if (--left) return;
        const local = path.join(root, policy.name, 'policy', path.posix.basename(policy.file));
        if (!fs.existsSync(local)) return resolve({ error: `The policy file ${policy.file} could not be copied from ${e.id}${err.trim() ? ` (${err.trim().split('\n')[0]})` : ''}.` });
        resolve({ root, name: policy.name, policy: local, dir: path.join(root, policy.name), at: Date.now() });
      };
      ssh.on('error', (x) => { err += x.message; finish(); });
      tar.on('error', (x) => { err += x.message; finish(); });
      ssh.on('close', finish);
      tar.on('close', finish);
    });
  }

  /**
   * Copy files to the target: `files` = [{ from (local path), as (path relative to remoteDir) }],
   * streamed as one tar over the connection into remoteDir (created). → { ok } | { error }.
   */
  copyTo(id, files, remoteDir) {
    const e = this.targets.get(id);
    if (!e || e.state !== 'connected') return Promise.resolve({ error: `Not connected to ${id}.` });
    return new Promise((resolve) => {
      const staging = fs.mkdtempSync(path.join(e.dir, 'push-'));
      try {
        for (const f of files) { const to = path.join(staging, f.as); fs.mkdirSync(path.dirname(to), { recursive: true }); fs.copyFileSync(f.from, to); }
      } catch (err) { fs.rmSync(staging, { recursive: true, force: true }); return resolve({ error: `Could not stage ${files.length} files: ${err.message}` }); }
      const tar = cp.spawn('tar', ['czf', '-', '-C', staging, '.'], { stdio: ['ignore', 'pipe', 'pipe'] });
      const ssh = cp.spawn('ssh', [...target.sshArgs(e.t, { control: e.control, knownHosts: this.knownHosts }), `mkdir -p ${target.shq(remoteDir)} && tar xzf - -C ${target.shq(remoteDir)}`], { stdio: ['pipe', 'pipe', 'pipe'] });
      tar.stdout.pipe(ssh.stdin);
      let err = '';
      tar.stderr.on('data', d => { err += d; });
      ssh.stderr.on('data', d => { err += d; });
      ssh.stdout.on('data', () => {});
      let code = null;
      const finish = () => { fs.rmSync(staging, { recursive: true, force: true }); resolve(code === 0 ? { ok: true } : { error: `Copying to ${id} failed: ${err.trim().split('\n')[0] || `exit ${code}`}` }); };
      ssh.on('error', (x) => { err += x.message; code = -1; finish(); });
      tar.on('error', (x) => { err += x.message; });
      ssh.on('close', (c) => { code = c; finish(); });
    });
  }

  /** The target's boolean values as read at the last refresh ({} when not readable). */
  booleans(id) { const e = this.targets.get(id); return (e && e.facts && e.facts.booleans) || {}; }

  /** Close the connection (ssh -O exit) and forget the target. */
  async disconnect(id) {
    const e = this.targets.get(id);
    if (!e) return { ok: false };
    this.closeMaster(e);
    this.targets.delete(id);
    fs.rmSync(e.dir, { recursive: true, force: true });
    this.onChange();
    return { ok: true };
  }

  closeMaster(e) {
    try { cp.spawnSync('ssh', ['-o', `ControlPath=${e.control}`, '-O', 'exit', target.sshDest(e.t)], { stdio: 'ignore', timeout: 5000 }); } catch { /* nothing to close */ }
  }

  /** On exit: every master closed (synchronously). */
  closeAll() { for (const e of this.targets.values()) this.closeMaster(e); this.targets.clear(); }
}

module.exports = { TargetHosts, sshError };
