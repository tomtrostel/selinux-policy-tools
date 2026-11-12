'use strict';
/**
 * Target hosts: a machine the editor's host reaches over ssh to read its SELinux
 * state (and later its denials, services and to push policy). This module is
 * pure: the ssh arguments, the askpass helper, the script that gathers the
 * target's facts in one round trip, and the parsers of what it prints. The
 * connections themselves live in targethost.js.
 */
const path = require('path');

/**
 * A host name or address as the user types it (optionally user@host[:port]).
 * Without a user: root (`defaults.user`), or null = ssh's own choice (its
 * config's User, else the local user) for key logins.
 */
function parseSpec(spec, defaults = {}) {
  // Neither part may start with '-': ssh would read it as an option.
  const m = /^\s*(?:(\w[\w.-]*)@)?(\[[0-9a-fA-F:.]+\]|\w[\w.-]*)(?::(\d{1,5}))?\s*$/.exec(spec || '');
  if (!m) return null;
  return { user: m[1] || (defaults.user === undefined ? 'root' : defaults.user), host: m[2].replace(/^\[|\]$/g, ''), port: m[3] ? +m[3] : defaults.port || 22 };
}

/** The identifier a target goes by in policy ids, directories and labels. */
const targetId = (t) => `${t.user ? `${t.user}@` : ''}${t.host}${t.port && t.port !== 22 ? `:${t.port}` : ''}`;
/** The destination argument for ssh. */
const sshDest = (t) => (t.user ? `${t.user}@${t.host}` : t.host);

/** Shell-quote one word for the target's sh. */
const shq = (s) => `'${String(s).replace(/'/g, `'\\''`)}'`;

/**
 * ssh arguments for a target: `control` = the ControlMaster socket path (every
 * command shares one authenticated connection), `master` = open it (password
 * prompts allowed, the askpass helper answers), `knownHosts` = our own file
 * (accept-new: a changed key is refused, never silently accepted).
 */
function sshArgs(t, { control, master = false, knownHosts = null, keyOnly = false, timeout = 20 } = {}) {
  const a = ['-o', `ControlPath=${control}`];
  if (master) a.push('-o', 'ControlMaster=yes', '-o', 'ControlPersist=600', '-o', `ConnectTimeout=${timeout}`, '-o', 'NumberOfPasswordPrompts=1');
  else a.push('-o', 'ControlMaster=no', '-o', 'BatchMode=yes');
  if (master && keyOnly) a.push('-o', 'BatchMode=yes');
  a.push('-o', 'StrictHostKeyChecking=accept-new', '-o', 'LogLevel=ERROR');
  if (knownHosts) a.push('-o', `UserKnownHostsFile=${knownHosts}`);
  if (t.port && t.port !== 22) a.push('-p', String(t.port));
  a.push(sshDest(t));
  return a;
}

/**
 * The askpass helper: ssh runs it instead of prompting on a terminal when it
 * has none (SSH_ASKPASS_REQUIRE=force on OpenSSH 8.4+; older ones need
 * DISPLAY set and no controlling tty, hence setsid). It prints the password
 * kept in a 0600 file for the one connection, which is removed afterwards.
 * A host-key question ("Are you sure…") must not get the password: it is
 * answered yes only for accept-new's first contact (ssh never asks with
 * accept-new, so the helper answers "no" to anything that isn't a password).
 */
const ASKPASS_SCRIPT = `#!/bin/sh
case "$1" in
  *assword*) cat "$SELINUX_TARGET_PW_FILE" ;;
  *) echo no ;;
esac
`;

/**
 * The script run on the target (sh -s) that prints every fact in one round
 * trip, each under a "### <key>" line; a command that fails prints its error
 * under "### <key>.err" so the parser can say what is missing (not root).
 */
const FACTS_SCRIPT = `
sec() { printf '### %s\\n' "$1"; }
run() { k=$1; shift; sec "$k"; out=$("$@" 2>&1); rc=$?; if [ $rc -eq 0 ]; then printf '%s\\n' "$out"; else sec "$k.err"; printf '%s\\n' "$out" | head -3; fi; }
sec hostname; hostname 2>/dev/null || uname -n
sec uid; id -u
sec now; date +%s
sec os-release; cat /etc/os-release 2>/dev/null
sec config; cat /etc/selinux/config 2>/dev/null
run getenforce getenforce
sec policy-rpm; rpm -q selinux-policy 2>/dev/null
sec policy-files; for d in /etc/selinux/*/policy; do ls -l "$d"/policy.[0-9]* 2>/dev/null; done
run modules semodule --list-modules=full
run permissive semanage permissive -l -n
run booleans getsebool -a
sec ssh-version; ssh -V 2>&1
sec done
`;

/** The output of FACTS_SCRIPT → { key: text }. */
function splitSections(text) {
  const out = {};
  let key = null;
  for (const line of String(text || '').split('\n')) {
    const m = /^### (\S+)$/.exec(line);
    if (m) { key = m[1]; if (!(key in out)) out[key] = ''; continue; }
    if (key != null) out[key] += line + '\n';
  }
  for (const k of Object.keys(out)) out[k] = out[k].replace(/\n$/, '');
  return out;
}

const parseOsRelease = (text) => {
  const o = {};
  for (const line of String(text || '').split('\n')) { const m = /^(\w+)=("?)(.*)\2$/.exec(line.trim()); if (m) o[m[1]] = m[3]; }
  return { id: o.ID || null, name: o.NAME || null, version: o.VERSION_ID || null, pretty: o.PRETTY_NAME || o.NAME || null };
};

const parseConfig = (text) => {
  const v = (k) => { const m = new RegExp(`^\\s*${k}\\s*=\\s*(\\S+)`, 'm').exec(text || ''); return m ? m[1] : null; };
  return { type: v('SELINUXTYPE'), mode: v('SELINUX') };
};

/** `semodule --list-modules=full` lines: PRIORITY NAME LANG [disabled]. */
function parseModules(text) {
  const out = [];
  for (const line of String(text || '').split('\n')) {
    const m = /^\s*(\d+)\s+(\S+)\s+(\S+)(?:\s+(disabled))?\s*$/.exec(line);
    if (m) out.push({ priority: +m[1], name: m[2], lang: m[3], disabled: !!m[4] });
  }
  return out;
}

/** `semanage permissive -l -n`: type names, one per line (headers skipped). */
const parsePermissive = (text) => String(text || '').split('\n').map(l => l.trim()).filter(l => /^\w+_t$/.test(l));

/** `getsebool -a`: name --> on|off. */
function parseBooleans(text) {
  const out = {};
  for (const line of String(text || '').split('\n')) { const m = /^(\S+)\s+-->\s+(on|off)\s*$/.exec(line); if (m) out[m[1]] = m[2] === 'on'; }
  return out;
}

/** `ls -l /etc/selinux/NAME/policy/policy.NN` lines → [{ name, file, size }] (newest policy version per store). */
function parsePolicyFiles(text) {
  const by = new Map();
  for (const line of String(text || '').split('\n')) {
    const m = /\s(\d+)\s+\S+\s+\d+\s+[\d:]+\s+(\/etc\/selinux\/([^/]+)\/policy\/policy\.(\d+))\s*$/.exec(line);
    if (!m) continue;
    const cur = by.get(m[3]);
    if (!cur || +m[4] > cur.version) by.set(m[3], { name: m[3], file: m[2], version: +m[4], size: +m[1] });
  }
  return [...by.values()];
}

/**
 * The facts of a target from FACTS_SCRIPT's output: { hostname, root, os,
 * mode (Enforcing|Permissive|Disabled|null), config {type, mode}, policyRpm,
 * policies [{name, file, version, size}], policy (the configured store's
 * entry, else the first), modules | null, permissive | null, booleans | null,
 * notes [what could not be read and why], at (the target's clock, seconds) }.
 */
function parseFacts(text) {
  const s = splitSections(text);
  const notes = [];
  const err = (k, what) => { if (s[`${k}.err`] != null) { const e = s[`${k}.err`].trim().split('\n')[0]; notes.push(`${what}: ${/ermission denied|not managed|cannot be accessed/i.test(e) ? 'not root on the target' : e || 'failed'}.`); return true; } return false; };
  const config = parseConfig(s.config);
  const policies = parsePolicyFiles(s['policy-files']);
  const policy = policies.find(p => p.name === config.type) || policies[0] || null;
  const uid = parseInt(s.uid, 10);
  const facts = {
    hostname: (s.hostname || '').trim() || null,
    root: uid === 0,
    uid: Number.isFinite(uid) ? uid : null,
    os: parseOsRelease(s['os-release']),
    mode: err('getenforce', 'SELinux mode') ? null : (s.getenforce || '').trim() || null,
    config,
    policyRpm: (s['policy-rpm'] || '').trim() || null,
    policies, policy,
    modules: err('modules', 'The module list (semodule)') ? null : parseModules(s.modules),
    permissive: err('permissive', 'Permissive domains (semanage)') ? null : parsePermissive(s.permissive),
    booleans: err('booleans', 'Boolean values (getsebool)') ? null : parseBooleans(s.booleans),
    sshVersion: (s['ssh-version'] || '').trim().split('\n')[0] || null,
    at: parseInt(s.now, 10) || null,
    complete: s.done != null,
    notes,
  };
  if (!facts.complete) notes.push('The facts script did not run to its end (the connection dropped?).');
  if (!facts.policy) notes.push('No policy file under /etc/selinux/*/policy: SELinux is not installed there, or the files are not readable.');
  if (facts.mode === 'Disabled') notes.push('SELinux is disabled on the target: nothing is enforced or logged there.');
  return facts;
}

/**
 * The command that reads a target's denials since `since` (ausearch's -ts
 * words, recent by default): AVC, USER_AVC and SELINUX_ERR records raw, and
 * the login programs' own refusals from the journal (they never reach the
 * audit log). Each part under a "### key" line, errors under key.err like
 * FACTS_SCRIPT; "<no matches>" is not an error.
 */
const JOURNAL_SINCE = { recent: '-10min', 'this-hour': '-1h', boot: '-b', today: 'today', yesterday: 'yesterday', 'this-week': '-7d', 'this-month': '-31d', 'this-year': '-366d' };
function denialsScript(since) {
  const ts = /^[\w-]+$/.test(since || '') ? since : 'recent';
  const j = JOURNAL_SINCE[ts];
  return `
sec() { printf '### %s\\n' "$1"; }
sec mode; getenforce 2>/dev/null
sec audit
# ausearch reads stdin when it is a pipe (it would eat the rest of this script): give it none.
out=$(ausearch -m avc,user_avc,selinux_err -ts ${ts} --raw 2>&1 </dev/null); rc=$?
if [ $rc -eq 0 ] || printf '%s' "$out" | grep -q '<no matches>'; then printf '%s\\n' "$out" | grep -v '<no matches>'; else sec audit.err; printf '%s\\n' "$out" | head -3; fi
sec journal
${j ? `journalctl -q ${j === '-b' ? '-b' : `--since ${shq(j)}`} 2>/dev/null </dev/null | grep -E 'pam_selinux|ssh_selinux|SELinux (security )?context'` : 'true'}
sec done
`;
}

/** The output of denialsScript → { text (the records), count (AVC lines), mode, error }. */
function parseDenialsOutput(out) {
  const s = splitSections(out);
  const audit = (s.audit || '').replace(/^\s+|\s+$/g, '');
  const journal = (s.journal || '').trim();
  const text = [audit, journal].filter(Boolean).join('\n');
  const e = s['audit.err'] != null ? s['audit.err'].trim().split('\n')[0] : null;
  return { text, count: text.split('\n').filter(l => /^type=(AVC|USER_AVC|SELINUX_ERR)\b/.test(l)).length, mode: (s.mode || '').trim() || null,
    error: e ? (/ermission denied/i.test(e) ? 'The audit log needs root on the target.' : /not found/i.test(e) ? 'ausearch is not installed on the target (audit package).' : e) : s.done == null ? 'The command did not finish on the target.' : null };
}

/**
 * The processes, services and listening sockets of the target, the same
 * commands What Runs Unconfined runs here (unconfined.js parses them).
 */
const HOST_FACTS_SCRIPT = `
sec() { printf '### %s\\n' "$1"; }
sec hostname; hostname 2>/dev/null || uname -n
sec uid; id -u
sec ps; ps -eo pid=,ppid=,user:32=,label=,comm=,args= 2>&1 </dev/null
sec units; systemctl show --no-pager -p Id,ExecStart,MainPID,ActiveState,SubState,FragmentPath,User,NoNewPrivileges '*.service' 2>&1 </dev/null
sec ss; ss -lntuHp 2>&1 </dev/null
sec done
`;

/** systemd's own search path for a bare name in ExecStart=. */
const PATH_DIRS = ['/usr/local/sbin', '/usr/local/bin', '/usr/sbin', '/usr/bin', '/sbin', '/bin'];

/**
 * A script resolving program paths on the target: for each candidate (an
 * absolute path, or a bare name systemd would search), whether it exists,
 * its real path and its package: lines `candidate<TAB>real<TAB>exists<TAB>pkg`.
 * The candidates ride inside the script (a quoted heredoc: no expansion).
 */
function pathsScript(candidates) {
  const list = [...new Set(candidates)].filter(c => /^[^\n\t]+$/.test(c) && c !== 'EOF_PATHS');
  return `
resolve() { p=$1; case "$p" in /*) ;; *) for d in ${PATH_DIRS.join(' ')}; do if [ -f "$d/$p" ]; then p="$d/$p"; break; fi; done ;; esac
  if [ -e "$p" ]; then r=$(realpath "$p" 2>/dev/null || printf '%s' "$p"); pk=$(rpm -qf --qf '%{NAME}\\n' -- "$r" 2>/dev/null </dev/null | head -1); case "$pk" in *"not owned"*|error*) pk= ;; esac; printf '%s\\t%s\\t1\\t%s\\n' "$1" "$r" "$pk"; else printf '%s\\t\\t0\\t\\n' "$1"; fi; }
while IFS= read -r c; do [ -n "$c" ] && resolve "$c"; done <<'EOF_PATHS'
${list.join('\n')}
EOF_PATHS
printf '### done\\n'
`;
}

/** pathsScript's output → Map candidate → { real, exists, pkg } (+ `done`). */
function parsePaths(out) {
  const m = new Map();
  let done = false;
  for (const line of String(out || '').split('\n')) {
    if (line === '### done') { done = true; continue; }
    const f = line.split('\t');
    if (f.length < 3) continue;
    m.set(f[0], { real: f[1] || null, exists: f[2] === '1', pkg: f[3] || null });
  }
  m.done = done;
  return m;
}

/** One line about a target for the status bar / pickers. */
function describe(t, facts) {
  const bits = [];
  if (facts) {
    if (facts.policy) bits.push(facts.policy.name);
    if (facts.mode) bits.push(facts.mode.toLowerCase());
    if (!facts.root) bits.push('not root');
  }
  return `${targetId(t)}${bits.length ? ` (${bits.join(', ')})` : ''}`;
}

/**
 * The files mirrored from the target's /etc/selinux/NAME so the policy can be
 * analyzed here like an installed one: the kernel policy, seusers, the
 * contexts tree (file_contexts and the application contexts), setrans.conf.
 * Relative to /etc/selinux; tar on the target ignores what isn't readable.
 */
function mirrorPaths(name, policyFile) {
  return ['config', `${name}/seusers`, `${name}/contexts`, `${name}/setrans.conf`, `${name}/policy/${path.posix.basename(policyFile)}`];
}

/** The tar command (run on the target) that streams the mirror. */
const mirrorCommand = (name, policyFile) => `cd /etc/selinux && tar czf - --ignore-failed-read ${mirrorPaths(name, policyFile).map(shq).join(' ')} 2>/dev/null`;

module.exports = { parseSpec, targetId, sshDest, shq, denialsScript, parseDenialsOutput, JOURNAL_SINCE, HOST_FACTS_SCRIPT, PATH_DIRS, pathsScript, parsePaths, sshArgs, ASKPASS_SCRIPT, FACTS_SCRIPT, splitSections, parseOsRelease, parseConfig, parseModules, parsePermissive, parseBooleans, parsePolicyFiles, parseFacts, describe, mirrorPaths, mirrorCommand };
