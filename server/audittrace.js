'use strict';
/**
 * What a refusal leaves behind on a host (pure). Logins that bounce often
 * leave no AVC record: a dontaudit rule hides the denial, the kernel logs
 * it as SELINUX_ERR (an invalid computed context, a refused NoNewPrivileges
 * change), or libselinux finds no context at all and only the login
 * program's own log says so (RHEL 8's security_compute_user checks without
 * auditing). Each problem carries a `trace` that says which, and how to see
 * it.
 *
 * trace: { record: 'avc' | 'none' | 'selinux_err' | 'log', hidden: [rule]
 * (dontaudit rules), text }.
 */

/** Where a login program writes its own messages. */
const LOGS = {
  sshd_t: 'sshd\'s log (journalctl -u sshd, /var/log/secure)', sshd_session_t: 'sshd\'s log (journalctl -u sshd, /var/log/secure)',
  local_login_t: 'login\'s log (/var/log/secure)', remote_login_t: 'login\'s log (/var/log/secure)',
  crond_t: 'crond\'s log (/var/log/cron)', xdm_t: 'the display manager\'s log (journalctl -b)',
  init_t: 'systemd\'s log (journalctl -u user@UID.service)', sulogin_t: 'the console',
};

const ruleText = (r) => `${r.rt} ${r.s} ${r.t}:${r.c} ${r.perms.length > 1 ? `{ ${r.perms.join(' ')} }` : r.perms[0]};${r.cond ? ` [${r.cond}]` : ''}`;

/**
 * An AVC refusal of `miss` (policy_query avc answer `a`): logged, unless every refused permission
 * is covered by a dontaudit rule.
 */
function avcTrace(a, miss) {
  const hidden = [];
  let audited = false;
  for (const p of miss || []) {
    const x = ((a && a.perms) || {})[p];
    if (x && x.dontaudit && x.dontaudit.length) {
      for (const r of x.dontaudit) if (!hidden.some(h => ruleText(h) === ruleText(r))) hidden.push(r);
    } else audited = true;
  }
  if (audited || !hidden.length) return { record: 'avc', hidden: [], text: 'An AVC denial is logged (ausearch -m AVC).' };
  return { record: 'none', hidden, text: `No AVC denial is logged: ${hidden.map(ruleText).join(' and ')} hide${hidden.length > 1 ? '' : 's'} it. To see it on a host, turn dontaudit rules off with semodule -DB (semodule -B turns them back on).` };
}

/** A refused process transition answer (policy_query logincontexts transition): AVC unless dontaudit hides it. */
function transitionTrace(t) {
  if (t && t.dontaudit && t.dontaudit.length) return avcTrace({ perms: { transition: { dontaudit: t.dontaudit } } }, ['transition']);
  return { record: 'avc', hidden: [], text: 'An AVC denial for process transition is logged (ausearch -m AVC).' };
}

/** The kernel logs it as SELINUX_ERR, never as AVC. */
function selinuxErrTrace(op, avcToo) {
  return { record: 'selinux_err', hidden: [], text: `No AVC denial${avcToo ? ' explains it alone' : ''}: the kernel logs SELINUX_ERR op=${op} (ausearch -m SELINUX_ERR).` };
}

/** Only the login program's log: libselinux found no context, nothing reached the kernel's audit. */
function logTrace(S) {
  return { record: 'log', hidden: [], text: `No audit record at all: only ${LOGS[S] || `${S}'s log`} says "Unable to get valid context" (pam_selinux) or "Failed to get default SELinux security context" (sshd).` };
}

module.exports = { avcTrace, transitionTrace, selinuxErrTrace, logTrace, ruleText, LOGS };
