# System access, capabilities and other interfaces

**System access** lists, in plain words, what services commonly need, each
mapped to the tree's interface:

* *Write to the system log* (syslog and the journal): almost every daemon.
* *Look up users, groups and host names* (nsswitch: passwd, SSSD, LDAP, DNS)
  versus *Read /etc/passwd and /etc/group only*: pick the narrower one if
  it's enough.
* *Read locale and time zone data*, *TLS certificates*, *D-Bus system bus*,
  *PAM*, *Kerberos*, reading `/proc` and `/sys` information, running
  programs from `/usr/bin` or a shell, sending mail…
* *Allow starting with NoNewPrivileges*: needed when the unit file uses
  systemd hardening options such as `NoNewPrivileges=yes` or
  `SystemCallFilter=`. Without it, systemd can't start the service in its
  domain.

Entries marked *(optional_policy)* call into modules that can be turned
off. The form wraps them so your module still builds without them.

**Its own processes**: pipes, signals and sockets between its own
processes, scheduling, resource limits. *Generate code at run time (JIT,
execmem)* is flagged ⚠ because it weakens exploit protection.

**Linux capabilities** are root's powers, split up. A daemon that starts as
root and drops privileges usually needs only `setuid` and `setgid`.
Capabilities marked ⚠ (`sys_admin`, `net_admin`, `dac_override`, …) grant a
lot, so look for another way first. `dac_override` denials, for example,
usually mean a file has the wrong owner.

**Other interfaces**: anything else in the tree that takes just the domain.
Search by name or by words in its description ("read random", "nfs"), or
**Find by need**: give a type (`etc_t`, `http_port_t`) or a path
(`/var/log/myapp.log`), the kind of object and what to do with it (read,
write, connect…), and it lists the interfaces that grant exactly that,
narrowest first, with what else each grants. **▸** next to any interface
(found, searched or already added) shows the rules it really compiles to.
