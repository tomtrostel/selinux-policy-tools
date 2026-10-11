# Before you start: what does the service need?

A confined service runs in a **domain** of its own (`mydaemon_t`). SELinux
then denies it everything that isn't explicitly allowed, whatever user it
runs as, root included. Writing its policy means listing what it legitimately
needs, and nothing else.

Collect this first (the package's file list, its systemd unit and a test run
tell you most of it):

| Question | Where it goes in the form |
| --- | --- |
| Which executable does systemd start? | **Service → Program** |
| Which files does it own: PID file and sockets in `/run`, data in `/var/lib`, logs, its own config in `/etc`, cache, spool? | **Files**, one type each |
| Which ports does it listen on, and which does it connect to? | **Network** |
| Does it log to syslog/journal, resolve user or host names, use D-Bus, PAM, TLS certificates? | **System access** |
| Does it start as root and drop privileges? Bind a port below 1024? | **Process and capabilities** |
| Is there something only some sites need (connect anywhere, read home dirs)? | **Booleans** |
| Does it run helper programs that need different rights? | **Helper programs** |

**Least privilege.** Give each file kind its own type and the lowest access
that works: logs *create and append*, configuration *read only*. Start
narrow: denials are easy to see and fix, whereas a too-broad grant goes
unnoticed.

**How labels work.** Files get their type from the `.fc` paths (applied by
`restorecon` or at install time), or when the service creates them in a
directory with a *type transition*. The form sets up both for you.
