# Contexts that won't load

A policy can compile and still fail on the host: the login programs, semodule,
restorecon and other programs read contexts from the policy's configuration
files, and each fails in its own way when the policy rejects one. Two checks
find these before a host does. Both run after every tree build, put their
problems on the lines that cause them, and have a panel that also checks
any installed policy.

**SELinux: Check Login Contexts…** works out the context each `seusers`
line gets for each way in (ssh, console, graphical, cron, systemd user
sessions), as libselinux does when a session starts:

* a login mapped to a user the policy lacks, a range it rejects, entries
  with a role the user can't have, a login program that may not switch to
  the user's domain: "Unable to get valid context for *user*";
* RHEL 8 and RHEL 9 pick differently (RHEL 9 takes the first valid entry
  without checking that the program may switch to it), so a configuration
  can work on one and fail on the other. The report says which.

**SELinux: Check Context Files…** covers every other place a context is
named:

* `file_contexts`: an invalid context or two lines for one path make
  `make validate` and semodule refuse the policy; the problem is on the
  module's `.fc` line;
* this host's `file_contexts.local`: one stale line makes every `semodule`
  and `semanage` change fail;
* home directories: the lines genhomedircon would silently leave out for a
  user (its prefix, role and level);
* types restorecon can't put on files (not file types);
* `default_type`, `x_contexts`, `dbus_contexts`, `openssh_contexts`,
  `lxc_contexts` and the rest, each with what its program does with a bad
  entry. Files read by programs your policy doesn't have are only noted.

Editing `seusers` or a contexts file updates the diagnostics without a
rebuild.
