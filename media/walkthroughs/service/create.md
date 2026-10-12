# Open the service editor

**SELinux: New Service…** (or **+** in the Policy Explorer title bar)
opens a form on the left and a live preview of the files on the right. The
preview is updated as you type, and any problems are listed above it.

**Service** section:

* **Module** (in a tree workspace): **In the policy tree** makes the module
  part of the tree's policy. **Standalone module (packaged as an RPM)** makes
  a module of its own, to ship next to the service: it is built against this
  host's `selinux-policy-devel` headers (only their interfaces are offered),
  and comes with `NAME-selinux.spec` and a `Makefile`; **SELinux: Build
  RPM** builds the `NAME-selinux` package, which the service's own package
  can require.
* **What**: a **System service** (a daemon), or a **Web application** whose
  CGI scripts Apache runs. Web applications have a page of their own in
  this walkthrough.
* **Module name**: lowercase letters, digits and `_`. It names the files
  (`mydaemon.te`, `.if`, `.fc`) and, by default, the types: `mydaemon_t` for
  the process, `mydaemon_exec_t` for its program.
* **Layer** (in a tree): the `policy/modules/<layer>/` directory. The module is
  also added to `modules.conf` as a loadable module. **Folder** (standalone):
  where the three files go.
* **Description**: one line, at the top of the `.if`.
* **Program**: the executable(s) systemd starts, one per line. When systemd
  runs a file with this label, the process enters the new domain.
* **Started by**: what starts it in its domain. Usually **systemd**; also
  **systemd, as a mail server** (an MTA) or **inetd / xinetd** (TCP, UDP or
  both) for a program started per connection. Tick **Also: D-Bus
  activation** if the bus may start it on demand, **Also: Run by cron** if
  cron jobs run it. Those two go into `optional_policy`, since their modules
  may be off. A way whose module is off in your tree (inetd in CLIP) is shown
  but can't be chosen: the policy would fail to link.
* **Permissive while testing**: the domain is not enforced, only logged.
  Use it for the first runs, and turn it off once the denials are gone.

`%` in names and paths stands for the module name, so `/usr/bin/%` becomes
`/usr/bin/mydaemon`.

**Hover any option, button or field** for an explanation: what it allows in
plain words, which type it adds, and when it's usually needed or risky.
