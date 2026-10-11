# Open the service editor

**SELinux: New Service…** (or **+** in the Policy Explorer title bar)
opens a form on the left and a live preview of the files on the right. The
preview is updated as you type, and any problems are listed above it.

**Service** section:

* **Module name**: lowercase letters, digits and `_`. It names the files
  (`mydaemon.te`, `.if`, `.fc`) and, by default, the types: `mydaemon_t` for
  the process, `mydaemon_exec_t` for its program.
* **Layer** (in a tree): the `policy/modules/<layer>/` directory. The module is
  also added to `modules.conf` as a loadable module. **Folder** (standalone):
  where the three files go.
* **Description**: one line, at the top of the `.if`.
* **Program**: the executable(s) systemd starts, one per line. When systemd
  runs a file with this label, the process enters the new domain.
* **Permissive while testing**: the domain is not enforced, only logged.
  Use it for the first runs, and turn it off once the denials are gone.

`%` in names and paths stands for the module name, so `/usr/bin/%` becomes
`/usr/bin/mydaemon`.

**Hover any option, button or field** for an explanation: what it allows in
plain words, which type it adds, and when it's usually needed or risky.
