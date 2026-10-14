# Programs only through wrappers

Some users should run a privileged program only in a controlled way: a
restricted shell in a chroot, say, whose users may run a program only with
the arguments a wrapper allows. The wrapper is your own program (it checks
the arguments and then runs the real one, much like `execve`). The policy
makes sure the wrapper is the **only** way to the real program.

**SELinux: New Wrapped Programs…** opens a form:

* **Chroot**: the directory the users' sessions run in, and whether it is
  labeled like `/` (an equivalence). The **protected** directory holds the
  copies of the real programs; the **wrapper** directory holds your
  wrappers (paths as the users see them inside the chroot).
* **Who runs the wrappers**: the users' role and domain (*New User…*
  creates one), and their Linux logins.
* **Programs**: add one by path. It is looked up for its label, its domain,
  its package, the domains it starts, and what its copy will miss in the
  chroot (libraries, and paths its domain uses).

What it writes:

* each wrapper gets a domain of its own, the only one that may run its
  program's copy;
* the copy runs in the original program's domain with the rules that domain
  has on the original file, so it keeps the original's privileges;
* the copies and the protected directory are labeled so that broad rules
  ("run any program", "list any directory") don't reach them, and the users
  can't run, read or even list them.

It goes into the tree (with the chroot's labeling and the commands to put
the copies in place on each system) or into a **standalone** module with an
RPM that makes the copies when installed and refreshes them when their
packages update.

It also adds checks to `selinux.checks`: the users may not execute, read or
stat the copies or the protected directory, and

```
never login %chrootusers reaches <program domain> except through <wrapper domain>
```

which follows the logins' real ways in, roles and transitions. If it fails,
the path it shows is a way around the wrapper. **SELinux: Edit Wrapped
Programs…** reopens the module; lines you added by hand are kept.
