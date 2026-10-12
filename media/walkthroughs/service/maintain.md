# Change it later, safely

**SELinux: Edit Service…** (or right-click a module in the Policy Explorer →
*Edit Service*) opens **any** service module in the same form: yours, or one
of the hundreds in the distribution policy. That includes services started
by systemd, D-Bus activation, inetd, cron or as a mail server, daemons a
template of their module declares and starts (`rpc_domain_template(nfsd)`,
`systemd_domain_template(systemd_logind)`: the template call stays as
written), and web applications (`apache_content_template(bugzilla)`). A
module with several domains asks which one to edit.

The editor reads the module back and **changes only the lines of the
settings you change**:

* turning a capability off rewrites just that `allow … self:capability` line,
  and keeps its comments;
* removing a file type removes its declaration, its rules and its file
  contexts;
* a new grant under a boolean goes into that boolean's existing block;
* everything the form doesn't model (conditional blocks on several
  booleans, `ifdef`s, rules involving other modules' types) stays exactly as
  it is and is listed under **Kept as is**. Click a line to jump to it.

It refuses changes that would break the build, and tells you where the
problem is: removing a type, boolean or helper that another module or the
`.if` still uses.

**Review what an edit really changed.** In a git-managed tree, **SELinux:
Compare Compiled Policy with HEAD** builds the committed version and lists
every rule your edit added or removed, down to single permissions, each traced
to the source line responsible. It also shows the side effects you didn't
write: one interface call can grant access to several types.

That's the loop for maintaining policy: **edit → save (builds) → compare →
commit**.
