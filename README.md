# SELinux Policy Tools (prototype)

A VS Code extension for refpolicy-style SELinux policy source: the
`.te` / `.if` / `.fc` / `.spt` files in RHEL and Fedora `selinux-policy`,
upstream refpolicy, and locked-down policies derived from them (CLIP-style).

It works at two levels:

* **Source.** It parses the m4 structure (interfaces, templates,
  `gen_require`, `optional_policy`, declarations, AV rules) without running
  m4, and expands templates so that generated names resolve, e.g.
  `http_port_t` and `corenet_tcp_bind_http_port` jump to
  `network_port(http, …)` in `corenetwork.te.in`.
* **Compiled policy.** On Linux it builds the policy with the real toolchain
  (m4, `checkmodule`, the policy's own Makefile), reports compiler and link
  errors on the source lines that caused them, shows what each line compiles
  to, and presents the linked kernel policy as a navigable tree.
* **Lockdown workflows.** On top of the compiled policy: what an edit
  changed compared with `HEAD`, what turning a module off or on would do,
  a domain transition graph, security property checks re-run after every
  build, and validation of users, roles and MLS levels, all traced back to
  the source lines responsible.

## Requirements

The `.vsix` is self-contained: the language server is plain JavaScript and
runs on the Node.js that VS Code (or VS Code Server, for Remote-SSH)
already bundles, so nothing needs compiling and no Node.js install is
needed. Navigation and source diagnostics work anywhere VS Code runs.

Building and the compiled-policy features run the real SELinux toolchain on
a Linux host (RHEL, Rocky, Alma, Fedora). Install everything with:

```
dnf install make m4 checkpolicy policycoreutils policycoreutils-devel selinux-policy-devel setools-console git-core
```

| Feature | Needs (RHEL packages) |
| --- | --- |
| Navigation, completion, diagnostics | nothing |
| Dimming of inactive `ifdef` branches | `make` |
| Standalone module builds | `make`, `m4`, `checkpolicy`, `selinux-policy-devel`, `gawk` |
| Full source-tree builds | `make`, `m4`, `checkpolicy`, `policycoreutils`, `policycoreutils-devel`, `gawk`, `python3` |
| Compiled Policy view, rules, Changes since HEAD | `python3-setools` (from `setools-console`) |
| Changes since HEAD | also `git-core`, `tar` |
| Compare with installed policy | also `policycoreutils` (`semodule`) |
| Property checks and Compiled Policy view for standalone modules | `policycoreutils` (`semodule`, `semodule_package`), `checkpolicy`, `python3-setools`, an installed policy |

`policycoreutils`, `gawk`, `python3` and `tar` are present on any normal
RHEL system with SELinux. From Windows or macOS, use VS Code **Remote-SSH**
to such a host: the extension runs on the remote side. Remote-SSH installs
VS Code Server on the host the first time you connect, which needs internet
access there (or an offline VS Code Server install).

## Install

The extension isn't on the Marketplace; it ships as a `.vsix` file on the
[Releases page](https://github.com/tomtrostel/selinux-policy-tools/releases).

1. **Download** `selinux-policy-tools-<version>.vsix` from the latest
   release. On a host with the GitHub CLI you can also run
   `gh release download -R tomtrostel/selinux-policy-tools --pattern '*.vsix'`.
2. **Install it into VS Code** (1.82 or newer):
   * **Local window:** Extensions view → "⋯" menu → *Install from VSIX…* →
     pick the file. Or from a terminal:
     `code --install-extension selinux-policy-tools-<version>.vsix`
   * **Remote-SSH window** (recommended, so builds run on a Linux host):
     open the remote window first, then Extensions view → "⋯" →
     *Install from VSIX…*. The dialog browses the remote host; use
     *Show Local* to pick a file on your own machine instead. The extension
     installs on the remote side automatically.
3. **Reload** the window when VS Code asks (or run *Developer: Reload
   Window*).
4. **Open a policy folder**: a full source tree (the folder with
   `Makefile`, `Rules.modular`, `build.conf` and `policy/`) or a standalone
   module directory; see [Workspaces](#workspaces). The status bar shows
   "SELinux: N modules, N interfaces" once indexing is done, and the shield
   icon in the activity bar opens the SELinux views.
5. **For building** (optional), install the toolchain on the Linux host
   (see [Requirements](#requirements) for what each feature needs):
   `dnf install make m4 checkpolicy policycoreutils policycoreutils-devel selinux-policy-devel setools-console git-core`,
   and trust the workspace when VS Code asks; builds are off in Restricted
   Mode. For CLIP- or RHEL-style trees, set the build arguments as described
   under [Settings](#settings) or run *SELinux: Configure Build from Spec
   File…*.

**Updating:** install the newer `.vsix` the same way; it replaces the old
version. **Removing:** Extensions view → SELinux Policy Tools → *Uninstall*.

## Workspaces

Open one of these as the workspace folder:

* **A full policy source tree**: the folder with `Makefile`, `Rules.modular`,
  `build.conf` and `policy/` (e.g. a `selinux-policy` or refpolicy checkout,
  or CLIP's `packages/selinux-policy/selinux-policy`). Indexing a full tree
  (~1,500 files) takes a second or two; the status bar shows the result.
* **A standalone module directory** (`myapp.te`, `.if`, `.fc` side by side,
  as the `selinux-policy-devel` Makefile expects). If the folder has no
  support macros, the extension indexes the installed devel headers
  (`/usr/share/selinux/devel/include`) instead.
* **Several trees** (e.g. `rhel9/`, `rhel10/` and `clip/` in one folder, or
  as folders of a multi-root workspace). The extension works on one tree at
  a time, since their names would collide: that tree is indexed, built and
  shown in the views, and the status bar names it. Opening a file of
  another tree switches to it (a second or two to reindex;
  `selinux.tree.autoSwitch` turns that off), and *SELinux: Select Policy
  Tree…* (or clicking the status bar item) switches by hand; the choice is
  remembered for the workspace. Files of the other trees show a hint
  instead of diagnostics. Each tree keeps its own build results, and its
  own build settings in `selinux.build.trees` (*Configure Build from Spec
  File…* writes there when there are several trees).

## Features

**Navigation**

* Go to definition (F12) for interfaces, templates, m4 defines, types,
  attributes, roles, booleans/tunables and object classes, including names
  generated by templates (types, interfaces and booleans such as
  `staff_exec_content`; `ifelse` branches in templates are followed for
  each call, so a branch that doesn't apply generates nothing).
* Find all references (Shift+F12), e.g. every caller of an interface.
* Hover: interface signature, summary, parameter docs and what it requires;
  for types, their attributes and the `.fc` paths that label them; for
  classes, the full permission list; tunable descriptions.
* Outline of the current file, and workspace-wide symbol search (Ctrl+T).
* **Policy Explorer** sidebar: layers → modules → types, attributes,
  booleans, interfaces and file contexts, each clickable.
* *SELinux: Open Module…* (Ctrl+Alt+M) and commands to jump between a
  module's `.te`, `.if` and `.fc`.

**Authoring**

* Completion for interfaces (as snippets with named parameters), types,
  attributes, booleans and keywords; in AV rules, object classes after `:`,
  then only the permissions valid for the chosen class(es).
* Signature help while typing interface arguments.
* Syntax highlighting for policy and file-context files.
* **Build-flag `ifdef`s follow your build configuration.** `ifdef`/`ifndef`
  blocks on m4 build flags (`distro_redhat`, `enable_mcs`, `enable_mls`,
  `enable_ubac`, `init_systemd`, …) are decided the way the configured build
  would decide them; the flags are asked from the Makefile with your build
  settings. Inactive branches are dimmed in the editor (hover shows why),
  get no diagnostics, and their declarations, definitions and file contexts
  leave the index, so e.g. go-to-definition skips a `type` that only exists
  on Debian. Hovering a flag shows whether it is defined. Needs `make`
  (Linux) and a trusted workspace.
* **`ifdef` on other names is decided too**, from where the sources define
  them and the order refpolicy feeds files to m4 (support `.spt` files,
  then all `.if` files, then one module's `.te`; `.fc` files see only the
  `.spt` files). An interface name is defined in every `.te` and interface
  body (``ifdef(`ipa_helper_noatsecure', …)`` in oddjob.te); a `define()`
  in a `.te` counts from that line on, and only if its own branch is
  compiled; a name nothing defines (`TODO`, `targeted_policy`, the
  misspelled `enabled_mls` in RHEL's init.te) is never defined, so its
  branch is dimmed; the ``ifndef(`x', `interface(`x', …)')`` guards around
  interface definitions count as active. Hovering the name shows which
  branch is compiled and why. Names defined dynamically (inside macros,
  by `pushdef`/`undefine`, or matching a template-generated interface
  name) and defines in another module's `.te` stay undecided.
* Diagnostics as you type, with quick fixes where possible:
  * unknown interface/macro calls (suggests the closest names);
  * unknown object classes and invalid permissions for a class;
  * in `.if` files, types/attributes used in an interface but missing from
    its `gen_require` block (quick fix inserts the line);
  * in `.te` files of loadable modules, types, attributes and booleans from
    other modules (booleans: in `if (...)` statements; `tunable_policy`
    requires its condition's booleans itself, also when an interface passes
    one in) used without a require in that scope: the module's top level, or the
    `optional_policy` block the use is in. A require counts for its whole
    scope and the blocks nested in it, whether it is written in a
    `require { }` / `gen_require` block or comes from an interface called in
    that scope (checkmodule works the same way). The quick fix adds the line
    to a require block in the right scope (or creates one). Standalone
    modules are always loadable; in a tree, modules marked `module` in
    `modules.conf` (and `APPS_MODS`) are checked, base modules aren't (they
    are compiled together and need no requires). A tree without
    `modules.conf` (a bare upstream checkout) is checked the way `make
    conf` would set it up: modules whose `.if` says
    `<required val="true">` are base, all others loadable. With
    `MONOLITHIC=y` nothing is loadable, so nothing is checked;
  * link failures before you build: in a tree, a loadable module that
    needs a type or attribute outside `optional_policy` (a require entry, or
    an interface called at the top level that always requires it) which
    only modules turned off in `modules.conf` declare (or that no module
    in the tree declares, like `timidity_t` in RHEL 10, which ships
    `timidity.if` without `timidity.te`). Each one is shown
    where the requirement comes from (`postfix.te:313: … 'mail_spool_t'
    (required by mta_getattr_spool()) … only the mta module, which is off
    in modules.conf, declares it`), all at once and updated when
    `modules.conf` is saved; `semodule_link` itself reports one module per
    build and no line;
  * in `corenetwork.te.in`: `network_port` ports outside 0–65535, ranges
    that run backwards, unknown protocols, and a port declared twice
    (checkmodule accepts the first silently and reports the second against
    an unrelated file);
  * unbalanced parentheses / m4 quotes;
  * in `gen_user(...)` lines (`policy/users`): roles that aren't declared
    anywhere, MLS/MCS sensitivities and categories outside what the build
    defines (an MCS build has only `s0`), a range whose high level is below
    its low level, unknown MLS tokens, and a user defined twice in the same
    configuration. Role names and MLS macros complete inside `gen_user`, and
    hovering a user shows its roles, range and Linux logins from the last
    build.

  Calls inside `optional_policy`, or guarded by ``ifdef(`name')``, to
  interfaces that aren't in the tree are information only or ignored, since
  the build skips them.

**Service editor** (*SELinux: New Service…*, *SELinux: Edit Service…*, or
**+** / *Edit Service* in the Policy Explorer)

A form for writing the policy of a system service (a daemon started by
systemd) without writing m4 by hand, with a live preview of the files it
writes. It offers what the existing service modules use (taken from the
327 daemon modules in the Fedora tree):

* **Service:** module name and description, the program path(s) that start
  in the new domain, permissive mode while testing.
* **Files** the service owns, each a type with paths and an access level:
  runtime files (`/run`), state data (`/var/lib`), logs (create and append
  only, or full), configuration (read only by default), cache, spool,
  temporary files, shared memory, lock files, any other files, and the
  systemd unit file / init script labels. A path ending in `/` covers the
  directory and everything in it. Files the service creates in `/run`,
  `/tmp`, `/var/lib`, … get their type automatically (file type
  transitions).
* **Network:** ports it listens on and ports it connects to (TCP/UDP, any
  port type in the tree, shown with its port numbers, or any port).
* **System access** in plain words: syslog, user/group/host lookups, DNS,
  `/proc` and `/sys`, random devices, locale data, certificates, running
  programs or shell scripts, D-Bus, sending mail, NoNewPrivileges starts, ….
* **Process and capabilities:** pipes, signals, Unix sockets, scheduling,
  System V IPC, and each Linux capability with what it allows; the risky
  ones (`dac_override`, `sys_admin`, `net_admin`, `sys_ptrace`, …) are
  marked.
* **Other interfaces:** any interface that takes just the domain, found by
  name or by words in its summary.
* **Booleans:** rights an administrator switches on at run time
  (`setsebool`). A new boolean gets a name, a description (what `semanage
  boolean -l` shows) and a default; an existing one (`use_nfs_home_dirs`,
  any boolean of the tree) can be used too. Under each you add what it
  allows while on: system access, process rights, capabilities, ports,
  interfaces. They are written as `gen_tunable` with its `## <desc>`
  comment and `tunable_policy` blocks (inside `optional_policy` for
  calls into modules that can be turned off). Anything conditional policy
  can't hold is kept out: checkmodule allows only allow/dontaudit/type
  rules under a boolean, so interfaces that declare attributes or contain
  `optional` blocks (e.g. `dbus_system_bus_client`) are offered only as
  always-on, and so is anything already allowed always (a domain
  transition granted twice fails the build).
* **Interfaces for other modules:** the usual ones in the `.if` (`_domtrans`,
  `_exec`, read config/logs/state, manage state, `_stream_connect`,
  `_admin`).

The editor uses the tree's own interfaces and conventions (`files_pid_file`
and `_var_run_t` on RHEL, `files_runtime_file` and `_runtime_t` upstream and
in CLIP; `policy_module` with or without a version), wraps calls into
modules that can be turned off in `optional_policy`, and writes the `.te`,
`.if` and `.fc` (plus a `name = module` line in the `modules.conf` the
build uses, e.g. RHEL's `modules-targeted-contrib.conf`). In a tree the
module goes into the layer you pick; in a standalone workspace, into a new
folder. *Create module* writes and saves the files as one undoable edit,
and saving builds them.

**Editing an existing service** opens any module with an
`init_daemon_domain()` (several daemon domains: pick one). The editor reads
the module back into the same form and changes only the lines of the
settings you change: turning a capability off rewrites just that
`allow … self:capability` line (comments kept), removing a file type
removes its declaration, its rules and its file contexts, a new file type
goes next to the other declarations, a call left alone in an
`optional_policy` block takes the block with it. Booleans read back with
their description, default and grants; a new grant goes into the boolean's
existing `tunable_policy` block, a changed default or description rewrites
just the declaration. Everything the form doesn't model (`tunable_policy`
on several booleans or with an else branch, `ifdef` blocks, rules with
other modules' types, …) stays exactly as it is and is listed under *Kept
as is*, each line clickable. Removing a file type or a boolean that the
`.if` or another module still uses is refused, with the place that uses
it.

**Building** (Linux)

* **Build on save.** Saving a policy file compiles it in a private scratch
  directory (unsaved editor contents included; nothing is written next to
  your sources). Errors from `checkmodule`, m4 and `refpolicywarn`
  deprecation warnings appear on the right source lines.
* **Full trees** are built with the tree's own Makefile: `base.pp modules`
  first (compile errors in about a second), then `make validate` (links
  every module, expands the policy, checks file contexts; a few more
  seconds). Validation catches modules that require a type whose module is
  disabled in `modules.conf`; the error lands on the require entry or the
  interface call that needs it (and the static link check above shows all
  such problems before you build).
* **Monolithic trees** (`MONOLITHIC=y`) build the `policy` target in one
  go; errors, hovers, the expanded view, the Compiled Policy view, property
  checks and Changes since HEAD work on its `policy.conf`. A tree without
  `policy/modules.conf` (upstream refpolicy) gets one from `make conf` in
  the scratch copy.
* **Generated `corenetwork.te`.** Errors in it are shown on the
  `corenetwork.te.in` line that produced them, and duplicate-port errors
  (which checkpolicy attributes to an unrelated file) on the duplicate
  `network_port(...)` line.
  Build arguments that a policy's RPM spec passes (NAME, TYPE, APPS_MODS, …)
  go in `selinux.build.tree.makeArgs`; config files the RPM copies in at
  build time go in `selinux.build.tree.files` (applied to the scratch copy
  only).
* **RHEL / Fedora `selinux-policy` trees.** *SELinux: Configure Build from
  Spec File…* reads `selinux-policy.spec` (from an unpacked source RPM or
  the dist-git checkout), asks for the variant (targeted, minimum, mls,
  automotive) and writes the matching `makeArgs` and `files` (the spec's
  `modules.conf`, `booleans.conf` and `users`) into the workspace settings.
  Both spec layouts are understood: RHEL 9's (`modules-*.conf`,
  `booleans-*.conf` and `users-*` files next to the spec) and RHEL 10's
  (the tree's `dist/<variant>/` files, with `modules.conf` filtered through
  the spec's `modules-*.lst` lists exactly as its script does). The RHEL 9
  and RHEL 10 targeted builds take about 30 s from scratch (435 and 420
  module packages; most of it is `validate`). RHEL 10's policy also builds
  on a RHEL 9 host with RHEL 9's tools.
* **Keeping full-tree outputs.** Set `selinux.build.tree.outputDir` and the
  *SELinux: Build* command copies the module packages, `policy.bin` and a
  `build-info.json` record (time, tree, make arguments, file list) there
  after a successful build. Files from the previous export that the new
  build didn't produce are removed, so the directory always holds one build.
  Builds on save never write there.
* **Standalone modules** are built against `selinux-policy-devel`. The
  *SELinux: Build* command (🔧 in the editor title bar) also writes
  `<module>.pp` next to the `.te`. *SELinux: Install Module* (or the
  **Install** button after a build) rebuilds it and runs
  `sudo semodule -i <module>.pp` in a terminal on the policy host, where you
  enter your password.
* **"Compiles to" hover.** After a build, hovering an interface call in a
  `.te` file shows the statements it produced, including nested calls.
* **SELinux: Show Expanded Policy** opens a module's m4 output read-only,
  each block headed by the source line that produced it.
* Build logs go to the *SELinux Build* output channel.

**Compiled Policy view** (full trees; standalone modules linked with the
installed policy)

A second sidebar view shows the linked kernel policy from the last build:
what the policy actually contains after modules are enabled or disabled, not
what the sources declare.

* Users → their roles, MLS range and default level, and the Linux logins
  mapped to them in the tree's `seusers` file (for the build's policy type);
  Roles → their domains, the roles they may switch to (`allow R1 R2`), role
  transitions (running a type switches the role) and the users that have
  them.
* Modules → types / attributes / booleans / roles; Users → roles → types;
  Roles; Domains; Types; Attributes → member types; Booleans (with default);
  Classes → permissions.
* Each type expands to its attributes, aliases, roles, and domain
  transitions in both directions (with the entrypoint type), and those expand
  further.
* Clicking any element opens its declaration; template-generated types open
  the call that generated them.
* **Rules.** Every type and attribute has *Can access* (allow rules with it
  as source, grouped by target), *Accessed by* (as target, grouped by
  source) and *Other rules* (dontaudit, auditallow, type transitions).
  Rules written for an attribute the type belongs to are included and
  marked "via domain" etc.; conditional rules show their boolean. Expanding
  a rule lists the source statements that produce it, with the interface
  call they came through (`logging.te:77 via init_daemon_domain(…)`).
  The policy is indexed once per build (CLIP under a second, RHEL targeted
  about 5 s, done in the background after later builds); after that a
  query takes milliseconds.
* *SELinux: Find in Compiled Policy* searches all elements and reveals the
  one you pick.

**Domain transition graph** (full trees)

*SELinux: Show Domain Transition Graph* (also on domains in the Compiled
Policy view, and in its title bar) opens a graph of how processes move
between domains in the last build, starting from `init_t`, the domain under
the cursor, or any domain you pick:

* Click a domain to expand the domains it can transition to; switch to
  *who can enter* to see the domains that can transition into it instead.
  Double-click (or Ctrl/Cmd-click) opens the domain's declaration;
  Alt-click makes it the new root. A filter box narrows large fan-outs
  (`init_t` reaches hundreds of domains on RHEL).
* A transition is shown when the compiled policy allows all of it: the
  source may `transition` to the target, and some file type is both the
  target's `entrypoint` and executable by the source. Arrows are solid when
  automatic (a `type_transition` on that entrypoint), dashed when explicit
  (the source sets the context itself, `setexec`, e.g. `runcon`/`sudo`),
  dotted for dynamic transitions (`dyntransition`), and orange when a
  boolean controls them. Hover an arrow for its entrypoint types.

**Changes since HEAD** (full trees in git)

*SELinux: Compare Compiled Policy with HEAD* answers "what did my edit
actually change in the compiled policy?". It builds the tree as of `HEAD`
(exported with `git archive`, same build settings, cached per commit) and
compares its kernel policy with your latest build:

* Rules added, removed or changed, down to individual permissions
  (`~ allow syslogd_t etc_t:dir +add_name +remove_name +write`), grouped by
  source type, including side effects you didn't write: one
  `auth_read_shadow(syslogd_t)` line also grants `shadow_history_t`.
* Each change is traced to the source: the line and the interface call
  that produce it (`logging.te:650 via files_manage_etc_files(syslogd_t)`).
  Rules that come from an attribute rule also show the line that put the
  type into the attribute. Removed permissions point at the `HEAD` version
  of the line.
* Attribute membership, and added/removed types, attributes, roles, users,
  booleans and classes; changed boolean defaults and role/user assignments.
* An edit that grants nothing new is reported as "No effective policy
  change".

The first comparison builds `HEAD` too (CLIP: ~20 s for both builds; RHEL
targeted about a minute); after that a comparison takes 1–2 s plus your
build, and the view refreshes after each build.

*SELinux: Compare Compiled Policy with…* (also in the view's title bar)
compares with any other version instead: a tag ("what changed since the
last release?"), a branch, a recent commit or any ref you type
(`HEAD~3`), or **two refs** without the working tree (e.g. what the policy
gained between release tags `v1` and `v2`, traced into each tag's sources),
or a **saved build** exported with `selinux.build.tree.outputDir` (its side
has no sources to trace). Committed trees are exported with `git archive`
and built with your current settings; the last three are kept, so
switching between them doesn't rebuild.

**Compare with the installed policy** (full trees)

*SELinux: Compare Build with Installed Policy* (also in the Changes view's
title bar) answers "what would change on this host if I installed my
build?". It rebuilds the policy the way an installed system does, loading
every module package of the build into a scratch policy store with
`semodule` (CIL; no root needed, the host's `semanage.conf` is used), and
compares it with `/etc/selinux/<name>/policy/policy.NN` (pick which when
there are several). The result appears in the Changes view: "+" would be
added by installing your build and is traced to your source lines, "−"
exists only on the host (separately packaged modules such as
container-selinux or cockpit, local modules, `semanage`/`setsebool -P`
customizations, or things your build removes). The `semodule` build takes
~8 s for CLIP and ~25 s for RHEL targeted; it is redone only when the
build's packages change, and the comparison runs on request.

**Property checks** (full trees and standalone modules)

Write down security properties once, in a `selinux.checks` file at the tree
root (versioned with the policy); they are checked against the compiled
policy after every build and whenever you save the file. *SELinux: Open
Property Checks* creates the file with examples.

```
# nobody but auditd_t may write the audit log
only auditd_t may write auditd_log_t
# users must not touch the shadow file
never user_t, staff_t may write shadow_t
# no domain-transition path from user_t to sysadm_t, direct or indirect
never user_t reaches sysadm_t
# password hashes must not end up anywhere user_t can read, by any chain of
# domains and files (passwd_t and chkpwd_t are trusted to handle them)
never shadow_t flows to user_t except passwd_t chkpwd_t
# a lockdown must not break logging
require syslogd_t may { append create } var_log_t:file
```

* `only|never <roles> may run <types>`: which roles may run a domain;
  `only|never <users> may use <roles>`: which SELinux users may have a role.
* `only <names> may <perms> <targets>[:<classes>]`: nobody else may;
  `never <names> may …`: none of these may (`*` = every domain);
  `never <names> reaches <names>`: no transition path;
  `require <names> may …`: must stay allowed.
* `never <types> flows to <types> [except <types>] [weight N]`: no
  information flow, through any chain of domains and objects. A domain
  reads from a type when it holds a read-like permission on it and writes
  to it with a write-like one (setools' permission map, the same model as
  `apol`'s information-flow analysis): `shadow_t → systemd_userdbd_t →
  staff_t` means `systemd_userdbd_t` reads `shadow_t` and something
  `staff_t` reads is written by it. `except` lists types trusted to pass
  the data on (they are left out of the path search). By default only
  strong flows count (weight 10: reading and writing data); `weight 1`
  counts every permission, including covert channels such as signals or
  `getattr`. A failure shows the shortest path, each step traced to the
  statement that grants it.
* Names are types, aliases or attributes (an attribute stands for all its
  member types). Permissions are `read` (read open map), `write` (write
  append create unlink link rename setattr add_name remove_name rmdir
  reparent relabelfrom relabelto), `execute` (execute execute_no_trans
  entrypoint), `any`, a single permission, or `{ perm perm … }` (exactly
  those: `{ read }` is just `read`). Classes default to the file-like ones
  (`require`: `file`); a permission group only asks for what each class has.
* Each check shows "✓ holds" or "✗ …" above its line. A failure is an
  error in the Problems panel; its related information points at the source
  statements that grant each violating rule (or the steps of a transition
  path). The status bar shows how many checks fail. Completion offers
  keywords and type names.

Example findings on CLIP: `only sysadm_r may run sysadm_t` fails because
`system_r` may run it too; `never staff_u may use sysadm_r` fails (staff_u
has sysadm_r, linked to its `gen_user` line); `never syslogd_t may write syslogd_var_run_t`
fails with the rules from `logging.te:444/447`; `never staff_t reaches
sysadm_t` fails via `staff_t → newrole_t → sysadm_t`; `never shadow_t flows
to staff_t` fails via `systemd_userdbd_t` (`auth_read_shadow` in
`systemd.te`), and with `except systemd_userdbd_t` via `fapolicyd_t`.

**Standalone modules.** A module on its own isn't a policy, so in a module
directory the extension links it with this host's installed policy after
each build: the installed kernel policy (`/etc/selinux/<type>/policy`,
readable without root) is decompiled to CIL and compiled together with the
module into a throwaway store with `semodule -p`. Checks in
`selinux.checks` at the workspace folder then answer questions like "does
my module let anything read `shadow_t`?" or "can my daemon's data reach
`user_t`?" for the module as it is now; the Compiled Policy view shows the
same linked policy (your module's types under its name, everything else
under *(installed policy)*). Linking takes about 8 s on RHEL targeted and
runs only when a checks file exists or the view is open. If the module is
installed already, its installed rules stay in the result too.

**Module Preview** (full trees)

*SELinux: Preview Turning a Module Off/On…* (also on a module's right-click
menu in the Policy Explorer) shows what flipping a module in `modules.conf`
would do, before you edit anything. It builds the tree with that one
change in a separate scratch copy (your normal build is untouched) and
compares the result with your current build:

* **Link errors** if other modules hard-depend on it, placed on the
  interface call that brings in the requirement
  (`postfix.te:313: mta_getattr_spool(postfix_master_t)`).
* **`optional_policy` blocks that drop out** (or come alive, when turning a
  module on): blocks in other enabled modules that call the module's
  interfaces or name its types. m4 drops a whole block when any of its
  requirements is missing, so every statement in it goes, not just the
  calls into the module.
* The resulting **rule, type, attribute, role and user changes**, traced to
  source like Changes since HEAD (removed rules into the current sources,
  e.g. a rule inside another module's optional block).
* **Apply** edits the module's line in `modules.conf` (or in the spec's
  `modules-*.conf` when the build uses those) for you to review and save.
  A module that `APPS_MODS` forces on is dropped from `APPS_MODS` in the
  preview, and Apply offers to remove it from `selinux.build.tree.makeArgs`.

Example on CLIP: turning `cron` off still links, but 22 optional blocks in
19 other modules drop out, along with 26 types and 1,353 rule changes;
turning `mta` off fails to link because `postfix` needs `mail_spool_t`.
A preview is a full build of the changed tree (CLIP ~10 s).

## Settings

| Setting | Default | Purpose |
| --- | --- | --- |
| `selinux.extraIncludePaths` | `[]` | More directories to index, e.g. the full policy tree while editing local modules elsewhere |
| `selinux.useDevelHeaders` | `auto` | `auto` / `always` / `never` index the devel headers |
| `selinux.develHeadersPath` | `/usr/share/selinux/devel/include` | Devel header location |
| `selinux.diagnostics.unknownMacros` / `.classPerms` / `.genRequire` / `.users` | `true` | Toggle individual checks |
| `selinux.ifdef.evaluate` | `true` | Decide `ifdef`/`ifndef` on m4 build flags from the Makefile and on other names from the sources (dim inactive branches, leave them out of the index) |
| `selinux.build.enabled` | `true` | Build with the real toolchain |
| `selinux.build.onSave` | `true` | Build when a policy file is saved |
| `selinux.build.develMakefile` | `/usr/share/selinux/devel/Makefile` | Makefile for standalone modules |
| `selinux.build.tree.makeArgs` | `[]` | Extra `make` variables for full trees (overrides `build.conf`) |
| `selinux.build.tree.targets` | `[]` | Make targets for full trees; empty means `base.pp modules` then `validate` (`policy` if `MONOLITHIC=y`) |
| `selinux.build.tree.validate` | `true` | Run `make validate` after a modular tree compiles |
| `selinux.build.tree.outputDir` | `""` | Where *SELinux: Build* copies a tree's outputs (`~/…` or relative to the tree root); empty keeps them only in the scratch directory |
| `selinux.build.tree.files` | `{}` | Files to put into the scratch copy before building: `"policy/modules.conf": ["a.conf", "b.conf"]` (concatenated); a source can also be `{ "from": "dist/targeted/modules.conf", "disable": ["…/modules-dropped.lst"] }` (that file with the listed non-base modules turned off, as the RHEL 10 spec does); your tree is not modified |
| `selinux.build.trees` | `{}` | Build settings per tree when the workspace has several: `{ "rhel10": { "makeArgs": [...], "files": {...} } }` (key: path relative to the workspace folder, or absolute); overrides `selinux.build.tree.*` for that tree |
| `selinux.tree.autoSwitch` | `true` | With several trees, switch to the tree of the file you open |
| `selinux.checks.file` | `selinux.checks` | Property checks file, relative to the tree root (standalone modules: the workspace folder) |

**Workspace trust.** Building runs the policy tree's Makefile, and the build
settings can carry commands. In VS Code's Restricted Mode, navigation and
diagnostics still work, but builds are off and workspace values of the
`selinux.build.*` settings above are ignored. Trust the workspace to enable
them.

Example for CLIP on RHEL 9 (its RPM build arguments), in the tree's
`.vscode/settings.json`:

```jsonc
"selinux.build.tree.makeArgs": [
  "NAME=mcs", "TYPE=mcs", "DISTRO=redhat", "UBAC=y", "DIRECT_INITRC=n",
  "MONOLITHIC=n", "POLY=y", "UNK_PERMS=deny", "MLS_CATS=1024", "MCS_CATS=1024",
  "SEMOD_EXP=/usr/bin/semodule_expand",
  "APPS_MODS=ssh rhsmcertd oddjob … devicekit"
]
```

## What has been tested

* Service editor: every daemon module of the Fedora tree (326) reads back
  into the form, and saving it unchanged leaves all files byte-identical;
  22 kinds of edits on each (capabilities, file types added, removed or
  with another access level, paths, ports, system access, interfaces,
  permissive, program paths; booleans added, removed, with another default
  or description, grants added and removed, an existing boolean used)
  read back as the edited form and repeat as a no-op (7,172 edits). On
  CLIP, RHEL 9 and RHEL 10 a new service using every kind of setting
  (booleans included) builds and links with the full tree, and so do an
  edited `ntp` (a new boolean) and an edited `rsync` (its own boolean's
  default and grants); grants conditional policy can't hold are refused
  before building. None of the 766 calls Fedora's daemons make under a
  boolean is refused. A standalone service builds against the devel
  headers. The form itself is tested with a fake DOM; it hasn't had
  interactive use yet.
* Source diagnostics over the full upstream Fedora tree, the RHEL 9 source
  (selinux-policy 38.1.75, from the Rocky 9.8 source RPM) and CLIP for RHEL 9
  (sealingtech/CLIP, branch `RHEL9`). The remaining findings were checked by
  hand and are real problems in those trees: on RHEL 9, mostly missing
  `gen_require` entries that later Fedora versions fixed; on CLIP, four
  latent bugs in interfaces nothing currently calls.
* Link failures and `corenetwork.te.in`: the static link check and the port
  checks report nothing on the Fedora, RHEL 9, RHEL 10 and CLIP trees with
  their module configurations (all of which link). Turning `mta` off in
  CLIP's `modules.conf` shows the 11 places where `postfix` hard-depends on
  it, each on the interface call responsible (the build reports one).
  An error added to `corenetwork.te.in` is shown on its line (the
  generated file's 2,000+ lines align with the source with no unmapped or
  mismatched line on all three trees); a duplicate port is flagged while
  typing and its build error lands on the `.te.in` line instead of on
  `ubac.te`; a port of 99999999 is flagged.
* Several trees: a workspace with CLIP and RHEL 10 side by side, each with
  its own `selinux.build.trees` settings. Only the active tree is indexed
  (`syslogd_t` resolves to that tree's `logging.te`), the other tree's
  files get a hint, each builds with its own settings and `ifdef` flags
  (CLIP with UBAC, RHEL 10 without; 90 and 420 packages), switching moves
  the index, diagnostics, builds and the Compiled Policy view, and coming
  back shows the earlier build without rebuilding. Tree switching
  (automatic on opening a file, and by hand) was also tried in VS Code over
  Remote-SSH and works as designed.
* Booleans in the `.te` require check: no findings on the four trees; a raw
  `if (allow_raw_memory_access)` in CLIP's loadable `cron.te` is flagged
  (checkmodule: "unknown boolean … in conditional expression"), the same
  boolean in `tunable_policy` isn't, and the quick fix's
  `bool allow_raw_memory_access;` makes it build. Template-generated
  booleans (`<user>_exec_content`, 9–10 per tree) now resolve to the
  template call that declares them.
* The `.te` require check: no findings on the loadable modules of all three
  trees (Fedora with `dist/targeted/modules.conf`: 425; RHEL 9 targeted
  from the spec's module lists: 434; CLIP: 79 incl. `APPS_MODS`), which
  build, so none of them can lack a require. Treating Fedora's base modules
  as loadable finds `domain.te` using `unlabeled_t` unrequired. A
  standalone module with three missing requires (top level and inside
  `optional_policy`) gets exactly those, checkmodule rejects it, and after
  the three quick fixes it builds; in a CLIP tree a loadable module
  (`cron`) is checked and a base one (`kernel`) isn't.
* Standalone-module builds against `selinux-policy-devel` on Rocky 9.8.
* Full-tree builds, the Compiled Policy view and the hover/expanded views on
  CLIP for RHEL 9 (90 module packages, linked and validated).
* The RHEL 9 targeted build (selinux-policy 38.1.75) with settings from its
  spec: exactly the spec's 434 modules plus base, boolean defaults from
  `booleans-targeted.conf`, link errors for types from modules the spec
  turns off. Compared with the policy installed on the same host, the
  types, booleans and roles differ only by the separately packaged
  `container-selinux` module.
* All spec variants: RHEL 9 minimum (434 modules), mls (262) and automotive
  (432), and RHEL 10 automotive (362, after both module lists), each built
  and validated with the spec's settings, boolean defaults and `ifdef`
  flags (`enable_mls` for mls) checked.
* Monolithic: upstream refpolicy (SELinuxProject/refpolicy) with
  `MONOLITHIC=y` builds in ~12 s; compile errors land on their lines, the
  hover, expanded view, Compiled Policy view (4,510 types, all located),
  rule origins, property checks, Changes since HEAD and the export all
  work on `policy.conf`/`policy.33`. Testing it found two problems that
  affected any tree without `modules.conf` or with executable scripts,
  modular too: the extension now runs `make conf` when needed and keeps
  the scripts' execute bit in the scratch copy.
* RHEL 10 (selinux-policy 42.1.18, from the Rocky Linux 10.2 source RPM),
  built on the Rocky 9.8 host with RHEL 9's tools: checkpolicy 3.6 compiles
  the whole tree (it uses no newer language features), writing policy
  version 33 where RHEL 10's own build writes 35. With settings from its
  spec (RHEL 10 takes `booleans.conf`, `users` and `modules.conf` from the
  tree's `dist/` and filters `modules.conf` with the spec's module lists;
  the filtered file is identical to what the spec's script produces):
  targeted (419 modules, 28.6 s), mls (254 modules, 20.5 s) and minimum
  (362 modules) build and validate, with boolean defaults, link errors,
  build-flag `ifdef` dimming (`enable_mls` in the mls build), rule queries
  and source locations for all types checked. Compared with the RHEL 9
  policy installed on the host, the targeted build shows 24,452 rule
  differences, 239 types added and 301 removed. The source survey finds
  60 missing `gen_require` entries in interfaces (the same kinds as on
  RHEL 9, e.g. `device_t` in `devices.if`, `kernel_t` required as
  `init_t`), all real, and no missing requires in the 419 loadable
  modules' `.te` files.
* Users and roles: the `gen_user` checks report nothing on the Fedora,
  RHEL 9 and CLIP users files (with and without build flags, CLIP in MCS
  and MLS mode); a test file with an unknown role, `s3` and `c2000` in an
  MCS build, a bogus MLS token and a duplicate user gets exactly those
  five findings. CLIP's view shows `__default__ → staff_u` from `seusers`.
* Property checks on CLIP: holding and failing `never`/`require`/`reaches`
  checks, alias resolution, unknown names and syntax errors, violations
  traced to source lines, re-checking on edit/save without a rebuild.
  On RHEL's installed policy, `only auditd_t may write auditd_log_t` fails
  with 111 domains (broad attribute rules in the targeted policy).
  Information flow on CLIP: `never shadow_t flows to staff_t` fails in two
  steps with both rules traced to source; excluding the first intermediate
  domain finds the next path; `except`/`weight` completion. The flow search
  over RHEL's installed policy takes ~4 s including indexing.
* Standalone module checks on Rocky 9.8 (RHEL 9 targeted installed): a
  module calling `auth_read_shadow` is linked with the installed policy
  (~8 s), the violation and a `shadow_t → demo_t → demo_private_t` flow are
  traced to the module's lines, installed types work in checks, the
  Compiled Policy view shows the linked policy, and an edit plus build
  relinks. A module that is already installed links too (its declarations
  are taken from the installed copy).
* Domain transitions: CLIP `init_t` reaches 144 domains (`syslogd_t`
  automatically via `syslogd_exec_t`; entered from `init_t` and
  `initrc_t`); RHEL's installed policy `init_t` 576, `sshd_t` 33 (incl.
  dynamic ones), 22 domains can enter `sysadm_t` (one boolean-controlled).
  The graph's webview script is tested against a fake DOM.
* Module Preview on CLIP: `cron` off (links; 22 dependent optional blocks;
  removed rules traced into them), `mta` off (link error on the requiring
  interface call), `nscd` on (blocks come alive), `ntp` off (also dropped
  from `APPS_MODS`), including several previews in a row.
* Compare with installed policy: a `semodule` build of the RHEL 9 targeted
  tree against the policy installed on the same Rocky 9.8 host shows 5,132
  rule differences (instead of ~1.3 million with the Makefile's build):
  58 host-only types from container-selinux and cockpit, `sandbox_t`
  (shipped separately on RHEL) only in the build, one boolean default
  changed locally.
* Compare with other refs on CLIP (git repo with tags `v1`, `v2` and an
  unsaved edit on top): `v1` → working tree shows both changes, `HEAD` →
  working tree only the unsaved one, `v1` → `v2` only the committed one
  (traced into `v2`'s copy), a saved build shows a reverted edit as "−".
* Changes since HEAD on CLIP: an unsaved edit adding two interface calls
  and removing two permissions gives exactly the five changed rules and one
  attribute-membership change, each traced to the right line (removals to
  the HEAD version); an edit granting nothing new reports no change.
* Interactive use through VS Code Remote-SSH from Windows to Rocky 9:
  indexing, standalone-module builds, and on CLIP the full-tree build
  (compile and link errors), the Compiled Policy view (browsing, navigation,
  find, rules per type with their source lines), the "Compiles to" hover,
  the expanded view and Changes since HEAD;
  on the RHEL 9 tree, configuring from the spec, the targeted build and its
  Compiled Policy view, and dimming of inactive build-flag `ifdef` branches.
  After the 0.4.0 release, all features were clicked through the same way,
  including Module Preview, the domain transition graph, property checks
  and the users/roles features (0.3.0), and the comparisons,
  information-flow checks and standalone-module checks (0.4.0); everything
  worked as designed. The 0.5.0 and 0.6.0 additions (the `.te` require
  check, RHEL 10, the static link check, `corenetwork.te.in` errors,
  booleans, `ifelse`, monolithic builds) are covered by the automated tests
  above but haven't had interactive use yet.

## Limitations

**Service editor**

* Services only: a domain started by init with `init_daemon_domain()`.
  User applications, CGI scripts and helper domains of a service are edited
  in the `.te` as before (helpers show up under *Kept as is*).
* Ports: only port types the tree already has. A new port number needs a
  `network_port()` line in `corenetwork.te.in` (or `semanage port -a`).
* Booleans: new ones are tunables (`gen_tunable`); `tunable_policy` on
  several booleans (`a && b`), with an else branch, or `if` statements
  on `gen_bool` booleans are kept but not editable in the form. File
  access can't be put under a boolean (use an interface).
* Editing an existing module's description, or removing interfaces from
  its `.if`, is done in the files (other modules may call them).

**Source analysis**

* Structural parsing, not m4 emulation. Names produced by deep m4 tricks
  (string building with `patsubst`, `changequote`) won't resolve. Template
  expansion follows nested templates up to five levels.
* `ifdef`/`ifndef` are decided only where `make` can be asked (Linux,
  trusted workspace); on Windows/macOS without Remote-SSH every branch is
  indexed as active. Names defined dynamically (in macro bodies, by
  `pushdef`/`undefine`, or matching a template-generated name), defines
  in another `.te` (base modules are concatenated, so order matters) and
  build flags at the top level of a `.if` file (all_interfaces.conf is
  made without the flags) stay undecided: 9 branches on RHEL and CLIP.
* `ifelse` appears only inside definitions in the policy trees (comparing
  their arguments). When a call is expanded, a 4-argument `ifelse` whose
  two sides become plain text is decided (e.g. ``ifelse(`$1',`unconfined', …)``
  in the user templates: `staff_exec_content` exists, no
  `unconfined_exec_content`); comparisons involving `eval(...)` or other
  macros, longer `ifelse` chains, and m4's own machinery in the support
  and corenetwork macros are left active.
  `self_contained_policy` and `users_extra`, which the Makefile passes
  only for some build steps, are never decided.
* The `.te` require check: uses inside `ifdef` branches that can't be
  decided (all of them without `make`) aren't judged, and a scope that calls
  an interface the index doesn't know isn't judged either.

**Building**

* Builds need Linux with the tools above; on Windows/macOS they report
  themselves unavailable (use Remote-SSH).
* Full-tree builds are verified on CLIP for RHEL 9, all four spec variants
  of RHEL 9 and RHEL 10 (targeted, minimum, mls, automotive), and upstream
  refpolicy (monolithic and modular). For *minimum*, the RPM turns most
  modules off at install time, which the build doesn't reproduce.
* Monolithic builds (`MONOLITHIC=y`) work like modular ones except where a
  feature needs module packages: there is no link step (so no link errors
  and no static link check against packages) and *Compare Build with
  Installed Policy* says it needs a modular build. RHEL and CLIP trees
  don't build monolithic themselves (undefined interfaces and scope errors
  that only show without modules), and upstream refpolicy's current
  `validate` fails with RHEL 9's semodule 3.6 (its compile works).
* A tree without `policy/modules.conf` (upstream refpolicy) gets one from
  `make conf` in the scratch copy on the first build (the modules' default
  states); static checks that need module states stay off for it.
* Built with RHEL 9's checkpolicy, a RHEL 10 policy comes out as policy
  version 33 (RHEL 10 ships 35). The sources don't use the newer features
  today; if a future release does (e.g. netlink extended permissions),
  RHEL 9's tools will reject it and the build needs a RHEL 10 host.
* `make validate` links with the legacy `semodule_link`/`semodule_expand`
  tools, while an installed policy is built by `semodule` (CIL); the two
  represent attributes differently (comparing them shows ~1.3 million
  spurious rule differences on RHEL). *Compare Build with Installed Policy*
  therefore rebuilds with `semodule` first; the regular build, Changes
  since HEAD and the Compiled Policy view use the Makefile's build.
* Each language server (VS Code window) builds in its own scratch area, so
  two windows on the same tree build independently (each keeps its own
  copy: twice the disk space and build time). Areas left by crashed servers
  are removed when the next server starts.
* With several trees in a workspace, only the active one is analyzed;
  switching reindexes (1–2 s). Trees are found up to six directory levels
  below the workspace folders.
* Without `selinux.build.tree.outputDir`, full-tree outputs stay in the
  language server's scratch area (`/tmp/selinux-policy-tools-<uid>/<pid>/`),
  which is removed when the server exits.
* There is no command to install a full policy; copy the exported outputs
  to a test system and install them there. *Install Module* covers
  standalone modules only.
* Link errors from `semodule_link` carry no line number; the extension
  places them where the module requires the missing type outside
  `optional_policy` (the require entry, or the interface call that brings
  it in). `semodule_link` stops at the first module that fails, so a build
  reports one at a time; the static link check above shows all of them,
  but only for requirements it can work out (interfaces it knows, ifdef
  branches the build flags decide) and only against `modules.conf`, not
  for a Module Preview's changed configuration (the preview build reports
  those).
* Module Preview finds dependent `optional_policy` blocks statically (calls
  to the module's interfaces, including template-generated ones, and its
  type/attribute names); blocks that depend on the module only indirectly,
  through another module's interface, show up in the rule changes but not
  in the block list.
* Errors in the generated `corenetwork.te` are shown on the
  `corenetwork.te.in` line they come from (found by aligning the generated
  file with its source; a declaration's expansion maps to the
  `network_port(...)` call), with the generated line number in the message.
  `portcon`/`nodecon`/`netifcon` errors, which checkpolicy reports against
  the last `#line` marker (some unrelated file), are placed on the
  declaration they name.
* Build results, the "Compiles to" hover and the expanded view describe the
  last build: once you edit a file they are hidden until the next build.

**Compiled Policy view**

* For a standalone module the view shows the module linked with the
  installed policy (see Property checks); installed types have no source
  to open.
* Rules are shown as the compiled policy stores them: some attribute rules
  are expanded per type by the build, others stay written for the
  attribute (marked "via …"). Finding a rule's source statements takes a
  few seconds the first time after a build on a RHEL-sized tree, and lists
  at most eight.

**Changes since HEAD**

* Comparing with commits needs the tree to be in a git repository; every
  commit is built with the *current* build settings (a ref whose tree
  needs different settings may not build). Comparing with a saved build
  works without git.
* Tracing finds the statements in the build output that match a changed
  rule; when several do, files you changed rank first and at most six are
  listed. Rules using complements or wildcards (`~{ … }`, `*`) match
  loosely.
* The statement index takes about 100 MB per side on a RHEL tree while
  comparisons are active; it is dropped after two idle minutes.

**Property checks**

* Checks look at allow rules as compiled. Rules that depend on a boolean
  count regardless of the boolean's state (a property must hold with any
  boolean setting); the related information names the boolean.
* `reaches` follows domain transitions only (not, e.g., writing a file
  another domain executes) and up to eight steps.
* `flows to` uses setools' default permission map: an object's type stands
  for every object with that label, and a domain counts as an object too
  (writing to a process, pipe or socket labeled with it). It reports the
  shortest path, not all paths; fix it or add trusted types to `except`
  and the next one shows. Paths through the big unconfined domains are
  common on targeted policies.
* Checks run on the full tree's last good build, or for a standalone module
  on the module linked with the installed policy. That link is an
  approximation: attributes that the installed policy expanded into their
  member types (it keeps only the larger ones) are declared afresh, so
  rules the module adds for such an attribute reach only the module's own
  types; a module that requires a type the host doesn't have can't be
  linked (the message names the type).

## Development

Plain JavaScript, no build step.

```
npm install
npm test               # LSP features against a policy tree with a seeded test module, plus the ifelse unit test
npm run test:build     # standalone-module builds (Linux; skips elsewhere)
npm run test:tree      # full-tree builds and the Compiled Policy view (Linux; defaults to a CLIP RHEL 9 checkout)
npm run test:rhel      # RHEL selinux-policy tree with settings from its spec (Linux; args: tree, spec, variant)
npm run test:diff      # compiled-policy diff vs HEAD and its source tracing (Linux; defaults to CLIP RHEL 9)
npm run test:preview   # module on/off preview (Linux; defaults to CLIP RHEL 9)
npm run test:webview   # transition graph webview script against a fake DOM (any OS)
npm run test:checks    # property checks (Linux; defaults to CLIP RHEL 9)
npm run test:modchecks # property checks for a standalone module linked with the installed policy (Linux)
npm run test:mono      # monolithic build of upstream refpolicy (Linux; ~/sepol-test/refpolicy)
npm run test:ifelse    # ifelse decisions in template expansion (any OS; also part of npm test)
npm run test:multi     # several trees in one workspace: CLIP + RHEL 10 (Linux)
npm run test:scratch   # per-server scratch areas: two windows, exit, crash cleanup (Linux)
npm run test:service   # service editor: model, edits, webview (any OS; part of npm test; add a policy dir for every daemon module in it)
npm run test:service-e2e  # service editor with real builds (Linux; CLIP by default; args: tree [spec [variant]])
npm run survey -- <policy-dir>   # every diagnostic over a tree, to catch false positives
npm run package        # build the .vsix
```

`npm test` expects a workspace at `<tmpdir>/selinux-e2e-ws` (a copy of a
tree's `policy/` plus the seeded module under `policy/modules/local/`); pass
another path as the first argument. `test:tree` takes a tree path and a JSON
file of make arguments as optional arguments.

Layout: `server/parser.js` (tokenizer and structural parser),
`server/indexer.js` (workspace index and template expansion),
`server/diagnostics.js`, `server/build.js` (real-toolchain builds and output
parsing), `server/policy_model.py` (setools export of a compiled policy),
`server/service.js` (service editor model: render, read back, minimal edits),
`server/server.js` (LSP features), `client/extension.js` (VS Code client,
Policy Explorer and Compiled Policy views), `media/` (webview scripts).
