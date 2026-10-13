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
  the source lines responsible. A logins report shows which SELinux user
  each Linux login gets and what its sessions can reach.
* **Writing and fixing policy.** A service editor that writes and edits a
  daemon's module from a form, and a denial assistant that reads AVC
  denials and tells a wrong label or a boolean that is off from a rule
  that is really missing.

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

## Tutorials

The extension comes with four step-by-step walkthroughs on VS Code's
*Welcome* page. Open them with **SELinux: Open Tutorials** (or the book icon
in the Policy Explorer title bar), or from *Help → Welcome → Walkthroughs*:

* **Get started with SELinux Policy Tools**: setting up the Linux host,
  navigating policy, fixing problems with quick fixes, building and the
  "Compiles to" hover, full trees and spec settings, the Compiled Policy
  view.
* **Write and maintain a service policy**: the service editor from planning
  to a confined, tested daemon (files, ports and port types, system access,
  capabilities, booleans, helper programs, web applications), and editing
  it safely later.
* **Fix a denial the right way**: reading an AVC message, telling a missing
  rule from a wrong label, granting with the owning module's interface
  instead of `audit2allow` rules, and checking what was actually granted.
* **Review and lock down a policy**: compiled change review against HEAD,
  tags or two refs, module previews, the transition graph, property checks,
  comparing with the installed policy, users, roles and who can log in as
  what, and a lockdown routine.

**SELinux: Create Practice Module…** copies a small daemon policy
(`notesd`) with four deliberate mistakes and a `selinux.checks` file into a
folder of your choice and opens it beside the walkthrough; its
`TUTORIAL.md` lists the hands-on tasks with solutions. Each step offers
buttons for the commands it describes and is ticked off when you use them.
The first time the extension starts, it offers the tutorials once.

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
* **All features in one menu** (*SELinux: All Features…*): click the
  *SELinux* item in the status bar, the ☰ button in the Policy Explorer's
  title bar, or *SELinux* in the right-click menu of the explorer and the
  editor. Features are grouped by what they're for (look into a policy,
  write policy, fix problems, build and install, compare, learn), each with
  a line saying what it does.

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
  transitions). Access levels: create, change and delete; create and
  append; read only; label only (no access: the type and its paths, for
  files other programs use). In an existing module, a file type whose
  rules match none of them (CLIP's `httpd_cache_t`:
  `mmap_manage_files_pattern`, `manage_lnk_files_pattern`,
  `files_var_filetrans`; plain `allow` rules) reads back as **custom (kept as
  written)**, with those rules listed under it: click one to open it in the
  `.te`, ▸ to see what it compiles to, and **Show what they allow** for a
  summary from their m4 expansion (CLIP's `httpd_cache_t`: dir, file and
  lnk_file create, write, rename, unlink …, file map, and the type
  transition `httpd_t var_t:dir httpd_cache_t`). They are kept exactly as
  they are; choosing a level instead says it replaces them with that
  level's standard rules (the preview shows the change).
* **Network:** ports it listens on and ports it connects to (TCP/UDP, any
  port type in the tree, shown with its port numbers, or any port), and
  **port types of its own** for port numbers no existing type covers. In a
  tree a new port type is a `network_port(name, tcp,9999,s0, …)` line in
  `corenetwork.te.in` (put in alphabetical place), so it gets the usual
  `corenet_*` interfaces and its `portcon`; numbers already taken by
  another port type are refused, overlaps with a range are pointed out.
  Port types named after the module (`ntp_port_t` for `ntp`) show up when
  editing it, and their numbers can be changed there. A standalone module
  declares the type itself (`corenet_port()`); since a loadable module
  can't carry port numbers, they are written as the `semanage port -a`
  commands to run after installing.
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
  interfaces, and more access to the service's own files (e.g. read only
  always, create/change/delete while the boolean is on; the type
  transition that puts new files in `/var/lib` & co. into its type comes
  along when the always-on level has none). They are written as `gen_tunable` with its `## <desc>`
  comment and `tunable_policy` blocks (inside `optional_policy` for
  calls into modules that can be turned off). Anything conditional policy
  can't hold is kept out: checkmodule allows only allow/dontaudit/type
  rules under a boolean, so interfaces that declare attributes or contain
  `optional` blocks (e.g. `dbus_system_bus_client`) are offered only as
  always-on, and so is anything already allowed always (a domain
  transition granted twice fails the build).
* **Helper programs:** programs the service starts that should run with
  other (usually fewer) rights than the service itself: a worker, a script,
  a privileged helper. Each gets a domain of its own (`NAME_t`, its program
  labeled `NAME_exec_t`; `domain_type`, `domain_entry_file`, `role
  system_r`), entered through `domtrans_pattern` when the service runs its
  program, and only the rights you give it: access to each of the
  service's file types (none, read, append, manage), system access,
  process rights, capabilities, ports, interfaces, and whether the service
  may signal it. Its rules go into a `# NAME_t local policy` section of
  their own.
* **Interfaces for other modules:** the usual ones in the `.if` (`_domtrans`,
  `_exec`, read config/logs/state, manage state, `_stream_connect`,
  `_admin`).

Every option, add button and field explains itself when you hover over it:
what it allows in plain words, which type it adds (with the module's name
filled in), and when it is usually needed or risky.

The editor uses the tree's own interfaces and conventions (`files_pid_file`
and `_var_run_t` on RHEL, `files_runtime_file` and `_runtime_t` upstream and
in CLIP; `policy_module` with or without a version), wraps calls into
modules that can be turned off in `optional_policy`, and writes the `.te`,
`.if` and `.fc` (plus a `name = module` line in the `modules.conf` the
build uses, e.g. RHEL's `modules-targeted-contrib.conf`). In a tree the
module goes into the layer you pick; in a standalone workspace, into a new
folder. *Create module* writes and saves the files as one undoable edit,
and saving builds them.

**Standalone modules packaged as RPMs.** In a tree workspace, a new service
can also be a **Standalone module (packaged as an RPM)**, to ship with the
service instead of in the policy: the form then works from this host's
`selinux-policy-devel` headers (`/usr/share/selinux/devel`, including
`distributed/`), not the tree. Only their interfaces are offered (one the
tree has but the headers don't is refused), the declaration helpers follow
them (on RHEL 9 runtime files use `files_pid_file` and `_var_run_t`, even
in a CLIP tree that has `files_runtime_file`), calls outside the kernel and
system layers go in `optional_policy`, new port types are declared in the
module, and nothing is added to `modules.conf` or `corenetwork.te.in`. The
module goes in `<workspace>/<name>-selinux/` (or the folder you give) with:

* `<name>-selinux.spec`: an independent `<name>-selinux` package (Fedora's
  SELinux packaging guidelines): `BuildRequires: selinux-policy-devel`,
  builds the `.pp` with the devel Makefile, installs it compressed under
  `/usr/share/selinux/packages/targeted/` and the `.if` under
  `/usr/share/selinux/devel/include/distributed/`, loads and unloads it with
  `%selinux_modules_install` / `%selinux_modules_uninstall`, relabels with
  `%selinux_relabel_pre` / `%selinux_relabel_post`, and labels the module's
  port numbers with `semanage port` in `%post` (removed on erase). Version
  from `policy_module()`, packager from git's `user.name` / `user.email`;
  `License:` as chosen in the form (below).
* `Makefile`: `make` builds the module, `make rpm` the RPM under
  `./rpmbuild`.

**License.** For a standalone module the form has a **License** picker: ten
common open source licenses (MIT, Apache-2.0, GPL-2.0-or-later,
GPL-2.0-only, GPL-3.0-or-later, LGPL-2.1-or-later, BSD-3-Clause,
BSD-2-Clause, MPL-2.0, ISC), the licenses you saved, or **Custom…** to type
your own (an SPDX expression such as `LicenseRef-Acme-Proprietary` or `MIT
AND BSD-3-Clause`; `%` and `#` are refused, since rpmbuild would read them
as a macro or a comment). **Save to my list** stores a custom license in
`selinux.packaging.customLicenses`, **Save as my default** (or **Make it my
default** on a listed one) in `selinux.packaging.license`, which the form
starts with (MIT unless you change it). Both go to your user settings, so
they are offered in every workspace, unless the workspace already sets them.

Both files are written once and then left alone, so edit them freely. New
services in a standalone workspace (a module folder, no tree) get them too. **SELinux:
Build RPM** runs `make rpm` for the module of the active editor (or one you
pick) in a terminal. Standalone modules next to a tree (any module folder
outside the tree's `policy/`) build with the devel Makefile, open in the
service editor again, can be installed with *SELinux: Install Module*, and
take fixes from the denial assistant. The service's own package can then
require `<name>-selinux`.

**Web applications.** A module built on `apache_content_template(NAME)`
(bugzilla, mediawiki, awstats, the CGI parts of collectd, git, munin, …)
opens as a web application: the domain Apache runs its CGI scripts in
(`NAME_script_t` in Fedora/RHEL, `httpd_NAME_script_t` upstream), its
**CGI scripts** paths, and a **Web content** section with the content types
the template declares (files it reads, data it changes, data it only adds
to, `.htaccess` files) and their paths in the `.fc`. Everything else in the
form (network, system access, capabilities, file types of its own, other
interfaces, booleans) edits the script domain's rules. A new module can be
a web application too (*What*: Web application), written as
`apache_content_template(NAME)` plus its paths; refused when the tree has
the apache module off. Paths keep a file type flag the path doesn't imply
(`/usr/share/bugzilla/ -d`), so CLIP's bugzilla, which labels one directory
`-d` for content and `--` for scripts, reads back and saves unchanged.

**Editing an existing service** opens any module with a domain something
starts as a system service: init (`init_daemon_domain()`,
`init_system_domain()`, `init_domain()` or their ranged variants), D-Bus
activation (`dbus_system_domain()`: accountsd, colord, geoclue, …), inetd
or xinetd (`inetd_service_domain()` and its TCP/UDP variants: comsat,
tcpd, …; `ucspitcp_service_domain()`), cron (`cron_system_entry()`:
certwatch, backup, tripwire, …) or as a mail server (`mta_mailserver()`,
`mta_sendmail_mailserver()`), at the top level or in `optional_policy`
(several domains: pick one). Daemons a template of their module declares
and starts count too: `rpc_domain_template(nfsd)` (nfsd, gssd, rpcd),
`systemd_domain_template(systemd_logind)`, rhcs, courier, milter, condor,
zarafa and others, found by following the template's body (and the calls
in it) to its start call. There *Started by* shows the template call, which
stays as written together with what the template itself declares and
allows; the form edits the module's own rules for the domain. So on RHEL also `xserver` (`xdm_t`,
`xserver_t`), `dbus`, `rpm`, `getty`, `mount` and others declared that way.
**Started by** shows how: systemd, systemd as a mail server, or inetd as
the main way, plus D-Bus activation and cron as further ones (written in
`optional_policy`). A main way whose module is off in the tree (inetd in
CLIP) is shown but can't be chosen, since the module would fail to link.
A way the list doesn't offer is kept as written (an edit
never turns `init_domain` into `init_daemon_domain`), and a domain declared
by a template (`ssh_server_template(sshd)` declares `sshd_t`) reads back
with that call as its declaration. The editor reads
the module back into the same form and changes only the lines of the
settings you change: turning a capability off rewrites just that
`allow … self:capability` line (comments kept), removing a file type
removes its declaration, its rules and its file contexts, a new file type
goes next to the other declarations, a call left alone in an
`optional_policy` block takes the block with it. Booleans read back with
their description, default and grants (file access under a boolean when
its patterns match a level; other file rules there stay as written); a new
grant goes into the boolean's
existing `tunable_policy` block, a changed default or description rewrites
just the declaration. Helper domains that the service enters through
`domtrans_pattern` (declared with `domain_type` + `domain_entry_file` or
`application_domain`) read back with their rights, e.g. `lsmd_plugin_t` or
`sssd_selinux_manager_t`; new rules go after the helper's last one.
Everything the form doesn't model (`tunable_policy`
on several booleans or with an else branch, `ifdef` blocks, rules with
other modules' types, …) stays exactly as it is and is listed under *Kept
as is*, each line clickable. Removing a file type, a boolean or a helper that the
`.if` or another module still uses is refused, with the place that uses
it. A path given for two types (say the service's program and a helper's)
is refused too, since `setfiles` rejects the build.

**Long lists of other interfaces** (more than 12, as on sshd or xdm) are
grouped by module: one collapsible line per module with its count
(`xdm_t` on RHEL 9: 255 interfaces in 70 modules, devices 33, files 26,
userdomain 18, …), a filter that narrows them as you type (name, words of
the description, module; groups with matches open, counts show "3 of 33"),
and *Expand all* / *Collapse all*. Each entry keeps its ▸ (what it compiles
to) and ✕.

**Finding interfaces.** The keyword search in *Other interfaces* ranks
results instead of listing them alphabetically: whole parts of an interface
name count most, then the types it requires (a type such as `etc_t` puts
the interfaces using exactly that type first), its module and its summary;
a few other spellings help (password → shadow/passwd, random → urand, pid
→ runtime, log → logging, …); among equal matches, interfaces called by
more modules come first (`logging_send_syslog_msg` is used by 310 of
CLIP's), `dontaudit` ones and rarely needed ones (`*_stub`, `mounton`,
`relabel`, …) last unless typed. It shows 25 at a time with a button for
the rest, and only offers interfaces whose argument is a domain (not
`files_pid_file`-style ones that take a type). Besides it,
**Find by need**: a type (`etc_t`, a port type such as `http_port_t`, a
domain such as `syslogd_t`) or an absolute path (looked up in the tree
build's file contexts, else this host's), the kind of object (file, dir,
socket classes, process, dbus, …) and what to do with it (read, write,
append, create, list, connect, bind, send signals, …, or exact
permissions). It lists the interfaces that grant exactly that, ranked as
the denial assistant ranks them (from what each one compiles to, narrowest
first, tagged *narrowest*, *owner*, *broad*, with what else each grants;
pairs when no single one covers it); *Add* puts one in the service. **▸**
next to an interface (found, from the keyword search, or already in the
service) shows the rules it really compiles to for this service's domain
and the attributes it adds (m4 with the policy's own Makefile; in a tree
after a build), so long lists such as sshd's can be reviewed.

**Login services.** *System access* has a **Logins** group for programs
that log users in, such as sshd, getty or a display manager: log users in
(`auth_login_pgm_domain`: PAM, switching to the user's identity, role and
level), start users' sessions in their own domains and signal them
(`userdom_spec_domtrans_all_users`, `userdom_signal_all_users`), record
logins in utmp/wtmp, lastlog and faillog, work out the session's SELinux
context, use the console and virtual terminals, use users' pseudo-terminals,
and **Pseudo-terminals for logins**: a pty type of its own
(`<domain>_devpts_t` with `term_login_pty` and `term_create_pty`, as
sshd's), which reads back like the other options.

**Denial assistant** (*SELinux: Analyze Denials…*, or the shield icon in the
Policy Explorer; Linux)

Paste audit records, open a saved log, or click *Read from this host*: it
runs `sudo ausearch -m avc,user_avc,selinux_err` in a terminal (sudo asks
for your password there) for the period you pick. Running the command with
the active editor holding audit records (or a selection of them) starts
from those. It reads `audit.log` lines, `ausearch` output (raw or `-i`) and
kernel/journal `avc: denied` lines, and joins each denial with the
program and full path from the same audit event (SYSCALL, CWD and PATH
records, hex-encoded names decoded).

Denials are grouped by source type, target type and class, and each group
gets a verdict, checked in this order:

| Verdict | When | Fix offered |
| --- | --- | --- |
| Not in its domain | the process runs as `unconfined_service_t`, `init_t`, `initrc_t`, `unconfined_t` or `kernel_t`, and its program (from the SYSCALL record) is labeled, or should be, with the program type of a domain of its own (`chronyd_exec_t` → `chronyd_t`): mislabeled, started from a shell, or started without the transition | `restorecon -v <program>` when it's mislabeled; otherwise how to start it so it enters its domain |
| No policy for this program | the same, but the program has a generic label (`bin_t`, `usr_t`, …) that only unconfined domains enter | **New Service…**: the service editor with the program filled in |
| Constraint | the rules allow it, but a `constrain`/`mlsconstrain` evaluated on the two contexts fails: MCS/MLS levels (`h1 dom h2`), SELinux users (UBAC), roles; the failing comparisons are shown with their values | `chcon -l <level>` or `chcon -u <user>` on the file, or an exemption interface |
| Wrong label | the policy's file contexts give the path another type (`matchpathcon`); for a `create`, the directory's label or a missing type transition | `restorecon -v <paths>` (none if the file has been relabeled since) |
| Boolean | the policy allows it once a boolean is changed (settings from rules on the type itself first; the one that covers every permission) | `setsebool -P <boolean> on` |
| Already allowed | the policy allows it now and no constraint fails (an older denial) | none; the allowing rules are shown |
| Generic label | the target is a catch-all type (`default_t`, `var_t`, `var_lib_t`, `usr_t`, …) | give the files a type of their own |
| Missing rule | none of the above | the interfaces that grant it, narrowest first (below); two that do together; or a new interface in the owner module |

When the rules already allow an access as labeled, a label that differs
from the file contexts isn't reported as its cause (libvirt's
`svirt_image_t` images, for instance, differ from `virt_image_t` in the file
contexts on purpose). In a standalone workspace, the module's own `.fc` is
used with the running policy's file contexts, so its paths are checked too.

Types the policy doesn't have ("from a different policy") and
`SELINUX_ERR` records are reported as such; permissive mode and
permissive domains are noted. *Check against* picks the policy: the one
running on this host (with its current boolean values and
`file_contexts.local`), another installed one, or the workspace's last
build (a tree's `policy.bin` and file contexts; a standalone module linked
with the installed policy). Each fix can be copied or put into a terminal
with `sudo` (not run: you press Enter); types link to their declarations.

**Interface suggestions.** For a missing rule the card lists the
interfaces that grant the access, narrowest first. Candidates are the
one-argument interfaces whose requirements (followed through the
interfaces they call) include the target type, or a smaller attribute of
it; what each really grants comes from m4, not from its name: one probe
module calls them all with the denied domain and is expanded by the
policy's own Makefile (a tree's last build, or the devel headers). An
interface counts when its rules (plus the rules of attributes it gives the
domain, from the compiled policy) cover every denied permission; the
others it grants are counted per type (attributes by their member count),
writes weighing three times and executes or transitions five times as much
as reads. When only reading was denied, an interface that would also let
the domain write, create, delete or run things ranks as if its other rights
were 20 times larger, and is tagged *writes*: for reading `user_home_t`,
`userdom_read_user_home_content_files` (reads 85 home types) comes before
`userdom_manage_user_home_content_files` (also writes `user_home_t`), while
a read-only interface over a very large attribute still loses to a narrow
one. Each suggestion shows what else it grants (`user_home_type (85
types) dir, file: read …` against `user_home_t file: create unlink write
…`), and is tagged *owner* (the target type's module), *broad* (far more
than the best one), *module off*, or what it lacks if nothing covers it
all. When both types belong to the domain's module, the fix is a plain rule
there. Examples on Rocky 9: `chronyd_t` writing `etc_t` →
`files_rw_etc_files`; connecting to `http_port_t` →
`corenet_tcp_connect_http_port` (a template-generated interface); reading
`shadow_t` → `auth_read_shadow`; reading `/dev/urandom` →
`dev_read_urand`. Click a call to open its definition, or copy it.
When no single interface covers every denied permission, the narrowest
**pairs** that do together are listed (*Add to module…* adds both). When no
interface grants it at all and the module that owns the target type is in
the workspace, it proposes **a new interface** for that module, named the
refpolicy way (`ntp_read_ntpd_extra_files`, `syslogd_sendto_unix_dgram_sockets`),
with its doc comment, `gen_require` and exactly the denied permissions;
*Add to module…* writes it into the owner's `.if` and the call into the
domain's module (in `optional_policy` when the owner can be off).

**Applying the fix.** *Add to module…* on a suggestion (or on the plain
rule for the domain's own types) shows exactly what goes where before
anything changes: the file, the line and the inserted text. *Apply* writes
it as one undoable edit and saves, so the module builds; when the build
finishes, the panel checks the denial again against that build and marks
it *Resolved* (or says what still denies it, or that the build failed). The
call goes where refpolicy modules keep it: among the domain's
one-argument interface calls next to its alphabetical neighbour, or, for an
interface from a module that can be turned off (not a base module; outside
the kernel and system layers without modules.conf), into that module's
existing `optional_policy` block for the domain, else a new block placed
alphabetically among the others; a plain rule goes after the domain's last
`allow` rule. A call that is already there is reported instead. In a
standalone workspace, a domain of the installed policy (e.g. `httpd_t`) gets
a small module of its own, `local_httpd/local_httpd.te` (`gen_require` of the
domain plus the call), built and checked linked with the installed policy;
install it with *SELinux: Install Module*.

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

**File labels** (*SELinux: Look Up File Label…*, *SELinux → Look Up File
Label* on any file in the explorer or editor, or the button in the Policy
Explorer; Linux)

What a policy does with any file or program on the system. Type a path
(`/usr/bin/rpm`; it doesn't have to exist) or pick one with *Browse…*; each
path gets a card:

* **On this host**: what it is (regular file, directory, link, device, …),
  its label now, the package that owns it (`rpm -qf`), and for a link its
  target (*Look up the target*). Paths are looked up as restorecon does:
  the directories resolved (`/bin/rpm` is `/usr/bin/rpm`), then the
  policy's equivalent directories (`file_contexts.subs`: `/usr/lib64` is
  `/usr/lib`).
* **Label**, for every policy at once (this host's installed ones and the
  workspace's last build): the context, and the file-context line that
  sets it, opened at its `.fc` source line with the module (a tree build),
  or at its line in `/etc/selinux/<name>/contexts/files` (local
  customizations from `semanage fcontext` say so). The other lines that also
  match and lose are listed with the rule that decides (the most specific
  wins). When the running policy's label differs from the file's: what
  `restorecon` would change it to. A kind (`-d`, `--`, …) can be chosen for
  paths that don't exist yet.
* **What the policy lets happen to the type** (*Rules from*: any of the
  policies): its declaration and attributes; for a program, the domains it
  starts and which domains start them that way (automatically or when they
  ask), with the transition graph, or that it starts no domain of its own
  (it runs in the caller's domain, with *Confine it: New Service…*); the
  type transitions that create objects with this label, and for a directory
  those that give new objects in it another one; and **who may access it**:
  the allow rules as written, for the type or one of its attributes (an
  attribute with its number of types and domains), strongest access first
  (relabel, manage, write, enter, execute, read), with conditions, a
  filter, and for the build *where from*: the source statements.

A tree build's file contexts are sorted the way `semodule` installs them.
The lookups of the denial assistant and of "can it …?" in Logins and Users
use the same order (earlier versions read the build's unsorted `.fc`
output, where a general line could win: CLIP's `/usr/bin/rpmbuild` came out
`usr_t` instead of `bin_t`).

**Logins and Users** (*SELinux: Logins and Users…*, or the person icon in
the Policy Explorer; Linux)

Who logs in as what, and what their sessions can reach. *Policy* picks this
host's installed policy (its `/etc/selinux/<name>` seusers and contexts) or
the workspace's last build (a tree's `config/appconfig-<TYPE>` files; a
standalone module linked with the running policy and its configuration).

* **Linux logins**: the seusers lines (`login`, `%group`, `__default__`)
  with the SELinux user and range, each line clickable. Noted: a login
  mapped to `unconfined_u`, `__default__` on a user with an admin role
  (CLIP maps `__default__` to `staff_u`, which has `sysadm_r`), a mapping to
  a user the policy doesn't have.
* **SELinux users**, one card each: its roles and logins; **ways in**
  (ssh, console, graphical, cron jobs, systemd user session, … from
  `default_contexts` and the user's own `contexts/users/<user>` file): the
  context each lands in and the others it may choose; then what its
  sessions can **reach**: every domain from there by running programs
  (domain transitions with an entrypoint the domain may execute, or
  dyntransition) and changing role where the user has the role, `allow R1
  R2` permits it and the policy's constraints agree (a `role_transition`, or
  asked for with newrole / `sudo -r` by a domain with `setexec`). Booleans
  are taken as possibly on; conditional steps say which boolean.
* **Risky abilities within reach**, with the shortest path and the rule:
  runs unconfined, loads a policy, switches to permissive, reads
  `/etc/shadow`, writes raw disks, changes booleans. Most are reached by
  running a program (`user_t → chkpwd_t` reads `/etc/shadow`); what a user
  can make it do then depends on the program, which the card says.
* **All reachable domains** on demand, each with its path, and **Ask**: can
  this user's sessions read `/etc/shadow` (a path, labeled from the
  policy's file contexts, or a type), with any class and permissions → yes
  with the nearest domain, the path and the rule, or no.
* On this host's running policy, **people's accounts** (UID ≥ `UID_MIN`
  from `/etc/login.defs`, and root) with the seusers line that applies
  (own, `%group`, or `__default__`), and **service accounts** (system
  UIDs): their processes run as `system_u` in the service's domain whatever
  seusers says; it applies only if the account logs in, so one with a login
  shell (e.g. `postgres` with `/bin/bash`) that would get a user with high
  risks is flagged.

On RHEL 9's targeted policy the report takes about 9 s (the reach of each
user is 0.1–2.5 s; staff_u reaches 867 domains, user_u 100, guest_u 11).

**User editor** (*SELinux: New User…*, or *New User…* in Logins and Users;
full trees)

A form for a new SELinux user, NAME_u with role NAME_r and domain NAME_t,
with a live preview of every file it writes:

* **Kind**: ordinary user (`userdom_unpriv_user_template`, like staff_u),
  restricted terminal or desktop user (guest_u, xguest_u), administrator
  (sysadm_u), or a confined administrator role with no login of its own,
  entered from another role (like webadm_r: Fedora/RHEL's
  `userdom_confined_admin_template`, upstream's `userdom_base_user_template`).
  Only kinds whose template the tree has are offered.
* **Logins**: Linux logins, `%group`s or `__default__` with an optional
  range (seusers; a login mapped to another user is refused), and the **ways
  in** (ssh, console, graphical login, cron jobs, rlogin): its own
  `NAME_u_default_contexts` lists only those, so the others aren't offered
  to it. Ticking cron jobs adds `cron_role`.
* **Roles**: roles it may switch to (`sysadm_role_change(NAME_r)` and the
  role in its gen_user line), roles that may switch to it
  (`staff_role_change_to(NAME_r)`), users who also get the role (added to
  their gen_user lines), and its own `NAME_role_change` /
  `NAME_role_change_to` interfaces in the `.if`.
* **Programs and administration**: sudo, su and the ssh client (role
  templates that give it NAME_sudo_t etc.; after sudo its contexts file
  offers its own context, then the roles it may switch to), and a search
  over the tree's role interfaces: services it administers (`*_admin`),
  applications (`*_role`) and admin programs (`*_run`). Arguments are filled
  by the interfaces' parameter names, so both Fedora's `(role, domain)` and
  upstream's `(prefix, domain, application attribute, role)` forms work;
  calls into modules that may be off go in `optional_policy`.
* **More rights** for its domain (capabilities, system access, other
  interfaces) as in the service editor, and the **levels** (default level,
  range, categories) and home directory prefix (the tree's usual one:
  `user` in Fedora/RHEL, the user's own name upstream).

**Create** writes, as one undoable edit: the role module in
`policy/modules/roles` (`role NAME_r;` plus the kind's template and the
calls), its gen_user line in the users file the build uses (RHEL: the
spec's `users-targeted`), `role NAME_r;` in `kernel.te` (the users file is
compiled into the base module, so base must declare every role it names, as
refpolicy does for staff_r), the seusers lines, the contexts file in
`config/appconfig-<TYPE>`, and the module's modules.conf line. Afterwards
*Logins and Users* on the build shows where its logins land and what it can
reach.

**Automation accounts.** *Start from → Automation account* fills the form
for an account scripts and tools log in as (Ansible, backups, monitoring):
an ordinary user (the restricted templates forbid setuid programs, so sudo
wouldn't work) that logs in over ssh and runs cron jobs only, with sudo and
`cron_role` and no extra rights. A note explains the rest: map its Linux
account, give it one narrow role to sudo into (a confined administrator
role made for just its job), and the matching `/etc/sudoers` line
(`ACCOUNT ALL=(root) ROLE=… TYPE=… NOPASSWD: …`), since sudo decides which
commands it may run and SELinux which domain they run in.

**Preview what it can reach** (above the file preview) builds the policy
with the planned files without writing anything: the tree in a scratch copy
of its own, or a standalone module linked with the installed policy. It
then shows where each way in lands, how many domains its sessions reach,
the risky abilities among them with the path there, and for an existing
user what the change adds or takes away compared with the last build
("staff without sudo: 77 domains, was 78; loses staff_sudo_t"). The
preview is marked stale when the form changes afterwards.

**Editing an existing user** (*SELinux: Edit User…*, or *Edit user…* on a
card in Logins and Users on a build) opens any role module of the tree
whose `.te` calls a userdomain template on a name: staff, sysadm, user,
guest, xguest, the confined admin roles, unconfined, CLIP's and RHEL's
alike. It reads back the role calls, role switches, extra rights and
booleans from the module, and from the other files: the `gen_user` line
(its roles, levels, prefix), seusers lines, the users who have the role,
and the ways in (its own contexts file, falling back to `default_contexts`
as libselinux does). Edits change only what changed:

* the module through the service editor's unit diff (new calls after the
  domain's rules or in their own `optional_policy` blocks; removed ones
  deleted; everything the form doesn't model listed under **Kept as is**,
  with the line to open);
* its `gen_user` line only when its roles, levels or prefix change, and only
  when it is a single plain line (CLIP's staff_u, written with `ifdef()`, is
  left alone with a note); a role switch added or removed adds or removes
  that role there; other users' lines for the users who get the role;
* seusers lines of its user;
* its contexts file: a way in turned off loses its lines, and its context
  comes off that source's line in `default_contexts` too (libselinux falls
  back to it), leaving the other roles there; a way turned on, or sudo / su
  added, gets a line.

A role without a user of its own (webadm_r) has no logins or levels to
edit: the users who get it are listed under Roles.

**Standalone users packaged as RPMs.** In a tree workspace whose host has
`selinux-policy-devel`, a new user can be **Standalone** (the Module choice
at the top), and in a folder of standalone modules it always is. The role
calls and their arguments then come from the host's devel headers (so in a
CLIP workspace on RHEL, `sudo_role_template(NAME, NAME_r, NAME_t)` in RHEL's
form), and the editor writes into `<folder>/NAME-selinux/`: the module, its
`NAME_u_default_contexts`, a Makefile and, once, `NAME-selinux.spec` with
the License picked in the form. A loadable module can't declare SELinux
users or login mappings, so the RPM's `%post` creates them after installing
the module (`semanage user -a -R 'NAME_r …' -L … -r … -P …`, `semanage
login -a` per login or `%group`, `semanage user -m` adding the role to the
users who get it), installs the contexts file as
`/etc/selinux/targeted/contexts/users/NAME_u`, and `%postun` undoes it all
before removing the module. Levels must be literal (`s0-s0:c0.c1023`, no
m4 macros); logins already mapped on this host are refused. *SELinux: Build
RPM* (`make rpm`) packages it. Opened again, a standalone user reads back
from its module, its contexts file and the spec's `%post` lines; the form
edits the module and the contexts file, and points to the spec for logins,
levels and granted users.

**Wrapped programs** (*SELinux: New Wrapped Programs…*, *SELinux: Edit
Wrapped Programs…*; full trees and standalone modules)

For users whose sessions run in a chroot (e.g. a read-only shell login with
sshd's `ChrootDirectory`) who may use certain programs only through
wrappers. Your wrapper decides what it allows (which arguments, for
example) and then `execve`s a protected copy of the real program. The policy
makes sure that:

* the users may run the wrappers, but can't run the protected copies, or
  even list the directory they're in;
* each wrapper (a domain of its own) may run only its own program's copy;
* the copy runs in the original program's domain, so it has exactly the
  privileges the program has outside the chroot. The rules that domain has
  on the program's own file are given on the copy too, and the user's role
  gets the domain and the domains it starts on its own.

The copy's type is deliberately not one of the attributes for programs
(`exec_type`, `entry_type`): rules other domains have on those, such as
running any program, don't reach it, so the wrapper is its only way in. The
copy and the protected directory are declared as security files where the
policy has `files_security_file`: broad rules on other files (on RHEL every
user domain may stat any ordinary directory) don't reach them either.

The form takes the chroot, the directories inside it for the wrappers and
the protected copies, the user (a role with its domain; *New User…* creates
one) and its Linux logins (`%chrootusers`, for the checks), and the
programs: give a program's path (`/usr/sbin/someprog`) and it
is looked up in the tree's build (or this host's policy for a standalone
module):
* its label and domain; programs without a domain of their own run in the
  wrapper's domain, which the form says;
* the domains that domain starts on its own;
* the package it comes from;
* what the copy will find in the chroot: the libraries it links and the
  paths of the file types its domain uses, missing ones first. Bind mounts
  are yours to set up.

Each wrapper's domain gets what an `execve` hop needs (libraries, locale,
the user's terminal); add interfaces if your wrapper does more.

*Label the chroot like /* (on by default) labels everything in the chroot
like its counterpart outside (`semanage fcontext -e / CHROOT`; in a tree a
line of `config/file_contexts.subs_dist`). File contexts for the wrappers
and copies are then written for the paths as seen inside the chroot, so they
must be paths the host itself doesn't use: the form refuses ones that exist
on the host, since their lines would relabel the host's files too.

What it writes:

* **In a tree:** the module (`policy/modules/<layer>`), its `modules.conf`
  line, the equivalence in `file_contexts.subs_dist`, and the commands to
  run on each system, which put the copies in place, label the chroot and
  re-copy a program whenever it is updated.
* **Standalone:** the module, a spec and a Makefile, packaged on its own like
  the other standalone modules. Installing the package labels the chroot
  and makes the copies; a trigger per program package refreshes its copy
  when that package is updated, so the copies get its fixes; removing it
  takes them away. Editing the module rewrites only the spec's marked
  wrapped-programs blocks.
* **Checks** in `selinux.checks`, rewritten with the module and run after
  every build:
  ```
  never ro_t may { execute read getattr } ro_someprog_real_exec_t:file
  never ro_t may { getattr search read } ro_protected_t:dir
  never login %chrootusers reaches someprog_t except through ro_someprog_t
  ```
  `except through` is new: a path into the domain that goes through the
  wrapper doesn't count, any other way in does. The reach check follows the
  logins as *Logins and Users* does (their SELinux user, roles, ways in), so
  it needs the logins; a check on the domain alone would count transitions
  the user's role can never take. (On CLIP, with `staff_r` as the user, it
  reports that staff logins may land in `sysadm_t`, which runs the
  program's domain directly.)

Reopening a module reads it back. Lines added to it by hand are kept, in a
*Local additions* section at the end.

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
* Logins (with the seusers and contexts files of the checked policy: the
  tree's `config/appconfig-<TYPE>`, or this host's for a standalone module):
  `only|never <users> may log in` (the SELinux users any seusers line maps
  to: `only staff_u user_u may log in`, `never unconfined_u may log in`);
  `never login <logins> maps to <users>`; `never login <logins> reaches
  <domains>` and `never login <logins> may <perms> <targets>[:<classes>]`
  (what a login's sessions can reach from where its ways in land, as in
  *Logins and Users*: domain transitions and role changes). Logins are
  Linux names (one without a line of its own gets `__default__`'s),
  `%group`, `__default__`, or `*` for every seusers line. A failure names
  the login, its user and the path (`alice (via __default__) → staff_u
  reaches sysadm_t: staff_t → newrole_t → sysadm_t`), with the seusers line
  and the steps as related locations.
* `only <names> may <perms> <targets>[:<classes>]`: nobody else may;
  `never <names> may …`: none of these may (`*` = every domain);
  `never <names> reaches <names> [except through <names>]`: no transition
  path (paths through the `except through` domains, e.g. a wrapper that is
  the only allowed way in, don't count; `never login … reaches` takes it
  too);
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
| `selinux.packaging.license` | `MIT` | The license the service editor starts with for a standalone module's RPM spec (SPDX expression); existing specs are left alone |
| `selinux.packaging.customLicenses` | `[]` | Your own licenses, offered in the service editor's License picker next to the common ones (filled by *Save to my list*) |

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

* Wrapped programs (`npm run test:wrapper-e2e`, melody, on copies of the
  CLIP, RHEL 9 and RHEL 10 trees): a chroot on the host; a program with a
  domain of its own and one without (`bin_t`) looked up (label, domain,
  package; the chroot's missing libraries and paths); the module, its
  `modules.conf` line, the equivalence and the checks written; the tree
  builds. In the compiled policy, the wrapper enters the original's domain
  through the copy, the user's domain may not execute it, and only the
  original domain is entered through it. The labels inside the chroot are
  as intended, and the checks that the user can't execute, read or stat the
  copies or the protected directory hold on all three. The login reach
  check reports the other ways in each policy offers: on RHEL, `user_u`'s
  sessions can also start the program's domain through `newrole_t` once
  that domain is in `user_r`.
  Then: read back, no-op, an edit that removes a program and keeps a
  hand-written line. Standalone: built against the devel headers, packaged,
  its scripts and trigger checked; adding a program changes only the spec's
  wrapped-programs blocks.
* File labels (`npm run test:filelabel-e2e`, melody): for 7,355 paths on
  the host (every kind of file, under `/usr`, `/etc`, `/var`, `/dev`,
  `/run`, home, plus missing paths as each kind and paths through linked
  and equivalent directories) the lookup agrees with `matchpathcon` on the
  running targeted policy, and for 2,452 of them on a CLIP build; the
  build's 3,002 lines sort exactly as refpolicy's `fc_sort.py` sorts them.
  CLIP: `/usr/bin/rpm` is `rpm_exec_t` from `admin/rpm.fc` line 16,
  `/usr/bin/rpmbuild` `bin_t`; `rpm_exec_t` starts `rpm_t` from `sysadm_t`,
  `init_t` and four more, traced to `rpm.te`. Running policy: `/bin/rpm` is
  looked up as `/usr/bin/rpm`, `/usr/lib64/x.so` as `/usr/lib/x.so`
  (`lib_t`), `shadow_t`'s rules include `passwd_t` writing it, and the type
  transitions in `var_run_t` include named ones.
* Standalone service modules as RPMs (`npm run test:package`, melody): in a
  workspace holding a copy of the CLIP tree, a new standalone service with
  runtime and log files, syslog and a port type of its own gets RHEL 9's
  `files_pid_file` / `_var_run_t` (the tree has `files_runtime_file`), its
  port type declared in the module, a spec and a Makefile, and no change to
  `modules.conf` or `corenetwork.te.in`; an interface only the tree has is
  refused. The module builds with the devel Makefile, `make rpm` builds
  `pkgsvc-selinux-1.0.0-1.el9.noarch.rpm` in ~2 s with the compressed policy
  package and its `.if`, scripts that load and unload it (`semodule`) and
  add and delete the port label, and `Requires: selinux-policy-targeted`; it
  reads back into the form as standalone, an edit changes only the `.te`,
  and the tree still builds as a tree.
* Denial assistant: audit records in raw, `ausearch -i`, kernel/journal and
  USER_AVC form, joined events, hex names and grouping (unit tests); on
  Rocky 9 against the running targeted policy: a file under `/var/www`
  labeled `user_home_t` is a wrong label, `httpd_t` connecting to
  `http_cache_port_t` asks for `httpd_can_network_relay`, reading
  `user_home_t` without a path for `httpd_read_user_content`, an allowed
  read is *Already allowed*, `default_t` a generic label, `chronyd_t`
  writing `etc_t` a missing rule; against a standalone module linked with
  the installed policy its own types are known, and against a CLIP tree
  build labels come from the tree's file contexts. Interface suggestions:
  a benchmark (`npm run test:denials-bench`) takes 1,500 top-level calls
  of other modules' interfaces in RHEL 9's daemon modules, turns the main
  rule each one grants into a denial (735 distinct) and asks for
  suggestions: the interface the module uses, or one granting no more, is
  first for 98% (exactly the original for 57%: often several grant the
  same), in the top 3 for 90%, top 5 for 98%. The e2e test checks
  suggestions with the devel headers, a linked module build and a CLIP
  tree build. Applying fixes (e2e on Rocky 9): `files_rw_etc_files` and an
  `optional_policy`-wrapped `apache_read_sys_content` written into a
  standalone module, a new `local_httpd` module for `httpd_t`, and
  `files_rw_etc_files` written into a copy of CLIP's `apache.te` all build,
  and the rebuilt policy then allows each denial; asking again reports the
  call as already there. Phase 4 (e2e on Rocky 9): `svirt_t` at s0:c1,c2
  reading an image at s0:c3,c4 is an MCS constraint (with `chcon -l`),
  `chronyd` running as `unconfined_service_t` is *Not running in
  chronyd_t*, `/usr/bin/true` there is *No policy for this program*; in a
  CLIP copy, a type added to `ntp.te` that no interface mentions gets
  `ntp_read_ntpd_extra_files` proposed, written into `ntp.if` and called
  from `apache.te` in `optional_policy`, and the rebuilt tree allows it.
  The practice module's four sample denials get their intended verdicts,
  and its HTTP fix resolves after a build (`npm run test:tutorial`).
* Service editor: every service domain in the Fedora tree (685 in 420
  modules; 25 web applications, 34 started only by D-Bus activation, inetd,
  cron or as a mail server, 175 declared by a template and 138 of those
  started by it) reads back into the form, and saving it unchanged leaves
  all files byte-identical; 35 kinds of edits on each (23,975; web content paths, file access under a boolean, the ways it is started, the login options, the login pty type and custom file access
  included) read back and repeat as a no-op. Earlier, on the main daemon
  domain of 326 modules: 26 kinds of edits on each (capabilities, file types added, removed or
  with another access level, paths, ports, system access, interfaces,
  permissive, program paths; booleans added, removed, with another default
  or description, grants added and removed, an existing boolean used;
  helpers added, removed, with other rights or file access) read back as
  the edited form and repeat as a no-op (8,476 edits); the 17 helper
  domains among them read back. On CLIP, RHEL 9 and RHEL 10, `xserver`'s
  `xdm_t` and `xserver_t` and `ssh`'s `sshd_t` each get a capability (one
  line changes), a new login service with the login options and a pty type
  of its own is created, and the tree builds and links; all read back. On CLIP, RHEL 9 and RHEL 10 a new service
  using every kind of setting (booleans, a port type and a helper program
  of its own included) builds and links with the full tree, with
  `portcon` entries for its port type and the transition into its helper,
  and so do an edited `ntp` (a new boolean, a new helper, a number added
  to `ntp_port_t`) and an edited
  `rsync` (its own boolean's default and grants); grants conditional
  policy can't hold, and port numbers another port type has, are refused
  before building. None of the 766 calls Fedora's daemons make under a
  boolean is refused. A standalone service with a port type and a helper
  of its own builds against the devel headers. The form itself is tested with a fake DOM; it hasn't had
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
* Logins and Users (test/logins-e2e.js on Rocky 9.8): the running targeted
  policy maps `root` and `__default__` to `unconfined_u` (noted; it runs
  unconfined and can load a policy); `staff_u` over ssh lands in `staff_t`
  or may choose `sysadm_r:sysadm_t`, and from `staff_t` reaches `sysadm_t`
  through `newrole_t` (role change by setexec, only while `secure_mode` is
  off); `user_u` reads `/etc/shadow` only as `chkpwd_t`; `guest_u` can't
  load a policy; `daemon` is a service account without a login. CLIP's
  tree build: `__default__ → staff_u` noted for its admin role, `staff_u`
  opens at its `gen_user` line, no host accounts. The webview is tested
  against a fake DOM.
* User editor (test/user-e2e.js on CLIP and on RHEL 9 with its spec): a new
  login user (ssh and console, sudo and the ssh client, may switch to
  sysadm_r, logins `alice` and `%opsgroup`) and a confined log-admin role
  entered from staff_r that staff_u gets; the tree builds and links, and
  the build's logins report shows the user with its roles and logins, ssh
  landing in its domain, sysadm_t reached through newrole, and staff_u
  reaching the new role's domain. On RHEL the gen_user lines go into the
  spec's `users-targeted` and the module into `modules-targeted-contrib.conf`.
  Editing staff (CLIP, RHEL 9, RHEL 10): a no-op edit changes no file; a
  capability, an admin program and console logins taken away change only
  those lines (staff.te, its contexts file and its token in
  `default_contexts`), the tree builds, staff reads back as edited and the
  build's logins report no longer lands staff_u in staff_t on the console.
  Standalone (CLIP workspace on Rocky 9.8): a new user with a login, a
  `%group`, ssh, sudo, a switch to sysadm_r and staff_u granted; the sudo
  call in RHEL's form; the module builds against the devel headers; `make
  rpm` gives an RPM whose scripts create and remove the user, logins and
  role grant and whose files include `contexts/users/sadev_u`; it reads back
  (logins and staff_u from the spec), a no-op edit changes nothing and an
  edit touches only the `.te` and its contexts file. Installing the RPM
  needs root and wasn't part of the test.
  Previews: a new automation user in the CLIP tree (ssh lands in its
  domain, roles with the narrow role it may switch to, 16 domains, ~9 s,
  nothing written), staff without sudo against the last build (77 domains,
  was 78, staff_sudo_t lost), a standalone user linked with RHEL's installed
  policy (switching to sysadm_r brings all six risky abilities).
  Survey (test/user-test.js with a tree): every user role module unchanged
  by a no-op edit (Fedora 11, CLIP 11, RHEL 9 12, RHEL 10 12) and every
  test edit read back as edited and idempotent (130, 126, 138, 141: role
  calls, switches, capabilities, interfaces, ways in, logins, granted
  users, booleans).
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
  above but haven't had interactive use yet. The tutorials (0.9.0) were
  checked in VS Code over Remote-SSH: the walkthrough pages render as
  intended.

## Limitations

**Wrapped programs**

* The editor labels your wrappers; it doesn't write them, and what they let
  through (arguments, environment) is up to them. A copy runs with the full
  privileges of the original program's domain, so a wrapper that passes
  everything on gives the user everything the program can do.
* What the copy needs in the chroot is listed, not set up: bind mounts and
  libraries are yours. The list comes from the file types the domain uses,
  so it can name paths the program never touches.
* Adding the program's domain to the users' role is what lets the wrapper
  start it; any other program the role may run that enters that domain is
  a way around the wrapper. The `never login … except through` check finds
  such paths.
* In a tree, the copies are made by the commands shown, on each system;
  only the standalone package keeps them up to date by itself.

**File labels**

* A tree build doesn't know the target system's users: home directory
  lines (`HOME_DIR`, `HOME_ROOT`, `%{USERID}`) are taken as `/home/<user>`,
  as `genhomedircon` writes them for ordinary users; other home roots and
  per-user prefixes aren't modelled. Installed policies use their real
  `file_contexts.homedirs`.
* Patterns are matched with JavaScript's regular expressions (PCRE syntax,
  POSIX classes like `[[:digit:]]` translated); the tests found no line
  that matches differently from `matchpathcon`, but an exotic pattern could.
* Rules are listed as written (for the type or one of its attributes), not
  per domain; dontaudit and neverallow rules aren't shown. Source statements
  can be traced for the workspace's build only.

**Logins and Users**

* Reach is what the policy permits, not what each program will do: a
  domain counts as reached when the user may run a program that enters it
  (`mount`, `passwd`, a container runtime), even if that program only does
  narrow things for ordinary users. Booleans are taken as possibly on.
* MLS/MCS constraints and levels aren't part of reach (the session's range
  limits which categories it sees, not which domains it enters); pam and
  sudoers settings aren't read (sudo rules decide who may run what as
  root; the policy decides which domain that runs in).
* A new tree user's role module is loadable, but its role is also declared
  in `kernel.te` (base), as the users file requires. The editor doesn't
  remove users or rename them, and a `gen_user` line written with `ifdef()`
  or more than once is edited by hand. A standalone user's logins, levels
  and granted users live in its spec's `%post` (written once, edited there);
  the spec's `semanage user -l` parsing assumes an MLS/MCS policy (targeted,
  mls).
* `semanage login`/`user` changes that aren't in the files under
  `/etc/selinux/<name>` (the merged `seusers` is) and user roles added with
  `semanage user` show up only through the installed policy, not a tree
  build. For a tree build, the target system's accounts aren't known.

**Denial assistant**

* Verification uses your build: a fix is resolved there once it builds;
  the host that logged the denial needs the module installed (and, for a
  tree, the policy) before the denial goes away. In a tree, a domain not
  declared in it can't be fixed from the panel.
* Suggestions consider interfaces with one argument (the domain); patterns
  that take a second type (file type transitions, `*_pattern` macros)
  aren't suggested, and pairs only when no single interface covers it. In a
  tree they need a build (its m4 output). A new interface for another
  standalone module can be written, but not verified: a standalone build
  is linked with the installed policy and that one module only.
* Labels are checked only for denials whose full path is known (a `path=`
  field, or PATH records of the same event, which need syscall auditing);
  with only `name=` the label check is skipped. Commands are meant for the
  host that logged the denials.
* *Not in its domain* needs the program's path (the SYSCALL record's
  `exe`). Constraints are evaluated for `constrain` / `mlsconstrain`
  (not `validatetrans`).

**Tutorials**

* The practice module's `sample-denials.log` is checked against the
  module's build: build it first (save `notesd.te`).
* The line under a walkthrough saying that Code collects usage data is VS
  Code's own telemetry notice, not this extension's (it collects nothing);
  it goes away with `"telemetry.telemetryLevel": "off"` in your user
  settings.
* The walkthroughs' pages render in VS Code's Welcome editor; the practice
  module's build and checks steps need a Linux host with
  `selinux-policy-devel` (and an installed policy for the checks).

**Service editor**

* Standalone modules in a tree workspace target the devel headers of the
  build host (RHEL 9 on melody when tested); to package for another release,
  build on a host with that release's `selinux-policy-devel`. Port number
  conflicts are checked against the tree, not the target policy. The
  property checks and the Compiled Policy view still show the tree.
* Find by need and ▸ need the policy's m4 output: in a tree, a build;
  standalone, the devel headers. Find by need offers interfaces that take
  just the domain.
* Services and web applications only: a domain started by init, D-Bus
  activation, inetd, cron or as a mail server, directly or through a
  template of its module, or the script domain of `apache_content_template`
  (see *Editing an existing service*, *Web applications*). User applications
  (`application_domain`) are edited in the `.te` as before. What
  `apache_content_template` grants and declares is fixed by the template.
  For template-declared daemons, types and rules inside the
  template (often its runtime and log types) aren't in the form. Big
  daemons such as sshd, xdm or the X server still list many interfaces
  under *Other interfaces* (no option describes them) and keep the rules
  of the module's other domains and those in `ifdef` blocks as they are.
* Helpers: started by the service only (not by init or by users), with
  rights at the top level (not under a boolean); access to the service's
  file types, not file types of their own (give the service a type with
  "label only" access and the helper the access). A helper started by
  another helper, or declared through a template, isn't recognized and
  stays under *Kept as is*; rules between the helper and the service
  (sockets, pipes beyond `domtrans_pattern`) are written in the `.te`.
* Port types: a port type can't be removed or renamed from the form once
  it is in `corenetwork.te.in` (other modules may use it); only port types
  named after the module are shown as its own. A standalone module's port
  numbers aren't in the policy at all: run the `semanage port -a` commands
  it lists after installing.
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
