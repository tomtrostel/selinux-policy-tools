# Changelog

## 0.17.0 (2026-10-22)

**Added**

* **Check Login Contexts** (*SELinux: Check Login Contexts…*, and
  diagnostics after every tree build): finds the logins that would fail
  with "Unable to get valid context for <user>" although the policy
  compiles.
  * For every seusers line and every way in (ssh, console, graphical,
    cron, systemd user sessions, …), it picks the context libselinux would
    pick: 3.x (RHEL 9, 10) and 2.x (RHEL 8), which can differ.
  * Each problem comes with its reason: a missing user, role or type, a
    range outside the user's, no transition from the login program (rule,
    boolean or constraint), or the failsafe as the only way in.
  * For a tree build the problems land on the seusers and contexts file
    lines, and update when those files change.
  * Found in CLIP: users' crontabs can't run in CLIP RHEL 9, and in CLIP
    RHEL 8 they would stop working after an upgrade to RHEL 9 (README,
    Findings).
* **Check Context Files** (*SELinux: Check Context Files…*, and
  diagnostics after every tree build, also one where `make validate`
  failed): every other place the configuration names a context.
  * `file_contexts`: invalid contexts and duplicate paths, on the module's
    `.fc` line (both make `make validate` and semodule fail).
  * `file_contexts.local` of this host: a stale line makes every semodule
    and semanage change fail.
  * Home directories as genhomedircon writes them per user (prefix, role,
    level): the lines it would silently leave out.
  * File-context types restorecon can't apply (not file types).
  * `default_type`, `failsafe_context`, `initrc_context`, `x_contexts`,
    `dbus_contexts`, `lxc_contexts`, `openssh_contexts` and the other
    context files, each with what its reader does with a bad entry.
  * Found in CLIP RHEL 8: 13 home-directory types of `gnome` and
    `telepathy` are file types only through the `xdg` module, which is off,
    so restorecon can't apply them (README, Findings).

**Changed**

* Tutorials: a lockdown step "Contexts that won't load" for both checks.
* User editor: an existing user's kind can be changed (for example from
  restricted desktop user to restricted terminal user). Only its template
  call is replaced.
* User editor: kinds whose template can't link in this build are disabled
  and say why. A desktop user needs `xdm_t`, so on a tree whose build turns
  `xserver` off, linking failed with "global requirements were not met:
  type/attribute xdm_t".

**Fixed** (found by testing on Rocky 8.10 with RHEL 8's own tools)

* On RHEL 8, file labels from a build or a standalone module could be
  wrong. RHEL 8's `semodule` (libsemanage 2.9) puts the one of two equally
  specific file-context lines limited to a file kind first; RHEL 9 and
  refpolicy's `fc_sort.py` put it last. File Labels and the denial
  assistant now follow the host's order.
* On RHEL 8, the denial assistant, finding interfaces by path and "can it
  …?" in Logins and Users found no label for files whose type the running
  policy lacks (e.g. CLIP's `systemd_unit_t`): RHEL 8's `matchpathcon -f`
  refuses such files. They now look labels up the way File Labels does.

## 0.16.0 (2026-10-14)

**Added**

* **Compare Host's Local Changes** (*SELinux: Compare Host's Local
  Changes…*): what `semanage` and `semodule -i` changed on a host, read
  with sudo in a terminal, without sudo (partly), or from another host's
  export.
  * Each change is compared with your build or an installed policy: only
    on the host, overrides your policy, already in it, same as the
    default, or not in your policy. Risky changes are flagged.
  * For a tree, a change can be written into the source: file contexts
    (an override edits the policy's own line), ports (an override moves the
    number), booleans, logins, equivalences, modules turned off.
* **Tutorial:** a "Compare with a host's local changes" step in the
  lockdown walkthrough.
* **Levels and Categories** (*SELinux: Levels and Categories…*), for
  MLS/MCS policies:
  * *Can it access?* takes two full contexts (or a file's label), a class
    and permissions. It says whether the source context is valid, gives
    the type rules, and lists every constraint with its comparisons in
    plain words.
  * *Who ignores levels* groups the domains by the level constraints they
    pass whatever the levels, and why (e.g. not in
    `mcs_constrained_type`), with *Add check*.
  * The denial assistant opens constraint denials there.
* **`only|never <domains> may ignore levels [on <classes>]`** in
  `selinux.checks`.
* **Kept apart by levels?** (in Levels and Categories) and **`require
  <domains> isolated by levels [on <classes>] [weight N]`**: a domain's
  accesses to objects two of its processes can share that no level
  constraint checks. On RHEL 9 targeted, `container_t` has 48 such
  accesses, e.g. `connectto` on another container's unix socket.
* **Level names** from `setrans.conf` in the context check, File Labels,
  Logins and Users, and on hover over levels in the sources.
* **Range transitions** in the transition graph (purple edges) and in File
  Labels ("Running it starts … at s0-s0:c0.c1023").
* **User editor:** the level and range the user will have, with names and
  problems, and quick choices (no, all, some categories). In an MCS tree it
  says that `gen_user` ignores its level and range arguments; only the
  categories count.

**Fixed**

* `never X reaches Y except through Z` ignored the `except through` part
  (0.15.0; `never login … reaches … except through` was right).
* Tree builds: an edit to `booleans.conf`, or to the flask files, had no
  effect until a clean build. refpolicy's `tmp/generated_definitions.conf`
  rule has no prerequisites, so it was never remade; the build now removes
  it when those files change.

**Docs and tests**

* README and tutorials cover the newer features (file labels, the
  features menu, the user editor, wrapped programs, levels, CLIP specs),
  with new lockdown steps for levels and categories and for wrapped
  programs, and a labels/logins/levels section in the practice module.
* A **Findings** section in the README: MCS in CLIP RHEL 8 vs RHEL 9 (RHEL 8
  binds every domain to its categories; RHEL 9 binds none), what restoring
  it would take, and the gaps in `container_t`'s isolation on RHEL 9.
* Unit tests for the diagnostics, the checks language, build output
  parsing, rule tracing, the Python policy helper (against a fake setools)
  and client pieces; the LSP test now asserts. `npm run test:clip-all` runs
  every tree test on CLIP RHEL 8 and RHEL 9 plus a diagnostics survey
  against reviewed findings.

## 0.15.0 (2026-10-13)

**Added**

* **Wrapped programs** (*SELinux: New Wrapped Programs…* / *Edit Wrapped
  Programs…*): users whose sessions run in a chroot run programs only
  through wrappers. Each wrapper is a domain of its own and the only one
  that may run its program's protected copy, kept in a directory the users
  can't list. The copy runs in the original program's domain, with its
  privileges: the rules on the program's own file are copied, and the role
  gets the domains it starts. Programs are looked up by path (label,
  domain, package, and what the copy will miss in the chroot); the chroot
  can be labeled like / (an equivalence). Writes a tree module (with
  `file_contexts.subs_dist` and the setup commands for each system) or a
  standalone module packaged on its own, which makes the copies when
  installed and refreshes them when their packages update. Adds checks to
  `selinux.checks`. Modules are read back with hand edits kept.
* **`… reaches <domains> except through <domains>`** in `selinux.checks`,
  for `never <names> reaches` and `never login <logins> reaches`: paths
  through the given domains don't count.
* **CLIP for RHEL 8**: *Configure Build from Spec File…* now reads CLIP's
  spec (`%installCmds`) and the Makefile next to it (`SEPARATE_PKGS` →
  `APPS_MODS`), for both the RHEL 8 and RHEL 9 branches. All tools were
  tested on CLIP's `RHEL8` branch (refpolicy 2.20200229).

**Fixed**

* File labels: a directory made equivalent to `/` (`semanage fcontext -e /
  DIR`) looked paths up as `//etc/…` instead of `/etc/…`.
* Wrapped programs form: changing the wrapper or protected directory (or
  the module name) didn't update the paths and type names shown in the
  program cards.

## 0.14.0 (2026-10-13)

**Added**

* **File labels** (*SELinux: Look Up File Label…*, or *SELinux → Look Up
  File Label* on any file in the explorer or editor): for any path on the
  system, the label each policy gives it (installed policies and the
  workspace's build side by side) and the file-context line that sets it,
  traced to its `.fc` source line and module, with the lines that also
  match and lose; what the file is labeled now, its package, link target,
  and what `restorecon` would change; and what the policy lets happen to
  that type: who may access it (rules as written, strongest first, traced
  to their source for the build), the domains a program starts and from
  where (or that it runs in its caller's domain, with *Confine it: New
  Service…*), and the type transitions that create it.
* **All features in one menu** (*SELinux: All Features…*): from the
  SELinux status bar item, the Policy Explorer's title bar, or the new
  *SELinux* submenu in the explorer's and editor's right-click menus.
  Grouped by purpose, each feature with a one-line description.

**Fixed**

* File-context lookups on a tree build (denial assistant, "can it …?" in
  Logins and Users) used the build's `.fc` output unsorted, so a general
  line could win over a specific one (CLIP: `/usr/bin/rpmbuild` came out
  `usr_t` instead of `bin_t`). They are now sorted as `semodule` sorts
  them, with the tree's `file_contexts.subs_dist`; a standalone module's
  lines are sorted together with the running policy's.
* The domains a login reaches were attributed to a role picked in a random
  order when several of the user's roles could run them (e.g. `sysadm_t`
  as `system_r` instead of `sysadm_r` for `staff_u`); the same role, then
  the role named like the domain, now come first.

## 0.13.0 (2026-10-13)

**Added**

* **Login checks in `selinux.checks`**: `only|never <users> may log in`
  (the SELinux users seusers maps logins to), `never login <logins> maps
  to <users>`, `never login <logins> reaches <domains>` and `never login
  <logins> may <perms> <targets>[:<classes>]` (from where the login's ways
  in land, through domain transitions and role changes, as in Logins and
  Users). Logins: names (falling back to `__default__`), `%group`,
  `__default__`, `*`. Evaluated with the tree's seusers and contexts files
  (a standalone module: this host's) after every build and on edits;
  failures name the login, its user and the path, with the seusers line
  and each step as related locations. Completion offers the seusers logins.

## 0.12.0 (2026-10-12)

**Added**

* **Logins and Users** (*SELinux: Logins and Users…*, person icon in the
  Policy Explorer): who logs in as which SELinux user and what their
  sessions can reach, for this host's installed policy or the workspace's
  last build. Linux logins from `seusers` (`%group` and `__default__`
  lines, with notes for `unconfined_u` and for `__default__` on a user with
  an admin role); per SELinux user the ways in (ssh, console, cron, …) from
  `default_contexts` and its own contexts file, every domain reachable by
  running programs and changing role (role allow, role_transition or
  setexec, checked against the policy's constraints), risky abilities
  within reach with the path and the rule (unconfined, loading a policy,
  permissive mode, `/etc/shadow`, raw disks, booleans), and a "can it …?"
  question for a path or type. On the running policy also people's and
  service accounts from `/etc/passwd` with the seusers line that applies.
  The lockdown walkthrough's users page covers it.
* **User editor** (*SELinux: New User…*): a form for a new SELinux user in
  a tree: the kind (ordinary, restricted, administrator, or a confined
  administrator role entered from another role), Linux logins and ranges,
  the ways in (ssh, console, graphical, cron), roles it may switch to and
  roles that may switch to it, users who also get the role, sudo / su /
  ssh role templates, services it administers and applications it runs
  (role interfaces with arguments filled by their parameter names, in both
  Fedora's and upstream's forms), extra rights, levels and home prefix.
  It writes the role module, the gen_user line (into the spec's users file
  on RHEL), the role in kernel.te, seusers, the user's contexts file and
  modules.conf, with a preview of each.
  *SELinux: Edit User…* opens existing role modules (staff, sysadm, user,
  guest, the confined admin roles, …) read back from the module, its
  gen_user line, seusers and contexts, and edits only what changed: a way in
  turned off also takes the user's context off that line in
  `default_contexts`; gen_user lines written with ifdef are left alone.
  Standalone users: a new user can be a module of its own built against
  the host's devel headers (role calls in their form), packaged with a spec
  whose `%post` creates the SELinux user, its logins and role grants with
  semanage and installs its contexts file (`%postun` removes them);
  reopened, it reads back from the module, contexts file and spec.
  *Start from → Automation account* (ssh and cron only, sudo into one
  narrow role, with the sudoers line to add) and *Preview what it can
  reach*: the policy built with the planned files in a scratch copy (or the
  standalone module linked with the installed policy) shows where the
  logins land, what they reach, the risky abilities, and for an existing
  user what the change adds or takes away.

**Fixed**

* Service and user editor: removing a call from an `optional_policy` that
  also held only a nested `optional_policy` (or comments) left a block the
  compiler refuses ("This block has no require section"); such a block is
  now removed with it (found removing sudo from RHEL's staff.te).

## 0.11.0 (2026-10-12)

**Added**

* **Service editor: file access under a boolean.** Each boolean card lists
  the service's file types with a level that applies only while the boolean
  is on, next to what is always allowed (e.g. configuration read only
  always, create/change/delete when `myd_write_config` is on). The level's
  patterns go into the boolean's `tunable_policy` block, with the type
  transition (e.g. `files_var_lib_filetrans`) when the always-on level has
  none, since the same type rule both always and under a boolean fails the
  build. Existing modules read back the same way: patterns on one of the
  service's file types inside a plain `tunable_policy` block are that
  boolean's level, and other rules on the type in the block go with it;
  rules that match no level stay kept as written. A level the service
  always has anyway is noted.
* **Service editor: services not started by init.** Modules whose service
  is started by D-Bus activation (`dbus_system_domain`: accountsd, colord,
  geoclue, …), inetd/xinetd (`inetd_service_domain` and its TCP/UDP
  variants: comsat, tcpd, dbskk; `ucspitcp_service_domain`), cron
  (`cron_system_entry`: certwatch, backup, tripwire, …) or as a mail server
  (`mta_mailserver`, `mta_sendmail_mailserver`) now open in the editor, also
  when that call is in `optional_policy` (Fedora: 523 service domains in 397
  modules, was 488 in 376). A new **Started by** row chooses systemd,
  systemd as a mail server or inetd, and adds D-Bus activation and cron as
  further ways (in `optional_policy`). A main way whose module is off in
  the tree (inetd in CLIP) is shown but refused, since it would fail to link.
* **Service editor: daemons a template declares and starts.** Domains that
  a template of their module declares and starts (`rpc_domain_template(nfsd)`,
  `systemd_domain_template(systemd_logind)`, rhcs, courier, milter, condor,
  zarafa, …) are found by following the template's body to its start call,
  and open in the editor with the template call as their declaration and
  start (Fedora: 660 service domains in 414 modules; RHEL 10: 129 such
  domains). The template call and what it declares stay as written.
* **Service editor: web applications.** Modules built on
  `apache_content_template` (bugzilla, mediawiki, awstats, the CGI parts of
  collectd, git, munin, Apache's own `httpd_sys_script_t`, …) open as web
  applications: the script domain, its **CGI scripts** paths and a **Web
  content** section with the template's content types (read, read/write,
  append-only, `.htaccess`) and their `.fc` paths, with the rest of the form
  editing the script domain's rules (Fedora: 25 web applications; type
  names from the template, so `NAME_script_t` in Fedora/RHEL and
  `httpd_NAME_script_t` upstream). New modules can be web applications
  (*What*: Web application), refused when the apache module is off.
* Paths in the service editor keep a file type flag the path doesn't imply
  (`/usr/share/bugzilla/ -d`), and one path for directories (`-d`) and for
  files (`--`) is no longer reported as two labels for one path.
* **Tutorials**: a new *Web applications (CGI scripts)* page in the service
  walkthrough; the other service pages cover *What*, *Started by*, file
  access under a boolean, custom file access, path flags and which modules
  the editor opens.

**Fixes**

* Service editor: an existing port type without port numbers (CLIP's
  `milter_port_t`) no longer blocks saving the module that owns it.

## 0.10.2 (2026-10-11)

**Fixes**

* **Build from a panel or a non-policy file** (e.g. *Build the policy* in the
  Compiled Policy view while the service editor has the focus, in a workspace
  whose tree is a subfolder such as a CLIP clone): refused with "This file is
  outside the policy tree". Anything that isn't in a tree or module now builds
  the active tree (a file of another tree is still refused, saying to switch
  trees); the views' build buttons always build the tree, and the service
  editor offers **Build now** where a build is missing.
* **Service editor, file access**: a file type whose rules match none of the
  access levels (e.g. `mmap_manage_files_pattern`, plain `allow` rules, a
  type transition of its own) read back as "label only (no access)", and
  choosing a level silently replaced those rules. It now reads back as
  **custom (kept as written)** with the rules shown, and choosing a level
  warns that they will be replaced; each rule opens in the `.te` with a click,
  shows what it compiles to (▸), and **Show what they allow** sums them up
  per class. In the Fedora tree 313 file types were
  affected (CLIP's `httpd_cache_t` among them). The login pty option is
  refused when its type is already a file type of the module.

**Changed**

* **Long lists of other interfaces** (service editor, more than 12): grouped
  by module, collapsible, with counts, a filter that narrows them as you
  type, and Expand all / Collapse all (`xdm_t` on RHEL 9: 255 interfaces in
  70 modules).

## 0.10.1 (2026-10-11)

**Changed**

* **Read-only denials**: an interface that would also let the domain write,
  create, delete or run things now ranks below read-only ones (tagged
  *writes*), unless the read-only one covers a far larger set of types.
  Reading `user_home_t` now suggests `userdom_read_user_home_content_files`
  first.
* **Keyword search for interfaces** (service editor): ranked by name parts,
  the types an interface requires, module and summary, with a few
  synonyms; widely used interfaces first among equals, `dontaudit` and
  rarely needed ones last; 25 results at a time with more on demand;
  interfaces that take a type instead of a domain are no longer offered.

## 0.10.0 (2026-10-11)

**New**

* **Service editor: finding interfaces**: *Find by need* in *Other
  interfaces* (a type or path, the kind of object, what to do with it) lists
  the interfaces that grant it, narrowest first, with what else each
  grants; **▸** on any interface shows the rules it really compiles to.
* **Service editor: more services, login services**: modules whose
  domains are started by `init_system_domain`, `init_domain` or a ranged
  variant open too (on RHEL 9 51 more, e.g. `xserver`, `dbus`, `getty`),
  keeping how init starts them; domains declared by a template
  (`ssh_server_template(sshd)`) read back. A **Logins** group (log users
  in, start their sessions, login records, session contexts, terminals) and
  a pty type of its own for logins. Paths under `HOME_DIR/` are accepted.
* **Standalone service modules, packaged as RPMs**: in a tree workspace,
  *SELinux: New Service…* can make a **Standalone module (packaged as an
  RPM)** instead of a tree module: built against the host's
  `selinux-policy-devel` headers (their interfaces and helper variants),
  port types declared in the module, nothing added to the tree. It comes
  with `<name>-selinux.spec` (an independent package following Fedora's
  SELinux packaging guidelines: install/uninstall/relabel macros, port
  labels) and a Makefile; a **License** picker offers common open source
  licenses, your saved ones, or a custom one you can save to your list or
  as your default (`selinux.packaging.customLicenses`,
  `selinux.packaging.license`, default MIT); **SELinux: Build RPM** builds the package. Module
  folders next to a tree now build with the devel Makefile.
* **Denial assistant** (*SELinux: Analyze Denials…*): paste audit records,
  open a log, or read them from the host (`ausearch` with sudo in a
  terminal). Denials are grouped and each group gets a verdict: wrong label
  (fix: `restorecon`), allowed under a boolean that is off (fix:
  `setsebool -P`), already allowed, generic label, or missing rule,
  checked against the running policy (current boolean values), another
  installed one, or the workspace's last build.
* **Interface suggestions** for a missing rule: the interfaces that grant
  it, narrowest first, each with what else it grants, worked out from what
  each one really expands to (m4 with the policy's own Makefile) and the
  compiled policy. A plain rule is suggested when both types are the
  domain's own.
* **Denial assistant, more cases**: a service that isn't in its domain
  (running as `unconfined_service_t`, `init_t`, … while its program has a
  domain of its own: relabel, or start it right; or no policy at all:
  *New Service…* with the program filled in); denials by constraints (MCS/MLS
  levels, UBAC users, roles) explained with the failing comparisons; pairs
  of interfaces when no single one covers the denial; a new interface for
  the module that owns the type when none grants it. The practice module
  has sample denials, opened from the *Fix a denial* tutorial.
* **Applying the fix**: *Add to module…* shows the exact insertion (file,
  line, text; `optional_policy` when the interface's module can be off),
  *Apply* writes it and saves, and after the build the denial is checked
  again against it (*Resolved*). Domains of the installed policy get a
  small local module in a standalone workspace.

**Fixes**

* Paths under `HOME_DIR/` (as in RHEL's `xserver.fc`) were refused as not
  absolute by the service editor.
* RHEL tree builds write no combined file contexts file, so label checks
  used the host's file contexts; the tree's `base.fc` and modules' `.mod.fc`
  are combined now.

**Tests**: `npm run test:denials` (in `npm test`), `npm run
test:denials-e2e` (melody: installed policy, standalone module, CLIP tree),
`npm run test:denials-bench` (melody: suggestions for 735 denials made
from RHEL 9 modules' own interface calls), `npm run test:package` (melody:
a standalone service from a CLIP workspace, built and packaged as an RPM).

## 0.9.0 (2026-10-11)

**New**

* **Service editor** (*SELinux: New Service…*, *SELinux: Edit Service…*,
  **+** and *Edit Service* in the Policy Explorer): a form for a system
  service's policy (the daemon's program, the files it owns with paths and
  access levels, ports it listens on and connects to, system access in
  plain words, capabilities, other interfaces, the interfaces its `.if`
  offers) with a live preview, writing the `.te`, `.if`, `.fc` and the
  `modules.conf` line in the tree's own conventions. Existing service
  modules open in the same form; only the lines of changed settings are
  edited, everything else is kept and listed.
* **Booleans in the service editor**: new tunables (name, description,
  default) or existing booleans, each with what it allows while on
  (system access, process rights, capabilities, ports, interfaces),
  written as `gen_tunable` + `tunable_policy` (`optional_policy` outside
  for calls into modules that can be off). Booleans of existing modules
  are read back and edited in place. Grants that conditional policy can't
  hold (interfaces declaring attributes or containing `optional` blocks,
  e.g. `dbus_system_bus_client`) or that are already always allowed are
  refused before building.
* **New port types in the service editor**: *+ New port type* in Network
  for port numbers no existing type covers. In a tree it adds a
  `network_port()` line to `corenetwork.te.in`, and the module uses the
  generated `corenet_*` interfaces; port types named after the module are
  editable when the module is opened again. A standalone module declares
  the type itself and lists the `semanage port -a` commands to run after
  installing. Numbers another port type already has are refused.
* **Tutorials**: four walkthroughs on the Welcome page (*SELinux: Open
  Tutorials*): getting started, writing and maintaining a service policy,
  fixing a denial, and reviewing and locking down a policy, with buttons for
  the commands each step describes. *SELinux: Create Practice Module…*
  sets up a small module with four deliberate mistakes to fix along the way.
* **Helper programs in the service editor**: *+ New helper program* gives
  a program the service starts a domain of its own (`domain_type`,
  `domain_entry_file`, `domtrans_pattern` from the service) with only the
  rights chosen for it: access to the service's file types, system access,
  process rights, capabilities, ports, interfaces, and whether the service
  may signal it. Existing helpers (e.g. `lsmd_plugin_t`) read back and are
  edited in place; removing one that is still used elsewhere is refused.
  A path labeled for two types is refused before building.
* **Hover help in the service editor**: every option, add button (*+
  Temporary files*, *+ Add port*, *+ New boolean*, …) and field explains
  what it does when you hover over it, including the type it adds.

**Fixes**

* Service editor, upstream refpolicy trees (CLIP): connecting to a
  specific UDP port was refused ("No udp port type"), because upstream
  generates no per-port UDP send interface. It is now written as the
  generic UDP rules plus the port's client packets, and read back.

**Tests**: `npm run test:service` (in `npm test`; with a policy dir, every
daemon module in it), `npm run test:service-e2e` (real builds on CLIP,
RHEL 9/10 and a standalone module).

## 0.8.0 (2026-10-10)

ifdef decisions on names that aren't build flags; the .te require check in
trees without modules.conf.

**New**

* **`ifdef` on names that aren't build flags is decided**: interface
  names, `define()`d names and names nothing defines are decided from the
  sources, in the order refpolicy feeds files to m4. Branches on names
  nothing defines (`TODO`, `targeted_policy`, the misspelled `enabled_mls`
  in RHEL's init.te) are dimmed; `ifdef(`some_interface', …)` counts as
  compiled. Hovering the name in an `ifdef` shows which branch is
  compiled and why. Dynamically defined names stay undecided (9 branches
  on RHEL and CLIP, down from 85 and 12).

* **`.te` require check in trees without `modules.conf`** (a bare
  upstream refpolicy checkout): modules are checked the way `make conf`
  would set them up (base when the `.if` says `<required val="true">`,
  otherwise loadable). With `MONOLITHIC=y` nothing is checked, since no
  module is loadable.

**Tests**: `test/ifdef-names-test.js` (in `npm test`), `npm run
test:confdefaults` (upstream refpolicy without modules.conf).

## 0.7.0 (2026-10-04)

Several policy trees in one workspace.

**New**

* **Several policy trees in one workspace**: the extension works on one
  tree at a time (indexed, built, shown in the views; named in the status
  bar), switches when you open a file of another tree (or with *SELinux:
  Select Policy Tree…*), and remembers the choice. Each tree has its own
  build settings in the new `selinux.build.trees` setting (*Configure
  Build from Spec File…* writes there when there are several trees) and
  keeps its own build results. Previously all trees were merged into one
  index and the first one found was built. New settings:
  `selinux.build.trees`, `selinux.tree.autoSwitch`; new command *SELinux:
  Select Policy Tree…* (also on the status bar item).

**Tests**: `npm run test:multi` (CLIP and RHEL 10 in one workspace).

## 0.6.0 (2026-10-04)

Catching link failures and port mistakes before you build, booleans in the
`.te` require check, `ifelse` in templates, and every build variant
verified.

**New**

* **Link failures before you build**: in a tree, a loadable module that
  needs a type outside `optional_policy` which only modules turned off in
  `modules.conf` declare (or that no module in the tree declares) is
  flagged where the requirement comes from (the require entry or the
  interface call), for all modules at once and as soon as `modules.conf`
  is saved. `semodule_link` reports one module per build and no line.
  Build-reported link errors are placed the same way (previously: the first
  mention of the type anywhere).
* **`corenetwork.te.in`**: build errors in the generated `corenetwork.te`
  are shown on the `.te.in` line they come from; duplicate-port errors,
  which checkpolicy reports against an unrelated file, land on the
  duplicate declaration. New checks while typing: ports outside 0–65535,
  backwards ranges, unknown protocols, ports declared twice.
* **Booleans in the `.te` require check**: a boolean from another module
  (or the global tunables) tested in an `if (...)` statement without
  `require { bool …; }` is flagged, with a quick fix. Booleans in
  `tunable_policy` need none (the macro requires them), also when an
  interface passes one in.
* **`ifelse` in templates** is decided per call when it compares plain
  values (e.g. the user templates' ``ifelse(`$1',`unconfined', …)``), so
  template expansion no longer generates names from branches that don't
  apply, and the require analysis follows the right branch.
* **Template-generated booleans** (``gen_tunable(`$1_exec_content', …)``,
  e.g. `staff_exec_content`) are indexed: definition, hover, completion.
* **All build variants verified**: RHEL 9 and RHEL 10 targeted, minimum,
  mls and automotive, and monolithic builds (upstream refpolicy).

**Fixes**

* Trees without `policy/modules.conf` (upstream refpolicy) failed to build
  ("No enabled modules!"); the scratch copy now gets one from `make conf`.
* Scripts in the scratch copy lost their execute bit, which broke trees
  whose Makefile runs them directly (upstream refpolicy's
  `support/gentemplates.sh`).

**Tests**: `npm run test:mono` (monolithic build of upstream refpolicy),
`npm run test:ifelse` (part of `npm test`), and the survey's `--modules` /
`--loadable` options.

## 0.5.0 (2026-10-04)

RHEL 10 support and a check for missing requires in `.te` files.

**New**

* **RHEL 10**: *Configure Build from Spec File…* understands the RHEL 10
  spec layout (`booleans.conf`, `users` and `modules.conf` from the tree's
  `dist/`, `modules.conf` filtered with the spec's module lists). A
  `selinux.build.tree.files` source can now be `{ "from": …, "disable":
  [list files] }` for that. Verified with the RHEL 10.2 source (targeted,
  mls and minimum builds), which also builds with RHEL 9's tools.
* **Missing requires in `.te` files**: in loadable modules (standalone
  modules, or `module` in `modules.conf` / `APPS_MODS`), a type or
  attribute from another module used without a require in its scope (the
  top level or the enclosing `optional_policy` block) is a warning, with
  a quick fix that adds it to a require block in that scope. Requires
  that interfaces called in the scope bring in count, as they do for
  checkmodule. No findings on the Fedora, RHEL 9, RHEL 10 and CLIP trees.
* `test/diag-survey.js` takes `--modules <modules.conf>` (and `--loadable`)
  to include the `.te` require check.

## 0.4.0 (2026-10-04)

Deeper property checks, checks for standalone modules, and comparing the
compiled policy with any version or with the installed policy.

**New**

* **Information-flow checks**: `never shadow_t flows to user_t [except
  passwd_t …] [weight N]` in `selinux.checks` fails if data can move from
  one type to another through any chain of domains and objects (reads and
  writes, setools' permission map). The failure shows the shortest path,
  each step traced to the statement that grants it; `except` lists types
  trusted to pass the data on.
* **Property checks for standalone modules**: in a module directory, the
  module is linked with the host's installed policy after each build
  (decompiled kernel policy + module, compiled with `semodule -p`, no root
  needed), and `selinux.checks` at the workspace folder is checked against
  it. The Compiled Policy view shows that linked policy too.
* **Compare Compiled Policy with…**: compare the working tree's build with
  any tag, branch, commit or typed ref, compare two refs with each other
  (e.g. two release tags), or compare with a saved build directory;
  changes are traced into the matching version's sources.
* **Compare Build with Installed Policy**: rebuilds the tree with
  `semodule` (CIL) into a scratch store, the way an installed system is
  built, and shows in the Changes view what installing it would add (traced
  to source) or remove compared with `/etc/selinux/<name>/policy`.

**Fixes**

* Two VS Code windows on the same tree no longer share scratch build
  directories: each language server builds in its own area
  (`/tmp/selinux-policy-tools-<uid>/<pid>/`), so builds can't interfere and
  closing one window no longer deletes the other's builds. Areas left by
  crashed servers are cleaned up at the next start.
* In checks, `{ read }` now means only the `read` permission; previously
  braces still expanded the `read` group (read, open, map).

## 0.3.0 (2026-10-04)

Lockdown workflows (full policy source trees, Linux).

**New**

* **Module Preview** (*SELinux: Preview Turning a Module Off/On…*, also on
  Policy Explorer modules): builds the tree with one module flipped in
  `modules.conf` in a separate scratch copy and shows link errors, the
  `optional_policy` blocks in other modules that drop out (or come alive),
  and the resulting rule, type, role and user changes traced to source.
  *Apply* edits the `modules.conf` line (and can drop the module from
  `APPS_MODS`).
* **Domain transition graph** (*SELinux: Show Domain Transition Graph*):
  interactive graph of the last build's domain transitions from any domain,
  or who can enter it; automatic, explicit (`setexec`), dynamic and
  boolean-controlled transitions, entrypoints on hover, click through to
  source.
* **Property checks**: assertions in `selinux.checks` at the tree root
  (`only … may write …`, `never … may …`, `never X reaches Y`,
  `require … may …`, `only|never <roles> may run <types>`,
  `only|never <users> may use <roles>`) checked after every build and on
  save; failures in the Problems panel with links to the source lines that
  cause them, ✓/✗ above each check, status bar summary.
* **Users and roles**: `gen_user` validation (undeclared roles, MLS/MCS
  levels and categories outside what the build defines, high below low,
  duplicate users); roles, role switching, role transitions, users and
  their Linux logins (`seusers`) in the Compiled Policy view; hover and
  completion for users, roles and MLS macros.
* New settings: `selinux.checks.file`, `selinux.diagnostics.users`.

**Fixed**

* Builds after changing the set of enabled modules (`modules.conf`,
  `APPS_MODS`): refpolicy's Makefile kept stale outputs (validation failed
  on removed modules' file contexts, old packages were exported).
* Link errors are placed on the interface call that brings in the missing
  requirement, not the module's first line.

**Note:** the features above are covered by automated tests on Rocky 9
(CLIP for RHEL 9 and the RHEL 9 targeted policy) but have had little
interactive use in VS Code yet. Please report anything that looks off.

## 0.2.0 (2026-10-04)

First published release.

**Source navigation and authoring**

* Go to definition, find references, hover docs, completion (interfaces
  as snippets, context-aware classes and permissions), signature help,
  outline and workspace symbols for refpolicy-style policy source,
  including names generated by templates.
* Diagnostics with quick fixes: unknown interfaces, unknown classes and
  permissions, missing `gen_require` entries, unbalanced syntax. No false
  warnings on the Fedora, RHEL 9 and CLIP RHEL 9 trees.
* `ifdef`/`ifndef` on m4 build flags (`distro_redhat`, `enable_mcs`, …)
  follow the configured build: inactive branches are dimmed, ignored by
  diagnostics and left out of the index.
* Policy Explorer sidebar; devel-header mode for standalone modules.

**Real builds** (Linux, trusted workspaces)

* Build on save with the real toolchain: compiler, m4 and link errors on
  the source lines that cause them.
* Standalone modules against `selinux-policy-devel`; *Build* writes
  `<module>.pp`, *Install Module* runs `sudo semodule -i` in a terminal.
* Full refpolicy trees with their own Makefile: compile, then link
  validation. *Configure Build from Spec File…* derives the settings of a
  RHEL/Fedora `selinux-policy.spec` variant (modules.conf, booleans.conf,
  users). Optional export of build outputs.
* "Compiles to" hover and a read-only expanded-policy view.

**Compiled policy**

* Compiled Policy view of the last build: modules, users, roles, domains,
  types, attributes, booleans, classes and domain transitions, each linked
  to its source declaration; allow and other rules per type with the
  source statements that produce them; find.
* Changes since HEAD: builds HEAD and shows what an edit adds or removes in
  the compiled policy, down to single permissions, traced to the source
  lines responsible.
