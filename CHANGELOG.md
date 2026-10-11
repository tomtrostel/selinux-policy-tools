# Changelog

## Unreleased

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
