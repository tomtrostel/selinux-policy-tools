# SELinux Policy Tools: project context

VS Code extension + language server for editing **uncompiled refpolicy-style
SELinux policy** (RHEL 9/10 `selinux-policy` source and CLIP-style locked-down
policies derived from it). Plain JavaScript (CommonJS), no build step.

## Goals and roadmap

Status as of 2026-10-10: **v0.7.0 released** (GitHub release `v0.7.0`;
v0.2.0 was the first release). Steps 1, 2 and 3 are done and in 0.3.0;
0.4.0 adds the step-4 items below plus info-flow and standalone-module
checks; 0.5.0 adds the .te missing-require check and RHEL 10 support;
0.6.0 adds the static link check, corenetwork.te.in mapping and port
checks, booleans in the .te check, ifelse decisions, all build variants
(and the `make conf` / exec-bit fixes); 0.7.0 adds several trees per
workspace (the last item under 5, confirmed interactively). Roadmap steps
1-5 are done; next: interactive use of the 0.5.0/0.6.0 features, or new
ideas from the user. Unreleased since 0.7.0: ifdef on names that aren't
build flags is decided from the sources (see Key design decisions); the
.te require check works without modules.conf (make conf defaults).
The user clicked through all features of 0.3.0 and 0.4.0 in VS Code
(Remote-SSH to melody) after the 0.4.0 release (all worked, nothing
reported), and confirmed 0.7.0's tree switching; 0.5.0/0.6.0 features are
so far covered by the e2e tests only.

1. **Navigation and authoring help** (done): definition, references,
   hover docs, completion, signature help, outline, Policy Explorer sidebar,
   diagnostics with quick fixes, build-flag ifdef evaluation.
2. **"What did this change actually grant"** (done): real builds
   (standalone modules + full trees: CLIP RHEL 9, RHEL 9 targeted via spec
   settings), compiler/link diagnostics, "Compiles to" hover, expanded
   view, Compiled Policy view (elements + rules per type, traced to
   source), "Changes since HEAD" (own setools diff + source tracing).
3. **Lockdown workflows** (done):
   1. **Module on/off preview** (done): request `selinux/modulePreview`
      {module, to}. Flips the module's line in the effective modules.conf
      (the spec overlay if `selinux.build.tree.files` has one, else the
      tree's; editor contents win), drops it from APPS_MODS if forced on
      there, builds with `buildTree(..., { variant: 'preview' })` (own
      scratch copy `tree-<hash(root#preview)>`), then policy_diff.py
      current vs preview and `explainDiff()` (shared with Changes since
      HEAD). Dependent optional_policy blocks are found statically
      (`dependentOptionalBlocks`: innermost active optional_policy around
      calls to the module's interfaces, incl. template-generated ones, or
      refs to its types/attributes, in enabled modules). Module Preview
      view (ModulePreviewView extends ChangesView, reuses diffGroups);
      Apply edits the conf line via WorkspaceEdit and offers to drop the
      module from APPS_MODS in settings. Found + fixed on the way: refpolicy
      doesn't rebuild set-dependent outputs when the module set changes
      (`forgetStaleModuleSet` in build.js), and link errors now land on the
      interface call that requires the missing type (`interfaceRequires`).
   2. **Domain-transition graph** (done): `policy_query.py` op
      `transitions` (out/in) computes real transitions like setools'
      DomainTransitionAnalysis, which needs python3-networkx (not
      installed): process:transition (target attributes expanded) +
      entrypoint ∩ execute file types; automatic if a type_transition on
      that entrypoint exists, explicit via setexec, dynamic via
      dyntransition + setcurrent; conditional booleans reported. Requests
      `selinux/transitions` (+ source locs) and `selinux/domains`. Webview
      `media/transitions.js` (plain JS + SVG, layered BFS layout, click to
      expand, double-click opens source, alt-click re-roots, filter);
      panel code `showTransitionGraph` in client/extension.js; tested with
      a fake DOM (test/webview-transitions-test.js).
   3. **Property checks** (done): `selinux.checks` at the tree root
      (`selinux.checks.file`), language `selinux-checks` (grammar +
      completion). `server/checks.js` parses `only|never|require <names>
      may <perms> <targets>[:<classes>]` and `never <names> reaches
      <names>`; perm groups read/write/execute/any. policy_query.py op
      `check` evaluates on the compiled policy (names() expands
      attributes, resolves aliases, '*' = domains; `granting()` finds allow
      rules incl. via attributes and self; require narrows groups to the
      class's perms; reaches = BFS over `transitions()`, 8 steps). Server
      `runChecks()` after each good tree build and on edit/save/disk change
      of the checks file (no rebuild): diagnostics with relatedInformation
      (explainRule origins / path steps), code lenses ✓/✗, notification
      `selinux/checks` → status bar item.
      - Info-flow checks (0.4.0): `never <types> flows to <types>
        [except <types>] [weight N]` (kind `flows`). policy_query.py
        `flow_path()`: BFS over types; rule read-weight (from setools
        PermissionMap, `rule_flow()` cached per rule) moves target → source,
        write-weight source → target; each (rule, direction) is expanded
        only once (later visits would reach only seen types), so attribute
        rules like `domain file_type` stay cheap (~4 s incl. indexing on
        RHEL). Default weight 10. Steps carry the rule + contributing perms;
        server traces each step with explainRule (relatedInformation
        "A → B: B reads (allow …) (via …)").
      - Standalone modules (0.4.0): `build.linkWithInstalled(res,
        {isAttribute})`: `checkpolicy -b -C` decompiles the installed
        kernel policy (world-readable; cached per mtime), `semodule_package`
        + `/usr/libexec/selinux/hll/pp` turn tmp/<mod>.mod into CIL, a shim
        declares `cil_gen_require` and required attributes the kernel
        policy expanded away (isAttribute from `requiredAttributes()`: decls
        + gen_require kinds in the devel headers; a missing *type* fails
        with a message), declarations already in the base (module
        installed) are dropped, then `semodule -p <work>/linked/root -s
        linked -i base.cil shim.cil mod.cil` (~8 s). Server:
        `checksRoot()` = tree root or roots[0] in devel mode;
        `linkedPolicy()` links the last good module build once
        (`lastModule`, keyed by the result object); `getPolicyModel()` uses
        it in devel mode (model.linked); `currentSide()` explains from
        `res.expandedPath`. Notifications `linking`/`linked`.
   4. **Users / roles / MLS** (done): parser keeps `argTokens` for
      gen_user calls (TOKENIZED_CALLS); diagnostics.js `checkUsers`: roles
      not declared anywhere (`idx.knownRoles()`, any branch + generated),
      MLS/MCS tokens checked against the m4 flags (MCS: s0 only;
      mcs_num_cats / mls_num_sens / mls_num_cats), high < low, unknown
      tokens unless a defined macro, duplicate users only when no undecided
      ifdef surrounds them (`idx.undecidedAt`). Survey clean on all trees
      and MCS/MLS. Model: roleAllows / roleTransitions (setools
      RBACRuleQuery), users' logins from config/appconfig-<TYPE>/seusers.
      View: roles → Types / May switch to / Role transitions / Users;
      users → Roles / Linux logins. Hover on users/roles, completion in
      gen_user. Checks: `only|never <roles> may run <types>`,
      `only|never <users> may use <roles>` (policy_query check_rbac).
      Editing preview = save + build + Changes since HEAD (no separate UI).
4. **Extensions of what's built** (smaller, any time):
   - Compare with other refs (done, 0.4.0): `selinux/policyDiff`
     {base: ref | saved: dir, target: ref | null=working tree};
     `ensureRefBuild()` (git archive into `head-<hash(root@sha)>` + build,
     LRU of 3, replaces the single HEAD baseline); `fromRef(label,
     srcRoot)` maps origins into a ref's copy (o.ref = label);
     `gitChangedFiles(root, info, from, to)` ranks origins; `gitRefs` feeds
     the *Compare with…* picker (HEAD, tags, branches, commits, typed ref,
     two refs, saved build dir). ChangesView `compareWith(params)`,
     refreshes after builds only when the working tree is a side.
   - Per-window scratch dirs (done, 0.4.0): `scratchDir()` lives in
     `<tmp>/selinux-policy-tools-<uid>/<server pid>/` (base mode 0700); the
     server removes its whole area on exit (`cleanupScratch`) and sweeps
     areas of dead pids at startup (`sweepStaleScratch`; also rmdir's the
     old shared `<tmp>/selinux-policy-tools` once empty). Build summaries
     carry `workDir`; tests use it instead of computing paths.
   - Build through semodule/CIL (done, 0.4.0): `build.cilBuild()`
     runs `semodule -p <work>/cil-root -X 100 -s <NAME> -i base.pp -i
     <every .pp>` (not `make load`, which only loads modules.conf modules,
     so CLIP's APPS_MODS packages would be missing); needs
     `<root>/var/lib/selinux`; copies the host's semanage.conf; works
     unprivileged (ownership warnings filtered). Request
     `selinux/compareInstalled` {name} diffs /etc/selinux/<name>/policy
     (A, no sources → `explainDiff(diff, null, b)`, origins marked
     noSource) vs the CIL build (B); cached by the build's .pp set.
     ChangesView `mode: 'installed'` (no auto-refresh). RHEL vs melody's
     installed targeted: 5,132 diffs (container-selinux, cockpit, sandbox,
     a local boolean) vs ~1.3M legacy-vs-CIL noise.
5. **Hardening**: .te missing-require check (done, 0.5.0:
   diagnostics.js `checkTeRequires`, code `missing-te-require`; scopes =
   top level / innermost optional_policy; provided = file-level require
   entries (parser now records their l/c) + `callRequires()` of every
   top-level call, transitive through bodyCalls with $N/$*/shift
   substitution, memoized in `idx._teRequires`; generated interfaces
   provide what their template call site generates (`idx.generatedAt`);
   .spt defs and structural macros contribute nothing (CLIP's
   tunable_policy recurses via declare_required_symbols); unknown macro
   → scope uncertain → silent; uses in undecided ifdef branches skipped.
   Loadable = `idx.isLoadable(module)`: `idx.allLoadable` in devel mode,
   else `idx.moduleKinds` from modules.conf + APPS_MODS
   (`updateModuleKinds()` in server; without modules.conf (after 0.7.0)
   `idx.defaultModuleKinds(root)` = what `make conf`/sedoctool writes:
   base if the module's .if has `## <required val="true">` (parser
   `f.required`), else module; identical to real make conf on upstream
   refpolicy (416 modules); MONOLITHIC=y (makeArgs, else build.conf) →
   all base, nothing checked; test/conf-defaults-e2e.js). Devel mode has no decls, so kinds
   come from `idx.requiredKind()` (interfaces' requires). Quick fix
   `teRequireEdit`. Survey: `--modules <conf>` / `--loadable` /
   `--conf-defaults`.)
   RHEL 10 (done, 0.5.0): see Known limitations.
   Link errors (done, 0.6.0): diagnostics.js `globalRequirements(f)`
   = require entries + `callRequires(..., mandatory=true)` of top-level calls
   outside optional_policy / undecided ifdefs (parser now marks def
   requires/bodyCalls inside optional_policy or ifdef/ifndef/ifelse of the
   body with `cond: true`; mandatory mode skips them). `checkLinkRequires`
   (code `link-missing`, trees with moduleKinds only): a global requirement
   whose `idx.declaringModules(name)` are all off. mapLinkDiagnostics places
   semodule_link errors on the first global-requirement site. Client
   watches `modules*.conf` and `*.lst`; server re-reads module states.
   corenetwork (done, 0.6.0): build.js `alignGenerated(gen, src)`
   (quote-insensitive line alignment; non-verbatim lines → the pending
   network_* call, preferring the one whose name prefixes a type in the
   line, else a wrapper like build_option) and `mapGeneratedDiagnostics`
   (also portcon/nodecon/netifcon errors, which checkpolicy attributes to
   the last #line file). diagnostics.js `checkNetworkPorts`: range,
   protocol, exact duplicates (codes `net-port`, `net-port-duplicate`).
   Variants (done, 0.6.0): RHEL 9 minimum/mls/automotive and RHEL 10
   automotive pass build-rhel-e2e; monolithic verified on upstream
   refpolicy (~/sepol-test/refpolicy, test/build-mono-e2e.js). Found on the
   way: buildTree runs `make conf` when the scratch copy has no
   policy/modules.conf (CONF_OUTPUTS kept by syncTree), and syncTree keeps
   the execute bit (refpolicy runs support/gentemplates.sh directly).
   RHEL/CLIP don't build MONOLITHIC=y themselves; upstream validate fails
   with semodule 3.6 (roletype in unconfined/cil).
   Several trees per workspace (done, 0.7.0): build.js `findTrees`
   (Makefile + Rules.modular + build.conf + obj_perm_sets.spt, depth 6,
   stops at a tree). One active tree: server `trees`, `activeTree`
   (`pickTree`: settings.activeTree from the client's workspaceState, else
   tree of an open document, else first), `excludedTrees` kept out of
   `idx.scanRoots(roots, exclude)` and document sync; files there get an
   `inactive-tree` INFO. `treeCfg()` = build.tree + the matching
   `settings.build.trees` entry (key relative to a workspace folder or
   absolute; `treeKey`). Requests `selinux/trees`, `selinux/selectTree`;
   stats carry `tree` + `trees`. Client: status bar shows the tree and
   switches on click, `selinux.selectTree`, auto-switch on active editor
   (800 ms settle, `selinux.tree.autoSwitch`), Configure from Spec writes
   `build.trees[key]`. Test: test/multi-tree-e2e.js. Confirmed working
   interactively by the user (VS Code over Remote-SSH).

Open decision for the user: the GitHub repo
(github.com/tomtrostel/selinux-policy-tools) is **private**, so the release
is only visible to collaborators; making it public is the user's call.

## Working setup (how this project is developed and tested)

- Dev machine is Windows (D:\src\selinux-policy-tools, Git Bash +
  PowerShell); `npm test` runs locally (build tests skip on Windows).
- Linux test host: `ssh melody` (Rocky 9.8, key auth, user ttrostel; sudo
  needs a password, so ask the user for package installs). Test copy of the
  extension at ~/sepol-test/tools (sync with
  `tar czf - server test client package.json syntaxes | ssh melody 'cd ~/sepol-test/tools && tar xzf -'`),
  trees: ~/sepol-test/rhel9 (+ ~/sepol-test/srpm unpacked SRPM),
  ~/sepol-test/clip (git clone, tree in packages/selinux-policy/selinux-policy),
  ~/sepol-test/mymodule (standalone module).
- Run on melody: `node test/build-e2e.js`, `test/build-tree-e2e.js`,
  `test/build-rhel-e2e.js`, `test/diff-e2e.js`, `test/preview-e2e.js`,
  `test/checks-e2e.js`, `test/module-checks-e2e.js`, `test/scratch-e2e.js`;
  survey with `--make`.
- Writing edit scripts: the Bash tool's heredocs collapse `\\` to `\`, which
  breaks regexes in generated JS; write scripts with the Write tool into the
  scratchpad and run them.
- Interactive testing: the user runs VS Code on Windows with Remote-SSH to
  melody. Install a fresh build there with `npx @vscode/vsce package`, scp
  the .vsix to ~/sepol-test/, then
  `~/.vscode-server/cli/servers/Stable-<commit>/server/bin/code-server --install-extension <vsix> --force`
  (commit = `code --version` line 2), and ask the user to *Developer:
  Reload Window*.
- Workflow the user expects after each feature: tests pass on melody,
  README/CLAUDE.md updated (features, tested, limitations), commit + push
  to GitHub (`gh` is at "C:\Program Files\GitHub CLI\gh.exe", logged in as
  tomtrostel). Keep LF line endings (.gitattributes); if git warns about
  CRLF in the working copy, delete and re-checkout the files.
- Release: bump package.json version, add a CHANGELOG.md entry, package,
  `gh release create v<version> <vsix> --notes-file <notes>` with install
  instructions (see the v0.2.0 notes).

## Key design decisions (don't undo without discussion)

- **Parse structure, don't emulate m4.** The parser tracks m4 call/quote
  nesting and records definitions, declarations, calls, gen_require contents,
  AV rules and identifier occurrences. Semantics (what a policy grants) must
  come from the real toolchain (layer 2), never from reimplementing m4.
- **Template expansion for generated names.** Definitions whose bodies
  declare `$N`-patterned names (types or nested `interface(...)`) are
  "generative"; calls to them are expanded (max depth 5) so names like
  `http_port_t`, `corenet_tcp_bind_http_port`, `httpd_sys_content_t` resolve
  to the generating call site. `$*`, `$@` and `shift($*)` are spliced.
- **Macros generated at build time are synthesized**: `all_<class>_perms`,
  `all_kernel_class_perms`, `all_userspace_class_perms` (genclassperms.py).
  Conversely, the devel headers have no flask files, so when no flask files
  are indexed the class/perm table is read from their `support/all_perms.spt`.
- **Diagnostics must stay quiet when unsure.** Zero false warnings on the
  full Fedora tree is the bar. Calls to unknown interfaces inside
  `optional_policy` are INFO, not warnings. Quote-balance checks are skipped
  for `.spt`/`.m4` (they use changequote tricks).
- **Builds use the real Makefile in a scratch dir** (`server/build.js`):
  module dir contents (editor buffers, so unsaved edits compile) are copied
  to `<scratch area>/<hash>/` and `make -f <devel Makefile>
  tmp/<mod>.mod` runs there (~0.3 s, no caching needed). checkmodule honours
  m4's `#line` markers, so its errors arrive in source coordinates. The
  expansion map parses `tmp/<mod>.tmp`: `#line N "file"` (file only on
  change; unmarked lines continue N+1) plus refpolicy's `##### begin/end`
  call markers. Build diagnostics are dropped once the file text differs
  from what was built, and suppressed on lines where a static `unknown-*`
  diagnostic (which has quick fixes) already reports the problem.
  Builds on save are checks only (nothing written next to the sources); the
  explicit "Build Current Module" command packages and copies `<mod>.pp`
  into the module dir. "Show Expanded Policy" renders `tmp/<mod>.tmp` as a
  read-only `selinux-expanded:` document (source-line headers, class /
  category boilerplate collapsed). Scratch dirs are removed on server exit.
- **Full-tree builds** (workspace contains a refpolicy root: `Makefile`,
  `Rules.modular`, `build.conf`, `policy/support/obj_perm_sets.spt`) keep a
  persistent scratch copy `<scratch area>/tree-<hash>/`,
  synced before each build by rewriting only files whose content differs
  (so make's incremental rebuild works; outputs listed in refpolicy's
  .gitignore and generated corenetwork.te/.if are not copied). The tree's
  own Makefile runs with `selinux.build.tree.makeArgs` (the RPM spec's
  variables; build.conf otherwise). Phase 1 `base.pp modules` (~0.5 s
  incremental) publishes compile errors; phase 2 `validate` (~6 s: link
  3.4 s + expand 2.9 s) adds link errors. semodule_link reports only
  "<mod>'s global requirements were not met: type X"; the server places it
  where that module's .te requires X outside optional_policy
  (`globalRequirements`), and the static `link-missing` check reports all
  of them before building. Hover/expanded view
  read `tmp/<mod>.tmp` (loadable modules) or `base.conf` (base modules),
  parsed lazily and cached by mtime.
  Explicit Build (request `package: true`) of a tree copies outputs to
  `selinux.build.tree.outputDir` (`~/` or tree-relative) via
  `exportTreeOutputs`: *.pp, policy.bin, policy.NN, file_contexts plus
  build-info.json, whose file list is used to delete stale files from the
  previous export. Builds on save never export. "Install Module" (client
  only, standalone mode) packages, then sends `sudo semodule -i` to a
  "SELinux Install" terminal; full-policy install is deliberately absent.
- **Compiled Policy view** shows the linked kernel policy of the last tree
  build (tmp/policy.bin), not the sources, so it reflects exactly what the
  lockdown enabled. `server/policy_model.py` (python3-setools) exports it as
  JSON (~0.6 s for CLIP); the server attaches a source location + module to
  each element from the index (types/attributes/roles/bools from decls,
  template-generated names via their call site, users from gen_user calls),
  cached by policy.bin mtime. The client tree is lazy and path-keyed;
  relationships (attributes, members, roles, domain transitions in/out) are
  derived client-side. Standalone-module mode shows the module linked with
  the installed policy (`linkWithInstalled`, model.linked).
- **ifdef/ifndef on build flags, and on names from the sources.** The
  parser records every
  ifdef/ifndef branch as a range + condition (`f.branches`, also for .fc;
  `inDef` when inside a definition body).
  The server asks the Makefile for the real flags (`make --eval` printing
  `$(M4PARAM)` with the build makeArgs; ~0.1 s; trusted + Linux only) and
  the "universe" of decidable flags is the Makefile's `-D` symbols (plus
  any `distro_*` when it passes `distro_$(DISTRO)`), minus flags Rules.*
  pass only for some steps (`m4.stepOnly`, undecided), minus anything
  define()d in the sources. Other names (after 0.7.0): `idx.branchState(f, b)`
  → {v: defined? true/false/null, kind} from `symSites()` (parser
  `f.symDefs`: define/pushdef/undefine/popdef/interface/template sites,
  `inDef` = enclosing def name) and m4's read order (`m4Role`,
  `siteRelevance`: .spt → all .if (all_interfaces.conf, made WITHOUT
  M4PARAM, so flag branches at .if top level stay undecided) → one .te;
  .fc sees only .spt; in a def body = expansion time: .if/.spt sites count,
  .te sites unsure; same file: only sites before the branch; other .te/.fc
  unsure since base modules are concatenated). A site counts only if its
  own branches are active (`siteState`, recursive, cycle → null). Never
  defined → false (TODO, targeted_policy, RHEL's misspelled enabled_mls,
  CLIP's leftover hide_broken_symptoms); self-guard `ifndef(X,
  interface(X))` → active; m4 builtins → true; `$N` pattern defines
  (except interface()/template()'s own define(`$1')), undefine/popdef,
  defines in macro bodies → null. `idx.branchReason` words it for
  inactiveRanges, hover on the ifdef name (`ifdefConditionHover`) and
  `inactive-macro`. RHEL: 85 → 9 undecided branches (+8 inactive),
  CLIP 12 → 9 (+3); survey diagnostics unchanged (test/ifdef-names-test.js).
  Undecided stays all-active (quiet when unsure). Inactive branches:
  dimmed (`selinux/inactiveRanges`), skipped by diagnostics, their defs
  move to `idx.inactiveDefs` (calls to them get INFO `inactive-macro`),
  their decls / fc entries / generative calls leave the index. RHEL
  targeted: 202 of 461 branches inactive; CLIP: 181 of 365; survey results
  unchanged on both. Survey: `diag-survey.js <policy> --make "<args>"`.
- VS Code extension + LSP rather than a standalone GUI; graphical views go in
  webview panels later.

## Layout

- `server/parser.js`: tokenizer, `parsePolicy` (.te/.if/.spt/.m4), `parseFc`,
  `parseFlask` (security_classes, access_vectors), refpolicy XML doc parsing.
- `server/indexer.js`: `PolicyIndex`: per-file parses → global maps
  (`defs`, `decls`, `classes`, `commons`, `fcByType`), generative expansion,
  queries. Full rebuild is ~180 ms on the Fedora tree; edits rebuild with a
  300 ms debounce.
- `server/diagnostics.js`: unknown macros, unknown class/perm in AV rules,
  missing gen_require entries in `.if` interfaces, missing requires in
  `.te` files of loadable modules, syntax balance.
- `server/server.js`: LSP features and custom requests
  (`selinux/modules`, `selinux/moduleContents`, `selinux/stats`,
  `selinux/reindex`, `selinux/build`, `selinux/expansion`,
  `selinux/expandedPolicy`; notifications `selinux/indexing`, `selinux/build`
  with states start / validating / done).
- `server/build.js`: toolchain detection, scratch-dir module build, tree
  build with scratch sync, parsers for checkmodule/m4/refpolicywarn/
  semodule_link output and the m4 `#line` expansion map.
- `server/specconfig.js`: build settings (makeArgs + files overlays) per
  variant from a Fedora/RHEL selinux-policy.spec (request
  `selinux/specBuildConfig`, command "Configure Build from Spec File…").
- `server/policy_diff.py`: setools diff of two compiled policies (TE rules
  keyed by type/source/target/class/conditional, compared per permission;
  element and membership changes) → JSON (request `selinux/policyDiff`).
- `server/explain.js`: indexes a build's m4 output statements (allow & co,
  type_* rules, typeattribute / `type T, attrs`) with source line + call
  chain, and traces changed rules to them (direct, or attribute rule +
  the membership statement). Names are interned and statement text is read
  back lazily; RHEL ≈ 242k statements, ~110 MB, 2.5 s cold / 0.15 s cached;
  dropped after 2 idle minutes.
- `server/policy_query.py`: long-running setools helper (JSON lines on
  stdin/stdout). Indexes the policy once per policy.bin (rules bucketed by
  source/target name + type attributes; CLIP 0.7 s, RHEL ~5 s) and answers
  `rules` queries in ms (requests `selinux/typeRules`; origins via
  `selinux/ruleOrigins` → explain.js on the current build's index). Warmed
  in the background after builds once used.
- `server/policy_model.py`: setools export of a compiled policy to JSON
  (request `selinux/policyModel`).
- `client/extension.js`: language client, status bar, commands, Policy
  Explorer (sources) and Compiled Policy (last build) tree views, expanded
  policy documents. `CompiledPolicyView` takes an injectable request
  function; build-tree-e2e drives it with a stub `vscode` module.
- `syntaxes/`: TextMate grammars (`source.selinux`, `source.selinux-fc`).
- `test/lsp-e2e.js`: drives the server over stdio LSP against a workspace
  with a seeded test module (`policy/modules/local/myapp.*`).
- `test/build-e2e.js` (`npm run test:build`): real-build checks over LSP;
  asserts, exits non-zero on failure, skips without the Linux toolchain.
  Run it on melody: `~/sepol-test/tools`.
- `test/checks-e2e.js` (`npm run test:checks`): gen_user validation (unsaved
  bad users lines), then property checks incl. roles/users on a CLIP
  copy (holding/failing/unknown/syntax, alias, tracing, edit+save without
  rebuild, completion), info flow (`flows to`, path traced, `except` with
  the reported intermediates reroutes or holds).
- `test/module-checks-e2e.js` (`npm run test:modchecks`): standalone module
  in a temp workspace linked with the installed policy; checks file at the
  workspace root, violations and a flow traced to the module, policyModel
  `linked`, edit + build relinks.
- `test/scratch-e2e.js` (`npm run test:scratch`): two servers on one
  workspace build in separate areas; exit/kill/sweep behaviour.
- `test/webview-transitions-test.js` (`npm run test:webview`, any OS):
  runs media/transitions.js against a fake DOM through a whole session.
- `test/preview-e2e.js` (`npm run test:preview`): module preview on a CLIP
  copy: cron off / mta off (link error placement) / nscd on / ntp off
  (APPS_MODS, after other previews), plus the view with a stub vscode.
- `test/diff-e2e.js` (`npm run test:diff`): copies a tree (default CLIP)
  into a fresh git repo, edits logging.te in an unsaved buffer, checks the
  diff vs HEAD, its tracing, and the Changes view (stub vscode).
- `test/build-rhel-e2e.js` (`npm run test:rhel`): RHEL tree build (+ compare
  with the installed targeted policy via semodule/CIL, and the view) with
  settings from the spec (default ~/sepol-test/rhel9 + srpm on melody),
  trust gating, overlays, booleans, link errors; ~2 min.
- `test/build-tree-e2e.js` (`npm run test:tree`): full-tree build checks on
  a copy of a refpolicy tree (default: the CLIP RHEL 9 clone on melody, with
  CLIP's RPM make arguments built in); same conventions as build-e2e.
- `test/ifdef-names-test.js` (in `npm test`, any OS): ifdef decisions on
  non-flag names over an in-memory index (guards, define order, inactive
  defines, patterns, .fc, interface bodies, no flags).
- `test/conf-defaults-e2e.js` (`npm run test:confdefaults`): upstream
  refpolicy copy without modules.conf over LSP: ssh.te (loadable by
  default) gets missing-te-require, terminal.te (required → base) doesn't,
  MONOLITHIC=y gets none.
- `test/diag-survey.js` (prints undecided branch counts with `--make`): runs all diagnostics over a tree and summarizes;
  use it after any parser/diagnostic change to catch false positives.

## Testing

```
git clone --depth 1 https://github.com/fedora-selinux/selinux-policy.git ../selinux-policy
node test/diag-survey.js ../selinux-policy/policy     # expect only unknown-macro-optional (container module)
node test/index-smoke.js ../selinux-policy/policy     # optional, if present
```

`test/lsp-e2e.js` expects a workspace path (default `<os.tmpdir()>/selinux-e2e-ws`,
override with the first CLI argument) containing a
copy of `policy/` plus the seeded module under `policy/modules/local/`
(myapp.te with a misspelled interface, permission and class; myapp.if with a
missing gen_require entry). Recreate it if missing; the expected diagnostics
are listed in the script output.

Package: `npx @vscode/vsce package`.

## Known limitations / open items

- RHEL 9 verified (Rocky 9.8, selinux-policy-38.1.75-2.el9_8 SRPM, unpacked as
  `%prep` does, i.e. with container-selinux.tgz extracted into contrib). Survey
  gives 54 missing-require + 1 unknown-class (container.te `user_namespace`,
  absent from el9 flask): all true positives, mostly fixed upstream since.
  Test host: `ssh melody` (~/sepol-test).
- RHEL 10 verified (Rocky 10.2 SRPM selinux-policy-42.1.18-4.el10_2.3,
  unpacked into ~/sepol-test/srpm10, tree in ~/sepol-test/rhel10 with
  container-selinux.tgz in contrib; the spec has no patches). RHEL 9's
  checkpolicy 3.6 builds it (policy.33; RHEL 10 ships policy.35, no
  xperm/newer statements in the sources). RHEL 10 spec layout: makeCmds
  copies `./dist/%1/booleans.conf` and `./dist/%1/users`; makeModulesConf
  runs process-modules-filtered.py (Source13) with modules-dropped.lst on
  `./dist/%1/modules.conf` ("disabled": non-base listed modules → off);
  minimum/automotive filter again with modules-extra.lst. specconfig.js
  emits tree-relative `dist/...` paths and `{ from, disable: [lists] }`
  sources; build.js `overlaySource()` / `disableModules()` apply them
  (byte-identical to the script's output); server `resolveOverlay()`.
  build-rhel-e2e.js takes `~/sepol-test/rhel10
  ~/sepol-test/srpm10/selinux-policy.spec <variant>`; targeted, mls and
  minimum pass. Survey: 60 missing-require (all real), 0 te-require.
- CLIP for RHEL 9: github.com/sealingtech/CLIP branch `RHEL9`, cloned on
  melody at ~/sepol-test/clip. Its policy is upstream refpolicy 2.20240226
  (not RHEL's fork) at `packages/selinux-policy/selinux-policy/`; the
  lockdown is `policy/modules.conf` (12 base, 55 module, 326 off) plus
  SEPARATE_PKGS passed as APPS_MODS. Survey: 2 missing-require + 2
  unknown-macro, all real latent bugs in uncalled interfaces. Builds
  90 packages, policy.33 with 1973 types. The tree has VS Code settings
  with CLIP's makeArgs in `.vscode/settings.json` (gitignored).
- RHEL selinux-policy tree builds (verified: RHEL 9 targeted, ~30 s cold,
  435 packages; validate is ~22 s of it): the git tree ships a modules.conf
  and users that differ from the RPM's, and no booleans.conf (optional to
  the Makefile). `server/specconfig.js` reads the spec's `%common_params`,
  `%makeCmds NAME TYPE UNK` and `%makeModulesConf` lines (not the shell in
  the macro bodies) into makeArgs + `selinux.build.tree.files` overlays
  (modules-X-base.conf + modules-X-contrib.conf, booleans-NAME.conf,
  users-NAME, from the spec's directory). Overlays are applied in syncTree
  as part of the wanted set, so unchanged overlays aren't rewritten. In
  RHEL, container_t exists via virt.te (aliases); use an off module such
  as timidity for link-error tests. All four spec variants verified on
  RHEL 9 and RHEL 10. make validate uses legacy link/expand while installed policies
  are CIL-built, so sediff against /etc/selinux/*/policy is dominated by
  attribute representation; a faithful build would go through
  `make load SEMODULE="semodule -p <scratch root> -X 100"` (works unprivileged).
- Workspace trust: builds refused when the client reports
  `trusted: false` (initializationOptions / `selinux/setTrusted`); the
  build settings are `restrictedConfigurations` in package.json.
- VS Code UI: clicked through over Remote-SSH (Windows → melody) on
  2026-10-03: standalone builds, and on CLIP the tree build (compile + link
  errors), Compiled Policy view (browse, navigate, find, refresh), hover and
  expanded view. All worked as designed; no UX issues reported. RHEL 9
  tree (Configure from Spec → targeted build → Compiled Policy view) used
  interactively too, after fixing the stale "build first" message; ifdef
  dimming and flag hover confirmed in VS Code on the RHEL tree; Changes
  since HEAD confirmed in VS Code on the CLIP clone. 2026-10-04, after
  v0.4.0: the user clicked through all features (module preview,
  transition graph, property checks incl. flows and standalone modules,
  users/roles, compare with refs / installed policy); all fine.
- Compiled Policy view: rules per type/attribute (Can access / Accessed by
  / Other rules) with on-demand source tracing; confirmed in VS Code.
  Changes view: any git ref, two refs, a saved build, or the installed
  policy.
- `.te` require check only for modules known to be loadable (devel mode,
  `module` in modules.conf / APPS_MODS, or make conf defaults without a
  modules.conf); upstream refpolicy surveys clean with the defaults.
- ifdef on names defined dynamically (macro bodies, pushdef, generated
  names) or in another .te stays all-active; without make (Windows local)
  nothing is decided. `ifelse` only occurs inside
  definitions; the parser records enclosing 4-arg ifelse branches as
  `when: [{a, b, then}]` on declPatterns, requires and bodyCalls, and
  `idx.whenHolds(when, args)` decides them per call (plain-text sides
  only) in expandGenerated and callRequires (test/ifelse-test.js).
- .te require check covers booleans (kind from decls / requiredKind);
  `tunable_policy` provides its condition's names when the tree's macro
  calls declare_required_symbols (`autoRequiringTunables`), at top level
  and inside interfaces (callRequires handles tunable_policy bodyCalls).
  gen_tunable/gen_bool with `$N` names in templates are declPatterns now.
- Windows paths: indexed paths come from `URI.fsPath` (lowercase drive
  letter); keep all path keys going through `toPath()` for consistency.

## Conventions

- Keep dependencies minimal (vscode-languageserver/client, vscode-uri).
- Every new diagnostic needs a survey run showing no new false positives.
- Prefer user-visible messages that say what to do, not just what's wrong.
