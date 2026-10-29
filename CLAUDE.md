# SELinux Policy Tools: project context

VS Code extension + language server for editing **uncompiled refpolicy-style
SELinux policy** (RHEL 9/10 `selinux-policy` source and CLIP-style locked-down
policies derived from it). Plain JavaScript (CommonJS), no build step.

## Goals and roadmap

Status as of 2026-10-22: **v0.17.0 released** (GitHub release `v0.17.0`;
v0.2.0 was the first release). Steps 1, 2 and 3 are done and in 0.3.0;
0.4.0 adds the step-4 items below plus info-flow and standalone-module
checks; 0.5.0 adds the .te missing-require check and RHEL 10 support;
0.6.0 adds the static link check, corenetwork.te.in mapping and port
checks, booleans in the .te check, ifelse decisions, all build variants
(and the `make conf` / exec-bit fixes); 0.7.0 adds several trees per
workspace (the last item under 5, confirmed interactively). Roadmap steps
1-5 are done; next: interactive use of the 0.5.0/0.6.0 features, or new
ideas from the user. 0.8.0 decides ifdef on names that aren't build flags
from the sources (see Key design decisions) and runs the .te require check
without modules.conf (make conf defaults); not yet tried interactively.
0.9.0 adds the service editor with booleans, port types and helper
domains (step 6 below; e2e-tested, the form not yet tried interactively)
and tutorials (step 7; the user checked the walkthroughs in VS Code and
they look good). 0.10.0 adds the denial assistant (step 8, phases 1-4),
standalone service modules packaged as RPMs with a license picker, more
services (all init_*domain variants, template-declared domains) and login
services, and finding interfaces by need (step 6). The user looked at it
before the release ("looks okay"); not clicked through feature by feature.
0.10.1: read-only denials rank read-only interfaces first (writes tag),
ranked keyword search for interfaces. 0.10.2: long interface lists grouped
by module, custom file access (kept rules shown, openable, expanded), build
of the active tree from outside trees/modules. 0.11.0 (service editor):
file access under a boolean, services started by D-Bus/inetd/cron/mail
server or by a template of their module, web applications
(apache_content_template), path flags (-d/--), a web applications
tutorial page. The user tried 0.11.0's features before the release ("That
all appears to work right").
0.12.0 (step 9): Logins and Users view and the user editor (new users,
existing users, standalone users as RPMs, automation preset, reach
preview). The user tried them before the release ("That all seems to
work").
0.13.0: login checks in selinux.checks (the user tried them before the
release: "that all seems to work").
0.14.0: file labels lookup and the all-features menu (step 10; released
at the user's request before they tried it interactively).
0.15.0: wrapped programs (step 11), `except through` in reach checks, CLIP
for RHEL 8 (Configure from CLIP specs); the user tried the wrapper form
(reported the stale path, fixed) before the release.
0.16.0: levels and categories (step 12, all six items), a host's local
changes (step 13), the booleans.conf incremental-build fix, the
`except through` fix, unit tests for the core pieces and test:clip-all;
the user tried the new panels before the release ("it looks like things
work").
0.17.0: contexts that won't load (step 14: login contexts, context files),
RHEL 8 hosts (ricardo: fc order, matchpathcon -f), user editor kind
changes, a lockdown tutorial step; the user tried it before the release
("It looks like it works").
Unreleased: step 15 (logins that bounce: session starts, fixes from the
tree's interfaces, SELINUX_ERR verdicts in the denial assistant) and step 16
(restricted logins: what they run, silent failures, which edit broke it)
and step 17 (dropped optional blocks dimmed, CLIP install profiles); none
tried interactively yet.
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
   (`updateModuleKinds()` in server; without modules.conf (0.8.0)
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

6. **Service editor** (done, 0.9.0; user request: "set up new
   services … a nice interface … restrict its rights properly … edit /
   modify existing services"). `server/service.js` (pure): a model
   {name, summary, domain, execType, exec[], files[{kind, type, paths,
   access}], self[], caps[], net{listen, connect: [{proto, port}]},
   access[], extra[], permissive, provides[]}; catalogs FILE_KINDS (decl
   helper + suffix alternatives, first that exists: files_runtime_file /
   _runtime_t upstream+CLIP vs files_pid_file / _var_run_t RHEL,
   init_unit_file vs systemd_unit_file), ACCESS_GROUPS, SELF, CAPS,
   PROVIDES, chosen from a survey of the 327 Fedora daemon modules.
   `unitsOf(model, ctx)` = unit key → {sig, stmts}; a new module is
   rendered whole (`renderTe/If/Fc`); an existing one is edited by unit
   diff (`editTe`): units whose sig changed delete their old statements
   (plus `own` = rules on the type that recognition attributed to the unit)
   unless the new model still generates them, and insert missing new ones
   (decls after the last declaration, local after the domain's last
   top-level rule, optional blocks after the last one; self perms edit the
   class's line in place). Only statements at top level or directly in one
   optional_policy are editable (`scanTe`); everything else mentioning the
   domain is `kept`. `recognize()` reads a module back (file types by decl
   helper, access by key pattern, net from corenet_*_port calls, catalog
   items when all calls present, remaining single-argument calls → extra;
   generic corenet calls never extras). fc edits only for types whose
   paths changed; paths shown as `/dir/` = `/dir(/.*)?`. CRLF preserved.
   Server: requests `selinux/serviceList`, `selinux/serviceInfo` {module?,
   domain?} (catalog, port types from network_port calls, 1-arg
   interfaces, layers, recognized model, kept, provided),
   `selinux/servicePlan` {model, module|null, where} (texts + line diffs +
   modules.conf line for a new tree module in the effective conf's last
   part; refuses removing a file type referenced elsewhere). `serviceCtx()`:
   optional = defining module not base (moduleKinds) or layer not
   kernel/system; moduleArgs from the tree's policy_module majority.
   Client: `showServiceEditor` webview (`media/service.js`, form + preview
   + Create/Apply as one WorkspaceEdit, saved; stale banner when the files
   are saved elsewhere). Tests: test/service-test.js (+ every daemon module
   of a tree as argument: 326/326 no-op identical, 4890/4890 edits), test/
   service-e2e.js (CLIP, RHEL 9, RHEL 10 builds + standalone).
   Booleans (done, 0.9.0): model.booleans [{name, desc, default,
   external, _new (UI), grants: {self, caps, net, access, extra}}].
   Statement keys under a boolean are `b:<name>:<key>` (`scoped()`);
   scanTe marks statements in a plain `tunable_policy(\`b', ...)` (one
   name, no else) as {bool, tun}, also inside optional_policy (opt +
   bool); combos/else/`if` stay kept. Units `tunable:<name>` (gen_tunable
   + `## <desc>` comment, own = call + comment range; a changed default or
   description is rewritten in place) and `b:<name>:...` grant units
   (`grantUnits(g, prefix, bool)`; port items under a boolean put their
   socket perms and generic corenet calls at the top level). editTe inserts
   into the boolean's existing top-level tunable block (or optional >
   tunable for optional calls), else new blocks after the domain's last
   rule; emptied tunable/optional blocks go, inner first. Validation (only
   for grants new against `opts.baseline` = recognized model): already
   always allowed (duplicate type_transition fails expand, found with
   mta_send_mail), and `ctx.condSafe` (server `makeCondSafe()`: interface
   body minus gen_require, recursively through bodyCalls, has no
   typeattribute/attribute/type/role/optional_policy/tunable_policy/if/
   role allow — checkmodule refuses those in conditionals; found with
   dbus_system_bus_client). 0 of 766 Fedora in-tunable calls flagged;
   981/7427 interfaces unsafe (UI hides/disables them under booleans).
   Server: `serviceBools()` (existing booleans for the picker), removing
   a boolean still referenced elsewhere is refused. Tests: 22 mutation
   kinds, 7172 Fedora edits; e2e: new service with a boolean + an external
   one, ntp + new boolean, rsync's own boolean edited, all build.
   Port types (done, 0.9.0): model.ports [{name ('' = module name),
   nums: [{proto, port, level}], _new}]. Tree (`ctx.corenet`): server
   `networkPorts()` parses network_port calls of corenetwork.te.in,
   `ownedPorts(mod)` = those named mod or mod_* on one line (passed to
   recognize as opts.ports and to plan as corenet.ports);
   `service.editCorenet()` rewrites changed lines and inserts new ones
   alphabetically; plan returns `net`, servicePlan adds a file of kind
   'net'. `portCtx()` makes ctx.has true for the corenet_* names of new
   ports (checked against `ctx.portRef`'s, e.g. http). validate: names,
   numbers/ranges, exact duplicates of `ctx.portNums` (error), overlaps
   (note), unused (note). Standalone: unit `port:<T>` = type + corenet_port
   + "# Port numbers…/#\tsemanage port -a …" comment (read back from it,
   rewritten in place like tunables), net items on own ports are plain
   allow rules (scanTe now keys allow rules: `allow:src:tgt:cls:perms`).
   Upstream refpolicy has no corenet_udp_sendrecv_X_port: UDP connect = the
   generic rules + client packets (recognized when the tree lacks it); a
   port type exists when corenet_tcp_bind_X_port does. e2e: svctest with a
   port type (portcon checked in the built corenetwork.te), ntp_port_t +
   tcp 47124, standalone develsvc_port_t; CLIP, RHEL 9, RHEL 10 pass.
   Helper domains (done, 0.9.0): model.helpers [{name ('' =
   %_helper), domain?/execType? (recognized names not NAME_t/NAME_exec_t),
   exec[], signal, decl ('domain_type' | 'application_domain' as read),
   files [{type, access}] (the service's file types), self, caps, net,
   access, extra, _new}]. Units `helper:<H>` (types, decl calls, `role
   system_r types H;` (scanTe now has kind 'role'), domtrans_pattern(D, HE,
   H) with dom D), `h:<H>:signal`, `h:<H>:file:<T>`, and grantUnits(h,
   `h:<H>:`, null, H) (statements carry `dom`; helper self keys
   `h:H:self:cls:perm`). recognize: a top-level type with domtrans_pattern(D,
   HE, H) + (domain_type + domain_entry_file | application_domain), not
   another daemon; grantsIn(…, S=H) top level only; 1-arg calls on H →
   helper extras. editTe: self-rule scopes '' / bool / '@H'; helper
   statements after H's last rule, else a new "# H local policy" section at
   the end (header removed with the helper); decls now end at the first
   "local policy" header when there is one. validate: names, clashes, file
   types, interfaces, and one path labeled for two types (setfiles refuses
   it; found by the e2e). servicePlan refuses removing a helper whose types
   are used elsewhere or by kept lines. Webview: Helper programs section
   (grantsEditor shared with booleans). Fedora: 17 helpers recognized; e2e:
   svctest_helper_t (transition checked in tmp/svctest.tmp), ntp + a new
   helper, standalone develsvc helper; CLIP, RHEL 9, RHEL 10 pass.
   Hover help: `HELP` in server/service.js (file kinds with {T} = the
   type, access levels, access/self/caps/provides) goes out as `help` in
   `catalog()`; the webview sets it as `title` (`tipOf()` substitutes the
   module name on hover); service-test checks every catalog item has help
   and every button/field/checkbox in the form has a title.
   More services and login services (done, 0.10.0; user: "why does
   the service editor not handle ssh and xserver", then "do A and B"):
   ENTRY_CALLS (init_daemon_domain, init_ranged_daemon_domain,
   init_system_domain, init_ranged_system_domain, init_domain,
   init_ranged_domain); `daemonDomains()` lists domains of any of them
   (init_daemon_domain's program type wins); recognize sets
   `model.entries` [{name, args (range)}] from top-level entry calls with
   (D, E) and `model.declaredBy` {name, args, execToo} when no `type D`
   statement exists and a top-level call's def declares `$1_t` with D =
   args[0]_t (ctx.declares(name) → declPattern patterns; server
   treeServiceCtx and the survey provide it); unitsOf's domain unit renders
   declaredBy-or-type(D), type(E) unless execToo, and each entry (default
   init_daemon_domain) — sig {D, E, entries, by}. Logins: ACCESS_GROUPS
   group (loginpgm, sessions, loginrecords, lastlog, faillog,
   usercontexts, ttys, ptys) + `model.loginPty` unit (type
   <D-stem>_devpts_t, term_login_pty, allow D P:chr_file { rw_chr_file_perms
   setattr_chr_file_perms relabelfrom }, term_create_pty(D, P); recognized
   when that type has term_login_pty; catalog.loginPty when the tree has
   both interfaces; form checkbox in the Logins group). editTe treats all
   entry calls as declarations. serviceModules regex accepts every entry
   call. validate accepts HOME_DIR/ and HOME_ROOT/ paths (RHEL xserver).
   Survey: every domain of every module with an entry call (488 domains,
   376 modules; 29 mutation kinds, 14,152 edits). e2e section 5 (CLIP,
   RHEL 9, RHEL 10): xdm_t, xserver_t, sshd_t + a capability (one line),
   new login service logintest with the options and pty, one tree build.
   Finding interfaces (done, 0.10.0; user: "let us add other
   interfaces … help us find the one we want", items 1 and 3 of 4 offered):
   server `selinux/findInterfaces` {domain, target | path, tclass, perms}
   (path → type with matchpathcon on the tree build's tmp/all_mods.fc or the
   host's; then suggestInterfaces() on one synthetic missing group with
   limit 12 against `policyForRanking()` = tree policy.bin / linked module /
   running policy) and `selinux/interfaceGrants` {domain, names} (probe
   expansion, statements per call formatted as rules + added attributes,
   cached per probe dir/build/index). Webview: `findByNeed()` (NEEDS: class
   → [label, exact perms], custom perms) under the keyword search, results
   like the denial cards with Add; `grantsToggle()` ▸ on extra chips,
   keyword hits and found rows (grantsInfo / grantsSlots, refilled on the
   'grants' message, reset when the domain name changes). Fixed on the way:
   ownReq in suggestInterfaces spread idx.generatedAt()'s Set (crashed in
   trees for port types). Keyword ranking (item 2, done, 0.10.1):
   serviceInterfaces drops interfaces whose doc param isn't a domain
   (/domain|^user/ and not /prefix/), adds `t` (types of the def's own
   gen_require, 8 max) and `c` (number of .te files calling it); webview
   `ifaceScore(it, words)`: per word the best of name part 4, module 3.5,
   type part 3, name substring 2, summary word 2, type substring 1.5,
   summary substring 1 (SYNONYMS alternatives ×0.6; a word ending _t that
   is exactly a required type 6); every word must match; +3 when the name
   is or starts with the words joined by _; −3 dontaudit, −1.5 RARE parts
   unless typed; + 0.8·log10(1 + uses); − length/100. 25 shown, "N more…".
   Custom file access (done, 0.10.2; user asked what "label only"
   means for CLIP's httpd_cache_t, which httpd_t actually manages via
   mmap_manage_files_pattern): recognize sets row.access 'custom' and
   row.rules (statement texts) when the level found is none but the file
   unit's own statements include rules from D (calls with D first, allow
   from D); unitsOf renders custom like none (decl only), so the kept rules
   survive while the sig is unchanged and are deleted when another level is
   chosen. ACCESS_LABELS/HELP.level custom; row.ruleLines (0-based .te
   lines). The form (customRules) lists them under the row: click opens
   the line, ▸ / "Show what they allow" ask server `selinux/expandStatements`
   {items} (the statements written into the probe .te between "# zzitem N"
   comments, which m4 copies unexpanded; parseStatements per chunk +
   type_transition lines) and show the compiled rules / a per-class
   summary for the domain; warns when another level is picked. validate
   refuses loginPty when <D-stem>_devpts_t is a file type already (found by
   the survey: ipsec_mgmt_devpts_t). Fedora: 313 file types custom, 0 left
   "label only" with access; survey mutation 30 = custom → read.
   Build target fix (0.10.2; user hit "This file is outside the policy
   tree" from Build the policy with the CLIP clone as workspace):
   buildRequestTarget falls back to treeRoot for anything outside trees and
   modules (not inExcludedTree; on-save builds still use buildTarget only);
   selinux.buildModule takes 'tree' (views pass it; ignores the active
   editor); webview buildHint() adds Build now (cmd build) to errors that
   mention a build.
   Grouping long lists (item 4, done, 0.10.2): extraSection groups
   model.extra by module (info.interfaces m, else the name's prefix) when
   more than GROUP_AT = 12: details.egroup per module (sorted; open state in
   openGroups), chips sorted; filter input narrows in place (chip.match =
   name + summary + module, groups hidden/opened, counts "n of m", status
   line) without re-render; Expand all / Collapse all. render() now restores
   the sections' open state from `.card` elements only (nested details
   would have broken the index-based restore).
   Read-only denials (done, 0.10.1; the user's open question, answered
   "do it"): rankInterfaces sets `writes` (perm weight > 1 beyond the need)
   and, when every denied perm has weight 1, scores writes candidates ×20;
   tag *writes* in both UIs (service editor: when findInterfaces says
   `readOnly`). Benchmark: exact 57%, top 3 90%, top 5 98%; "original or
   narrower first" 95% (was 98%: a read-only one may now beat a narrower
   writing one, by design).
   Standalone modules as RPMs (done, 0.10.0; user: "make them a stand
   alone module … package the service and the policy in an RPM"; target =
   the build host's devel headers): `isStandaloneModule(p)` = module file in
   a workspace root, outside the active tree's policy/ (and excluded trees);
   `buildTarget` → its .te → `moduleBuild` (devel Makefile; error result if
   missing). `develInterfaces()` parses include/<layer>/*.if (+ distributed/)
   for interface/template names → layer, cached by dir mtimes.
   `serviceCtx(standalone)` wraps `treeServiceCtx()`: has = devel names,
   optional = layer not kernel/system, corenet false, moduleArgs 2,
   moduleExists also devel modules, portRef from devel. serviceInfo
   {standalone} (new) / location (existing): catalog, ports and interfaces
   filtered to the devel headers, `canStandalone`, `folderSuffix` '-selinux';
   servicePlan {standalone}: `newServicePaths(name, where, true)` =
   <roots[0]>/<name>-selinux, no corenetwork/modules.conf, and once
   (absent files only) `server/packaging.js` specText (independent
   <name>-selinux package: %selinux_requires, selinux_modules_install /
   uninstall, relabel_pre/post, .pp.bz2 in /usr/share/selinux/packages/
   targeted, .if in devel/include/distributed, %ghost active/modules/200,
   semanage port add/delete for the module's port numbers, version from
   policy_module, packager from git config, License chosen in the form:
   packaging.LICENSES (10 SPDX ids) + settings packaging.customLicenses +
   Custom… field; default packaging.license = MIT (the user's call; repo is
   MIT); `licenseProblem()` refuses empty, %, #, newlines, > 200 chars;
   serviceInfo `licenses` {common, custom, default} for standalone (null for
   an existing module that has a spec); plan/apply carry `license`; client
   `saveLicense(lic, asDefault, defaultOnly)` updates the settings (workspace
   level if set there, else user), skips common ones in the saved list,
   answers `licenseSaved`; exported for the stub-vscode test in
   service-test.js) + makefileText (make / make rpm
   with _sourcedir/_topdir). serviceModules includes standalone modules;
   denialFix targets them (optional per the devel ctx). Webview: Module
   radio (in the tree / standalone) when canStandalone; switching re-inits
   with keep (model kept); plan/apply carry standalone. Client command
   `selinux.buildRpm` (spec of the active editor's folder or a pick → `make
   -C dir rpm` in the "SELinux RPM" terminal). test/package-e2e.js (melody,
   CLIP copy inside a workspace folder): RHEL helper variants, tree-only
   interface refused, build, make rpm, rpm -qpl/--scripts/-qpR, magic of the
   packaged .pp, read back, edit touches only the .te, tree untouched.
   File access under a boolean (done, 0.11.0; user: "go ahead and do
   file access under a boolean"): b.grants.files [{type, access}] (the
   service's file types, resolved names like helpers'). unitsOf: unit
   `b:<name>:file:<T>` = levelStmts() (shared with top level and helpers)
   scoped to the boolean, plus the kind's filetrans only when the always-on
   level is none/read (a duplicate type rule fails expand) and ctx.condSafe
   allows it; sig {access, ft}, so raising the always level drops it.
   recognize: grantsIn(bool) finds patterns (D, T, T) in the boolean's scope
   for each model.files type → level, ownAdd the block's other pattern/
   filetrans/allow rules on T; no level → kept. validate: removed file type
   (error), a level the always level covers (LEVEL_RANK; note). Webview
   boolFiles(b): per file type a select ("no more" + the kind's levels)
   and "always: …"; removing a file row drops its boolean grants; changing a
   row's level re-renders when there are booleans. Tests: service-test
   (render, read back, no-op, edits, hand-written module, form), survey
   mutations 31/32 (15,616 Fedora edits OK), service-e2e (svctest: state
   read always + manage and /var/lib filetrans under the boolean, built as
   `if (svctest_connect_any)`; ntp: manage ntpd_key_t under a new boolean)
   on CLIP, RHEL 9, RHEL 10.
   Other ways to start a service (done, 0.11.0; user asked why bugzilla
   isn't in the editor, then to survey all other module kinds; of the six
   found, "do 2-5 first"): START_CALLS dbus_system_domain, mta_mailserver,
   mta_sendmail_mailserver (one argument; ENTRY_EXEC gives sendmail_exec_t,
   model.execElsewhere = no `type E` here, the domain unit then omits it),
   inetd_service_domain / _tcp_ / _udp_ / _core_, ucspitcp_service_domain,
   cron_system_entry; ENTRY_CALLS = INIT_CALLS + those, ENTRY_RE (server
   serviceModules, survey). daemonDomains ranks init_daemon_domain, other
   init_*, others. recognize: entries also in optional_policy (not under a
   boolean). unitsOf entryStmt: ALSO (dbus, cron) with ctx.optional →
   local/opt (optional_policy), others decl at top level. STARTS {main,
   also} → catalog.starts (only ctx.has; `off` = server ctx.off(n): the
   defining module is off in moduleKinds); validate: new with no entries,
   unknown names, two main ways, a main way whose module is off (unless
   the same entries as the baseline). Webview startsRows(): Started by
   select (off ones disabled; "as written: …" for entries the list doesn't
   offer; "only as ticked below"), Also: checkboxes. Tests: service-test
   (render, read back, removal, inetd main, validation, sendmail-like,
   optional-only accountsd-like, form), survey mutations 33/34 (Fedora 523
   domains in 397 modules, 17,782 edits), service-e2e section 7 (accountsd,
   colord, geoclue, comsat, dbskk, tcpd, sendmail, certwatch, backup:
   no-op unchanged + one capability line; new starttest by inetd + D-Bus +
   cron, built; CLIP: inetd off → refused, systemd used) on CLIP, RHEL 9,
   RHEL 10.
   Template-started daemons (done, 0.11.0; "go ahead and do 1 next"):
   service.makeStartsVia(getDef)(name) → [{d, e, via}] in $N terms, through
   bodyCalls (not cond) with $N substituted, memoized, depth 5;
   daemonDomains(te, ctx) adds domains of top-level calls whose template
   starts one ({template: {name, args}}; attached to a domain already found
   through its own start call, e.g. cron added). recognize: dom.template →
   model.declaredBy {name, args, execToo, starts: via} (claimed); unitsOf:
   no default init_daemon_domain when by.starts; editTe treats the template
   call as a declaration. Server startingTemplates() (cached per idx.defs):
   names whose body starts something + regex for serviceModules; ctx
   startsVia. Webview: Started by = "its template X(args) (via)". Fixed on
   the way: existing port types without numbers (CLIP milter_port_t) were
   an error (now only new ones). Fedora: 660 domains / 414 modules, 150 by a
   template (138 started by it), 22,440 edits; e2e section 8: nfsd_t,
   gssd_t, fenced_t, systemd_logind_t, spamass_milter_t (+cap, built) on
   CLIP (34 listed), RHEL 9 (110), RHEL 10 (129).
   Web applications (done, 0.11.0; "go ahead and do 6"; bugzilla was
   the user's example): WEB_TEMPLATE apache_content_template;
   webPatterns(ctx) = its declPatterns (ctx.declares) → {template, d
   (*_script_t), e (*_script_exec_t), content {content, rw, ra, htaccess}}
   (Fedora $1_…, upstream httpd_$1_…); WEB_KINDS labels/help/default paths.
   daemonDomains: top-level calls of it → {web: {name, args}} (attached to
   a domain found through its own start call too). recognize: dom.web →
   declaredBy {…, web: true}, model.webapp (patterns), model.content {id:
   paths} from the .fc, exec = script paths (no implied --). names(): web
   models from the patterns (webStem = declaredBy.args[0] or model.name);
   unitsOf: a new web app is declared by the template call, no entries.
   fcEntries/editFc include content types; validate: no "Nothing starts"
   for web apps, "no CGI script paths" note, apache off → refused for new.
   Paths: fcFromPath reads a trailing " -d"/" --"/… flag (FT_SUFFIX);
   recognize's pathsOf(T, exec) appends the fc's flag when the path doesn't
   imply it (impliedFtype); validate's one-path-two-labels check keys on
   spec + flag (CLIP bugzilla: same dir -d content, -- scripts). Server
   startingTemplates() also returns web (patterns) and adds the template to
   the module regex. Catalog webapp {…, off, kinds}. Webview: What radio
   (new), setWebapp(on), CGI scripts row, "Run by" row, contentSection()
   (Web content), titles. Tests: service-test (catalog, new web app Fedora
   names, read back, no-op, CLIP bugzilla with -d/--, ra path added, apache
   off, form switch), survey mutation 35 (Fedora 685 domains / 420 modules,
   25 web apps, 23,975 edits), service-e2e section 9 (bugzilla no-op + cap +
   ra path; new webtest built, its rw path in tmp/all_mods.fc).
   Module kinds still not handled (survey 2026-10-12, Fedora + CLIP):
   all six agreed kinds are done. Out of scope so far: application_domain /
   userdom_user_application_domain programs, domains entered directly
   (keyutils, passenger, openca), roles, kernel-layer modules.
   gen_bool booleans / raw `if (...)` blocks: not needed (checked
   2026-10-12). No module the editor opens uses them: Fedora/RHEL has 2
   gen_bool, CLIP 3 (+4 if blocks), all in kernel-layer modules
   (kernel.te, selinux.te); services use gen_tunable (Fedora 336, CLIP
   270). Such blocks stay kept as is.

7. **Tutorials** (done, 0.9.0; user request: "tutorials … integrate
   them into the vsix … how to use the add-on and how it can help them
   making and maintaining SELinux policies"). package.json
   `contributes.walkthroughs`: getStarted (8 steps), services (10; webapps added in 0.11.0), denials
   (4), lockdown (11: levels + wrappers added 2026-10-13, hostchanges, contexts 2026-10-22); pages in media/walkthroughs/<wt>/<step>.md; step
   buttons are `command:` links (openTutorials takes a walkthrough id as
   URL-encoded JSON arg). Client `registerTutorials()`: selinux.openTutorials
   (quick pick or id → workbench.action.openWalkthrough
   `<extension.id>#<id>`), selinux.createPracticeModule (copies
   media/practice into <folder>/selinux-practice via workspace.fs, opens it;
   globalState `selinux.practiceOpen` makes the reloaded window show
   notesd.te with the walkthrough beside it), a one-time offer
   (`selinux.tutorialsOffered`), Policy Explorer viewsWelcome + book icon.
   Practice module notesd: mistakes lisen (unknown-perm), misspelled
   logging_send_syslog_mesg, urandom_device_t without require (appears only
   once the interface is fixed: an unknown call makes the scope uncertain),
   missing gen_require in the .if. Its selinux.checks avoids plain `read` on
   shadow_t (RHEL: `allow domain file_type:file map` under
   domain_can_mmap_files). Tests: test/walkthrough-test.js (npm test: pages,
   buttons, completion events, "SELinux: …" names, settings, every
   contributed command registered), test/tutorial-e2e.js (melody: the
   mistakes, quick fixes applied, build, Compiles-to hover, checks hold).
   The user checked the walkthroughs in VS Code (2026-10-11): fine. The
   "Code collects usage data" line under them is VS Code's telemetry
   notice (gone with telemetry.telemetryLevel off), not ours.

8. **Denial assistant** (user picked it from suggested features; plan agreed
   2026-10-11): from an AVC denial to the smallest correct fix.
   Phases: 1 parse/group/verdicts (done, 0.10.0), 2 interface
   suggestions (done, 0.10.0), 3 apply + verify after build (done,
   0.10.0), 4 (done, 0.10.0): no transition into the domain,
   two-interface covers, new interface in the owner module,
   constraint/MLS explanations, a tutorial quick action.
   Phase 1: `server/denials.js` (pure): `records()` (audit.log /
   ausearch --raw, ausearch -i " : " stamps, kernel `type=1400 audit(...)`,
   bare "avc: denied" lines; RHEL ENRICHED text after \x1d dropped),
   `parseDenials()` joins AVC/USER_AVC (fields inside msg='...')/SELINUX_ERR
   with SYSCALL (exe, comm), CWD and PATH (item whose basename = AVC name,
   NORMAL/CREATE first) by event stamp; hex fields decoded (name, exe, comm,
   cwd, path, proctitle). `groupDenials()` by source type|target type|class
   (events counted once). `verdict(g, te, labels, policyName)`: error,
   unknown type/class, label (expected ≠ target; create → dir label or type
   transition; relabeled since → no fix), boolean (only when no perm is
   missing; picks the setting covering all perms, fewest changes), allowed
   (constraint/MLS hint), generic (GENERIC_TYPES, file classes only),
   missing (`needed` raw rule, self when s = t). policy_query.py op `avc`
   (per perm allowed / boolean with `cond_options` brute force over the
   expression's booleans, rules on the type itself first / missing;
   permissive domains; `self.conds`, `bool_defaults`). Server:
   `denialPolicies()` (installed: `fc` null for the running one so
   matchpathcon uses its defaults incl. .local; build: tree policyBin +
   workDir/file_contexts or tmp/all_mods.fc, devel: linkedPolicy()),
   `runningBooleans()` (/sys/fs/selinux/booleans), `denialLabels()`
   (matchpathcon -m <mode> [-f fc], stat -c '%n\t%C'); requests
   `selinux/denialPolicies`, `selinux/analyzeDenials` {text, against}
   (default: running installed, else build). Client `showDenials`
   (media/denials.js): ausearch runs as `sudo ausearch ... > f.part; mv f.part
   f` in the "SELinux Denials" terminal, fs.watchFile picks it up; fixes go
   to that terminal with sudo and no newline. Command
   `selinux.analyzeDenials` (selection/document with audit records
   prefills), Policy Explorer shield icon, linked from the denial
   walkthrough. Tests: test/denials-test.js (npm test: parsing, grouping,
   verdicts, webview), test/denials-e2e.js (melody: running targeted policy
   verdicts, standalone build linked, CLIP tree build with its
   all_mods.fc). Not yet tried interactively.
   Phase 2: server `suggestInterfaces()` for groups with verdict missing
   (max 25; `suggest: { verdicts, max, limit }` param widens it for the
   benchmark): own types (s = t, or same module per sourceLocation) →
   `{ own, module, rule }`; else candidates = `interfacesRequiring()`
   (name → interface defs, kind interface, maxArg 1 or generated, whose
   `callRequires(..., ['zzprobe_domain_t'])` include it; cached per
   idx.defs) for the target (own-require first, then the owner module's,
   cap 600) + its attributes of ≤ 300 members (from typeinfo, 80 max).
   Owner module: declaring module, else (devel headers) the module whose
   interfaces most often require the type themselves. `build.expandCalls()`
   runs the policy's Makefile with `--eval 'zzprobe_m4: ; $(M4) $(M4PARAM)
   -s $(m4support) [generated_definitions.conf] all_interfaces.conf
   tmp/zzprobe.te > tmp/zzprobe.out'` in the tree build's workDir (needs a
   build) or the module build dir / a scratch dir (devel Makefile, rule
   depends on tmp/all_interfaces.conf); ~0.2 s for 500 calls.
   `denials.probeStatements()` splits by `##### begin X depth: 1` / `end
   depth: 0` markers, statements of deeper calls marked `nested`;
   `parseStatements()` (allow-like rules with flattened/nested sets, ~ and *
   → '*', exclusions dropped; typeattribute; require skipped; if/else blocks
   → cond). policy_query op `typeinfo` {names, sourceRules} → sizes,
   a type's attrs, allow rules of added attributes. `rankInterfaces()`:
   covers = unconditional rules (domain or added attributes as source) on
   the target or its attributes for the class; extra = Σ per type|class
   (deduped) size × permWeight (reads 1, WRITE_PERMS 3, EXEC_PERMS 5), the
   denied perms on the type itself free; owner ×0.8, module off last;
   `grants` top 4 per type; `broad` > 50×best+300. Webview: "Suggested
   interfaces" rows (call link → definition, Copy, tags narrowest / owner /
   broad / module off / lacks / has boolean rules, also grants, adds
   attributes). test/denials-bench.js (melody, `npm run
   test:denials-bench` = 1500 calls, ≥ 90% first / 80% top 3): top-level
   `iface(domain_t)` calls of other modules in RHEL 9 contrib .te, the
   interface's own (non-nested) rule with the most non-read perms → a denial;
   98% original-or-narrower first (57% exactly), 90% top 3, 98% top 5.
   Phase 3: `denials.insertFix(text, {domain, call | rule, optional,
   module})` on service.scanTe: calls among the domain's 1-arg top-level
   calls after the local-policy header, after the closest alphabetical
   predecessor (`afterPredecessor`; large modules are only roughly sorted);
   optional → inside the top-level optional_policy whose inner calls all
   start with `<module>_` and include the domain, else a new block placed by
   its first inner call name; rules after the domain's last allow; already
   present (top or optional, not under a boolean) → {already}; blank lines
   fixed only at the seam; CRLF kept. `localModuleText()`. Server
   `selinux/denialFix` {domain, call | rule}: `domainModuleFile()` (type decl
   in a workspace .te of the active tree), optional = serviceCtx().optional
   and interface module ≠ domain module; devel mode without a declaring
   .te → `<root>/local_<domain minus _t>/local_<…>.te` (insert if it exists).
   Client `applyDenialFix()` (WorkspaceEdit, save → build on save, select
   the inserted lines) and forwards every final `selinux/build` to the
   panel as `built`; webview `fixes` map (planning / plan / applied /
   resolved / still / failed), on `built` with an applied fix re-analyzes
   with against 'build' and marks verdict allowed as resolved; `opened`
   keeps toggled cards. e2e: standalone call + optional call + local module
   for httpd_t + CLIP copy apache.te, each rebuilt → allowed.
   Phase 4: policy_query ops `constraints` {s, t, c, perms} (evaluates
   constrain/mlsconstrain postfix expressions: sets of names (types expand
   attributes), ==/!=/dom/domby/incomp on setools Levels from lookup_range;
   returns failing constraints with each comparison's values; self.policy
   kept) and `entrypoints` {types} (domains with allow D T:file entrypoint
   written for T itself, not via attributes). Server: after the avc query,
   groups whose perms are all allowed get te.constraints;
   `denialTransitions()` for sources in UNCONFINED_SOURCES with an exe:
   matchpathcon + stat of the program, entrypoints of its types; generic when
   unconfined/initrc domains enter it, else domains sorted <stem>_t first.
   `moduleFileContexts()`: in devel mode the 'build' policy's fc = running
   file_contexts(+homedirs,+local) + the module's tmp/<mod>.mod.fc.
   verdict(): unknown → transition (wrong label / not running in D (shell or
   transition; relabel hint when the current label is unknown) / no policy
   → action newService) → constraint (when TE allows all) → label (only when
   TE doesn't allow all) → boolean → allowed → generic → missing;
   `constraintVerdict()` words MCS (chcon -l), UBAC (chcon -u), roles.
   rankInterfaces adds `combos` (pairs among the first 40 partials whose
   union covers, by extra, top 3) when nothing covers; `newInterfaceText()`
   (<module>_<verb>_<stem>_<class>s, verb read/rw/manage for file classes,
   the perm or 'use' otherwise, unique suffix, XML doc, gen_require type,
   exact perms); server `proposeInterface()` (owner .te in the workspace,
   not the domain's own module) → suggest.newIface; denialFix takes
   `calls` (pairs) and `newInterface` {target, tclass, perms} → plan.also
   = the owner .if, call optional per `moduleOptional()`; client applies
   also files in the same edit. Webview: badges domain/constraint, New
   Service… button (client → showServiceEditor(ctx, null, {exec}), server
   serviceInfo prefill → model.exec + name from the basename), pairs and
   new-interface rows, plans listing both files. Practice:
   media/practice/sample-denials.log (label, http → corenet, own log rule,
   unconfined_service_t); `selinux.analyzeDenials` arg 'practice' opens it
   against 'build'; denial walkthrough button; TUTORIAL.md section 6.
   Tests: denials-test (verdicts, pairs, names, cards), denials-e2e (svirt
   MCS, chronyd/true transitions, CLIP ntpd_extra_t new interface flow,
   prefill), tutorial-e2e (the sample denials + fix).

9. **Users and logins** (user request 2026-10-12: "start looking more at
   MCP and users (service accounts?)"; picked 1 + 2 of the suggestions,
   view first; "service accounts" = both automation logins and daemon
   run-as accounts; MCS / Model Context Protocol later).
   Phase 1, Logins and Users view (done, unreleased): `server/logins.js`
   (pure: parseSeusers (%group, l), parseContexts, entries(userRoles,
   roleTypes, userFile, defaultFile) = system_r sources, user file first,
   contexts filtered to the user's roles + role types, ENTRY_LABELS/ORDER;
   parsePasswd/parseGroups, mappingFor (own > first %group > __default__,
   as getseuserbyname), serviceAccounts (uid < UID_MIN or 65534, login
   shell?), pathTo/nearest/stepText, mappingNotes, ABILITIES).
   policy_query.py ops `users` {types, names} (users' roles + range, role
   types ∩ types, which names exist), `reach` {user, starts, access} (BFS
   over (role, type) states: transition + entrypoint ∩ exec types or
   dyntransition + setcurrent; role R2 of the user with t in its types and
   R2 == R or allow R R2, changed by role_transition on an entrypoint or
   setexec; `proc_ok` evaluates the non-MLS process constraints with u1 =
   u2; steps keyed "role:type", reached[type] = first state; access items
   {attr} or {t, classes, perms} → reached domains with it), `access`.
   Server: loginConfig(pol) (tree build: appconfigDir() files via
   readSource; installed: /etc/selinux/<name>/seusers, contexts/
   default_contexts, contexts/users/<u>; devel build: the running one,
   host true), loginPolicy (denialPolicies entries, linked for devel),
   userReach cache per bin mtime + starts; requests `selinux/logins`
   {against}, `selinux/loginReach` {user, starts}, `selinux/loginCan`
   {user, starts, target | path, tclass, perms} (path via matchpathcon
   with the policy's fc). Client showLogins (media/logins.js), command
   `selinux.showLogins` (Policy Explorer person icon), reloads after a
   build when on 'build'. Tests: test/logins-test.js (npm test),
   test/logins-e2e.js (melody: running targeted + CLIP build). RHEL 9:
   report ~9 s, staff_u reaches 867 domains (sysadm_t via newrole_t,
   setexec, only while secure_mode is off), user_u 100 (/etc/shadow only as
   chkpwd_t). The user tried it in VS Code ("That seems to work").
   Phase 2a, new users in a tree (done, unreleased; "go ahead with the
   user editor"): service.js model.user {kind} (USER_KINDS: unpriv,
   restricted, restricted_x, admin, confined = userdom_confined_admin_
   template | userdom_base_user_template; names(): R/U), unitsOf
   userUnits(): domain unit = `role R;` (scanTe kind 'roledecl') + the
   template (declaredBy kept for existing), `rc:<n>` role calls with
   roleCallArgs(n, model, ctx) by ctx.params(n) doc names (prefix → name,
   exec_domain → NAME_application_exec_domain, role → R, domain|^user → D;
   null when one can't be filled), `switch:<R2>` = roleIfaces[R2].change,
   `from:<R0>` = roleIfaces[R0].changeTo; grants/booleans as services.
   USER_PROVIDES role_change / role_change_to (.if); validateUser; newUserModel,
   userCatalog. server/userfiles.js: WAYS (ssh sshd_t+sshd_session_t,
   console, graphical, cron, rlogin), parseGenUsers (ifdef in roles → not
   simple), genUserLine, editUsers (new line + comment at the end, own
   line rewritten, role added to grantUsers' lines before an ifdef / removed
   for prevGrant), editKernelRoles (users file is compiled into base: `role
   R;` after kernel.te's last top-level role line — the build failed with
   "unknown role" without it), parseSeusers/editSeusers (before
   __default__), contextsText (ways → R:D; sudo/su lines R:NAME_sudo_t →
   own context then switch roles' R2:stem_t). Server: effectiveUsersFile
   (spec overlay files['policy/users']), defParams, roleIfaces() (from
   *_role_change(_to) defs' role requires), userRoleCalls (g login|admin|
   apps|run; needs a role param unless *_role), userCtx, requests
   `selinux/userInfo` (prefix default = shared majority prefix unless most
   users have their own), `selinux/userPlan` (te/if/fc in roles/, users,
   kernel.te, seusers, contexts, modules.conf; loginTaken). Client
   showUserEditor (media/user.js; EDITOR_CSS shared with the service
   editor), `selinux.newUser`, New User… in Logins and Users. Tests:
   test/user-test.js (npm test), test/user-e2e.js (CLIP + RHEL 9 spec: new
   login user + confined role, built, checked with the logins report).
   Phase 2b, existing users (done, unreleased; "lets continue with step b
   of the user editor"): recognize(texts, ctx, {user: true, module}) uses
   userDomain(te) (top-level USER_TEMPLATES call on one name → stem, kind;
   base template reads as 'confined') instead of daemonDomains; model.name =
   stem, model.module = module (role interfaces named after the module:
   unprivuser_role_change), declaredBy = the template call; role calls /
   switchTo / enteredFrom read back where the call's args equal
   roleCallArgs (catalog ctx.roleCalls, ctx.roleIfaces); mentionsD includes
   R. plan() passes user/module to recognize. userfiles.readUser fills
   genUser {exists, simple}, userRoles (all roles as written), level/range/
   cats/prefix, grantUsers, logins (seusers), ways (own contexts file, else
   default_contexts lines offering R:D, as libselinux falls back), waysDefault;
   editUsers with opts.prev: own line rewritten only when a field changed,
   roles = written roles ± switches added/removed (only newly added ones;
   staff.te switches to roles its line lacks); no new line for a role
   without a user (webadm); editContexts (ways/sudo/su toggled, lines
   added after the last non-blank, other lines and trailing blanks kept);
   editDefaults (a way turned off: R:D token off that source's
   default_contexts line, line dropped when empty — found by the survey:
   removing the own-file line alone falls back to default_contexts).
   userfiles.userTreeCtx(idx, base) (params, roleIfaces, roleExists,
   roleCalls; server userCtx caches it per idx.defs). Server userModules,
   userTexts, readExistingUser, existingUserPlan (notes: no gen_user line;
   ifdef line not rewritten), requests `selinux/userList`, `userInfo`
   {module}, `userPlan` {model, module}. Client: userPanels per module,
   `selinux.editUser` (quick pick, or a user name from Logins and Users'
   "Edit user…" on build reports), reload after Apply. Webview: name/kind
   fixed, ways from default_contexts marked, levels read-only for ifdef
   lines, Kept as is. Survey (`node test/user-test.js <tree>/policy`):
   no-op identical + 14 mutation kinds read back and idempotent: Fedora
   11/130, CLIP 11/126, RHEL 9 12/138, RHEL 10 12/141. e2e section 5 (edit
   staff, build, logins report) on CLIP, RHEL 9, RHEL 10.
   Phase 2c, standalone users + RPM (done, unreleased; "yes lets do step
   c"): server userCtx(standalone) takes the role catalog from
   develIndex() (a PolicyIndex of the devel include dir, cached per
   develIfCache key; RHEL's role calls differ from CLIP's), hostUsers()
   (running policy's seusers, users via policy_query `users`, which way
   sources exist), userModules() also standalone modules (m.standalone),
   userTexts standalone = module + contexts file next to it + spec,
   readExistingUser merges userfiles.readSpecUser (the spec's semanage
   lines → userRoles, level, range, prefix, logins, grantUsers),
   standaloneUserPlan (literal levels only, no categories, grantUsers on the
   host; files te/if/fc, NAME_u_default_contexts, once spec + Makefile),
   existingUserPlan standalone (module + contexts; logins/levels/grants →
   note pointing to the spec). packaging.specText({ user }): Source3 contexts
   file → /etc/selinux/%{selinuxtype}/contexts/users/NAME_u (%config
   noreplace), userScripts %post (semanage user -a … || -m, login -a per
   login with % → %%, role grant via `semanage user -l` awk with printf
   "%%s"), %postun (logins, user, grant removal, then the module);
   makefileText(name, extra deps). Webview: Module radio (standalone when
   canStandalone; switch reloads info keeping the model), License select +
   free text, standalone existing: logins/levels read-only, granted users
   disabled. e2e section 6 (CLIP workspace on melody): plan, RHEL-form sudo
   call, build, make rpm, rpm --scripts/-qpl, read back, no-op, edit; the
   RPM wasn't installed (needs root).
   Phase 2d, automation preset + reach preview (done, unreleased; "ok lets
   do step d"): webview automationPreset() (kind unpriv: restricted
   templates forbid setuid so sudo; ways ssh + cron; roleCalls
   sudo_role_template + cron_role; no extra rights; model.preset) and
   presetNote() (narrow role to switch to, sudoers line ROLE=/TYPE=).
   Server userPlan() factored out of the request; `selinux/userPreview`
   {model, module, standalone, license}: tree = buildTree(variant
   'userpreview') with the planned files as `files` overlays (spec overlay
   sources replaced by scratch copies, tree files added/replaced by
   tree-relative path); standalone = build.buildModule(te, planned texts)
   + linkWithInstalled; ways = logins.entries from the planned/current
   contexts file + default_contexts; roles from the built policy's user,
   else R + switchTo (policy_query reach takes `roles` for a user semanage
   will create); userReach(bin, U, starts, roles) (cache key includes
   roles), reachAbilities(); existing tree user: before = last build →
   gained (with paths) / lost. Webview reachBox (button, building, result,
   stale after a change). e2e section 7 (CLIP, RHEL 9): new tree user,
   staff without sudo loses staff_sudo_t, standalone linked. Found on RHEL:
   removing sudo_role_template from staff.te left an optional_policy with
   only a nested optional_policy (crontab_domtrans(staff_sudo_t)) →
   checkmodule "This block has no require section"; editTe now deletes a
   touched optional_policy whose remaining content is only nested
   optional_policy blocks or comments (service survey unchanged).
   Kind changes (2026-10-15, user hit "ro's global requirements
   were not met: xdm_t" on ricardo: their CLIP 8 workspace had no build
   settings, so no APPS_MODS and xserver off): userUnits keeps declaredBy
   only while its template belongs to the chosen kind, editTe replaces the
   template call on its line (inPlace 'domain'); server userCtx
   `linkBlockers(tpl)` (callRequires mandatory → types whose declaring
   modules are all off per idx.moduleKinds, which includes APPS_MODS; trees
   only) → catalog kinds[].blocked (service.blockedText), validateUser:
   error for a new/changed kind, Note when unchanged; webview kindChoices()
   for new and existing users (blocked disabled unless it is the user's
   own; info.kindWas). Tests: user-test (unit + form), user-e2e 5b.
   Step 9 released as 0.12.0. Login checks (done, 0.13.0; "ok lets add
   the login checks in selinux.checks now"): checks.js kinds login-reaches,
   login-may, login-maps (`never login <logins> …`), only-login /
   never-login (`<users> may log in`); tokens allow %group. Server
   runChecks sends the other kinds to policy_query `check` and evaluates
   login kinds in loginChecks(checks, bin): loginConfig({ build: true })
   (tree appconfig files, or the host's in devel mode), logins
   .resolveLogins (name → own line else __default__; %group own line only;
   * = every line), per user logins.entries → userReach, policy_query ops
   `names` (expand, KeyError → unknown) and `access_any` (first hits of
   reached domains on target types); results { login: [{ login, user, via,
   p, l, domain, path, rule, perms, target }] } → checkMessage / related
   info (seusers line, path steps, rule) / lens "✗ N logins violate it";
   completion: login, reaches/may/maps, to, seusers logins, "log in".
   Tests: logins-test (parser, resolveLogins), checks-e2e (CLIP: holds,
   __default__ → staff_u, alice reaches sysadm_t where it logs in, may read
   shadow_t as aide_t, errors, completion), module-checks-e2e (host seusers).
   Open (the user's "later" list): comparing with the host's semanage
   changes (MCS: done, step 12). Model Context Protocol / any AI: dropped —
   the user (2026-10-14): "We don't want to add AI to this plugin at this
   time" (verified: no AI, LLM, network or chat/LM API use anywhere in the
   extension). Plan agreed: kind of user from the tree's
   templates (Fedora 2-arg `X_role(R, D)` vs upstream/CLIP 4-arg role
   templates; userdom_unpriv/restricted/admin/base/confined_admin
   templates), roles it may switch to, ways in, sudo/su into a role
   (sudo_role_template, su_role_template), services it administers
   (*_admin), caps/access/interfaces/booleans as in the service editor;
   logins + range; writes the role module, gen_user line, seusers,
   <user>_default_contexts; standalone: RPM with semanage user/login and
   the contexts file; opens existing users with minimal edits; an
   "automation account" preset (restricted user, ssh/cron, sudo into one
   narrow role). Reuse reach as its preview.

10. **File labels + features menu** (done, 0.14.0; user 2026-10-13:
   "on melody if we use the clip policy for RHEL 9 what would the rpm
   program be marked with? … any binary or file on the system … see what
   policies would apply to it … a menu item making it easier to find all
   the SELinux features"). `server/filelabel.js` (pure): parseSpecs
   (spec, flag, mode, context, type, l, file, module + fc_sort measures),
   specificity/compareSpecs/sortSpecs = refpolicy fc_sort.py exactly
   (meta, stem, len, flag; stable), lookupOrder(...lists) = libselinux:
   concat file_contexts, .homedirs, .local, then specs without regex chars
   moved to the end; LAST match wins (`matches()` walks backwards, mode
   filter, anchored `^(?:…)$`, POSIX classes translated), parseSubs /
   applySubs (local then dist on the result; later lines tried first,
   libselinux prepends them — found by the e2e with /run vs
   /run/systemd/generator), splitHomeTemplates (HOME_DIR → /home/[^/]+,
   HOME_ROOT, USER, %{USERID}, %{USERNAME}; template keeps the original),
   modeOf(lstat), permLevels. Server: `fcLists(pol)` (installed: its
   files; tree build: base.fc + tmp/<m>.mod.fc of each packaged <m>.pp,
   sorted, templates as homedirs, tree config/file_contexts.subs_dist;
   standalone: running policy + module sorted together), cached by mtimes;
   `treeFileContexts()` now writes the sorted tmp/zz_file_contexts (+
   .subs_dist; matchpathcon -f reads <file>.subs_dist) and
   `moduleFileContexts()` the sorted union (+ .subs/.subs_dist): the old
   unsorted all_mods.fc gave CLIP /usr/bin/rpmbuild usr_t (bug fixed for
   denials + loginCan). `fcSourceOf()` maps a compiled line to the .fc
   source by `spec\ttype` over idx.fcByType (module's own first).
   Requests `selinux/fileLabel` {path, mode} (lstat, directories resolved
   like restorecon — matchpathcon does NOT resolve them, so the e2e passes
   resolved paths — stat %C, rpm -qf, link target; per denialPolicies():
   winner + up to 7 losing lines, key after subs, homeAssumed) and
   `selinux/fileTypeInfo` {against, type} (loginPolicy → policy_query op
   `fileinfo`: allow groups by (s, t as written, cond) with attr size /
   domains, entrypointOf (rules on the type itself) with transitions in
   through it, entryViaAttr count, created (type_transition default = T)
   and inside (parent = T), 200 unnamed + 200 named each; Index rules now
   carry `name` for filename transitions; locs via sourceLocation).
   Client: `selinux.lookUpFile` (Uri from menus, string arg, selected
   path) → `showFileLabel` (media/filelabel.js: path box, kind select,
   Browse… = showOpenDialog, "Rules from" policy select; cards per path:
   on this host, Label table, what the policy lets happen: type + attrs,
   Running it starts / runs in caller's domain + New Service…, created /
   inside, access rows ranked relabel>manage>write>enter>execute>read with
   filter, Show all, *where from* → selinux/ruleOrigins per class; reloads
   after builds). Features menu: `FEATURES` + `showFeatures()` quick pick
   (groups with separators, detail lines), `selinux.showFeatures`; the
   main status bar item now opens it (tree switching is in the menu);
   Policy Explorer title (menu icon) and submenu `selinux.contextMenu`
   ("SELinux") in explorer/context and editor/context (lookUpFile,
   buildModule for .te/.if/.fc — takes the Uri now —, analyzeDenials,
   showFeatures). Getting-started navigate page mentions both. Also fixed:
   policy_query reach iterated the user's roles as a set (hash order
   changes per run), so logins-e2e's "staff_u reaches sysadm_t as
   sysadm_r" was flaky; now same role, role named like the domain, name.
   Tests: test/filelabel-test.js (npm test), test/filelabel-e2e.js
   (melody: 7,355 host paths vs matchpathcon on targeted, 2,452 on the CLIP
   build, fc_sort.py order identical for 3,002 lines, rpm_exec_t → rpm_t
   traced to rpm.te). Answer to the user's question: CLIP labels
   /usr/bin/rpm system_u:object_r:rpm_exec_t:s0 (admin/rpm.fc:16).

11. **Wrapped programs** (done, 0.15.0; user 2026-10-13: chroot'ed
   read-only users run wrapper programs that execve protected copies of
   programs, which keep the originals' privileges; "a real chroot", "you
   don't need to know how the wrapper works … it runs something like
   execve", argument limits are the wrapper's job, "both in tree and stand
   alone", no mount units, generic for any program; document it but don't
   use one specific program as the example). `server/wrapper.js` (pure):
   model {name, summary, version, chroot, likeRoot (equivalence chroot = /),
   protectedDir, wrapperDir (paths inside the chroot), role, domain,
   logins (Linux logins / %groups of the chroot users, for the reach check;
   header `# wrapper-logins:`), programs [{stem, original, wrapper, copy, pkg, origType, target ('' = no
   domain of its own: can_exec in the wrapper), roles (domains target
   starts by type_transition, for the role), selfRules (target's rules on
   origType, entrypoint dropped), ifaces (DEFAULT_IFACES libs/locale/
   terminal)}]}. Types: NAME_STEM_t / _exec_t (domain_type +
   domain_entry_file), copy NAME_STEM_real_exec_t (NOT exec_type/entry_type:
   domain_entry_file_spec_domtrans and "run any program" rules would reach
   it), NAME_protected_t (dir, search for the wrappers); both declared with
   files_security_file where ctx.has it, else files_type (RHEL: `allow
   user_t non_security_file_type:dir getattr` let the user stat the
   protected dir — found by the RHEL e2e). Rules: domtrans_pattern(U, WE, W), domtrans_pattern(W, C, T),
   allow T C:file { entrypoint mmap_exec_file_perms ioctl lock } + selfRules,
   role R types {W, T, roles}; gen_require for U/R/T. .fc: paths inside the
   chroot (likeRoot) or chroot-prefixed, regex-escaped. Header comments
   `# wrapper-chroot/labels/protected/dir/user:` and per program `# STEM:
   ORIGINAL, copied to PATH (package P)` → recognize(); plan() re-renders
   and keeps lines the old render doesn't produce in a "Local additions"
   section (te + fc; .if kept as is); validate (names, paths, overlapping
   dirs, user, interfaces, type clashes for new, likeRoot paths that exist
   on the host refused: their lines would relabel the host; a note without
   logins); checksText (never U may {execute read getattr} copies; never U
   may {getattr search read} D:dir; with logins: never login L reaches T
   except through W — role-aware; the type-level `never U reaches T` was
   dropped because it counts transitions the role can't take, e.g. RHEL
   user_t → init_t); setupCommands. packaging.js
   wrapperBlocks/updateWrapperSpec: marked blocks (BEGIN/END "wrapped
   programs") in %post (semanage fcontext -a -e / CHROOT, install -d 0711,
   cp -p, restorecon -R), %postun (rm, rmdir, semanage -d) and
   %triggerin -- PKG per package (re-copy + restorecon); % doubled.
   Server: wrapperModules() (te with the header), treeTypeBuilt(t) (declared
   by an enabled module — CLIP's user_t is off: found by the e2e as a link
   error), wrapperUsers (roles R with R-stem_t built; standalone: host
   policy via policy_query users), requests `selinux/wrapperInfo`,
   `selinux/wrapperProgram` {path, chroot, standalone} (lookupFile() — the
   fileLabel request body as a function — fileinfo entrypointOf minus
   GENERIC_ENTRY, selfRules per candidate (cond rules skipped, counted),
   transitions out with auto, rpm -qf NAME, ldd libs vs chroot, the domain's
   file-class rule targets → fc specs' fixed dirs → present in chroot;
   needsCount before slicing to 80), `selinux/wrapperList`,
   `selinux/wrapperPlan` (te/if/fc; tree: config/file_contexts.subs_dist
   line (old chroot line removed when it changes), modules.conf for new,
   commands; standalone: spec once / updateWrapperSpec, Makefile, note for
   programs without a package; both: selinux.checks block between
   `# >>> wrapped programs: NAME` / `# <<<` markers). Client:
   showWrapperEditor (media/wrapper.js; EDITOR_CSS), selinux.newWrapper /
   editWrapper, FEATURES entries. Checks: `never X reaches Y except through
   Z` (checks.js `through`; policy_query transition_path avoid set; message
   "without going through"; grammar keyword) and `never login L reaches Y
   except through Z` (policy_query reach `avoid`: transitions into those
   types skipped; userReach(bin, U, starts, roles, avoid), cache key incl.
   avoid; loginChecks userReachFor(U, avoid)). Also: reach iterated roles
   in set order → fixed earlier. Also fixed: applySubs with a
   target of / (libselinux special case) gave //etc/…. Tests:
   test/wrapper-test.js (npm test), test/wrapper-e2e.js (melody; [tree
   [spec [variant]]]; adds `%rousers:<role>_u:s0` to the tree copy's
   appconfig-mcs/seusers): CLIP, RHEL 9, RHEL 10. On CLIP the only user
   roles built are admin ones (staff_r picked); the login reach check
   reports staff logins landing in sysadm_t, which runs setfiles_t (true).

12. **Levels and categories (MLS/MCS)** (done, all six items, 0.16.0; user 2026-10-13
   asked about s0 levels and container categories; agreed order: 1 bypass
   report + checks, 2 context compare, then 3 levels shown elsewhere with
   setrans names, 4 range_transition in graph/File Labels, 5 container
   isolation check, 6 setrans/category ranges in the user editor; 1 + 2
   done). policy_query.py: `level_constraints()` (mlsconstrain with perms;
   postfix expr), `eval_levels(expr, d)` three-valued (t1 vs a set known
   from d + its attributes; levels, users, roles, t2 unknown → None; and/or
   Kleene; `why` = the true t1 terms "in X" / "not in X"), op `levels`
   {classes?} → kind mcs|mls (sensitivities > 1), counts, constraints,
   groups {constraints (indexes), via, domains, classes: class → perms}
   sorted most bypassed first, targetTerms (t2 set terms, e.g. RHEL packet
   recv `not in mcs_constrained_type`); check kinds only-levels /
   never-levels (`check_levels`: error without MLS, or when no level
   constraint covers the classes). Op `context` (`context_check`): source
   validity (user → role, role → type, level within the user's range;
   missing level → s0 with a note), avc for the type rules, constraints
   (now `everything=True` returns passing ones with ok). checks.js: `only|
   never <domains> may ignore levels [on <class | {…}>]` (kinds
   only-levels/never-levels; KEYWORDS + grammar + completion "ignore
   levels"). Server: `selinux/levels` {against} (+ locs for via attributes
   and domains of groups ≤ 80), `selinux/contextCheck` {against, source,
   target, tclass, perms} (running booleans for the active installed
   policy; build: first allowing rule per perm traced via explainRule);
   checkMessage/lens/related info for x.levels (common classes first).
   Fixed: plain `reaches … except through` never sent `through` to
   policy_query (0.15.0 bug; login form was fine). Client showLevels
   (media/levels.js: Can it access? form with examples and "Use its label"
   via selinux/fileLabel, plain-word comparisons (OPERAND), Who ignores
   levels groups with filter (keeps focus), Add check → addCheckLine()
   appends to selinux.checks), `selinux.showLevels` (arg = prefill),
   FEATURES entry, denial assistant "Check in Levels and Categories" on
   constraint verdicts. Findings: RHEL 9 targeted 20 held (container,
   svirt, sandbox), 879 pass 49 of 72; CLIP RHEL 9 build (upstream
   `t1 != mcs_constrained_type` form, 110 constraints): no domain in
   mcs_constrained_type (no container/virt modules), so MCS binds nothing;
   CLIP RHEL 8 (policy/mcs written MLS-style, 228 constraints, exemptions
   by mls* attributes): 200+ domains held, exempt ones grouped by
   attribute. Told the user (possible protection loss RHEL 8 → 9).
   Scratch experiment (CLIP 9 copy + CLIP 8's policy/mcs): builds, 228
   constraints, 208/250 held, the 226 shared domains treated exactly as on
   CLIP 8 (same 42 exempt, same attributes), 24 RHEL 9-only domains held
   (systemd_journal_init_t etc. may need exemptions; runtime test needed).
   The user decided (2026-10-13): document only, don't change their CLIP
   clone; written up in README "## Findings". Tests: test/levels-test.js (npm test),
   test/levels-e2e.js (melody; [tree]).
   Items 3-6 (done, unreleased; "lets do the rest of the MCS items"):
   server/levels.js (pure: parseCats/catsText/canon (setools form, runs as
   cA.cB), parseSetrans (raw=Name lines; advanced mcstrans lines counted as
   skipped), translate (whole range, else each end), describe, problems
   (sens/cats limits, high covers low), covers). Server setransFor(pol):
   installed /etc/selinux/NAME/setrans.conf; build: appconfig-TYPE/,
   dist/NAME/, selinux_config/setrans-{NAME,TYPE}.conf (CLIP 8),
   ../support/ (CLIP 9), ../, spec dirs of build.tree.files (RHEL 9);
   levelLimits() from idx.m4 flags; levelHover() (level/range regex on the
   line, before wordAt); names in selinux/levels (setrans), contextCheck
   (levels.*.name, userName), lookupFile (per policy level/levelName,
   currentLevelName), logins (users' range canon + rangeName, mappings
   rangeName). Range transitions: policy_query range_rules()/ranges_for();
   transition() has `ranges` [{entry, range}]; fileinfo from[].range;
   transitions.js edge class `ranged` (purple) + tooltip + legend; File
   Labels "at RANGE". Isolation: policy_query isolation(domains, weight,
   classes, limit, scope own|all): binds = constraints whose eval_levels
   isn't True; own scope = targets the domain is or may create (create
   perm) and SHAREABLE classes (file classes, sem msgq msg shm ipc key
   process) + SHARE_PERMS (unix_stream connectto, unix_dgram sendto);
   perms with permmap weight ≥ N not covered by a binding constraint;
   fdOnly when (class, open) is checked; op `isolation`, check kind
   require-isolated (checks.js `require <d> isolated by levels [on …]
   [weight N]`), server selinux/isolation (origins traced for a build),
   checkMessage/lens/related, completion "isolated by levels". Webview
   "Kept apart by levels?" card (domains default container_t/svirt_t from
   the held group, weight select, every target, Add check). User editor:
   userPlan response carries `levels` (userLevelsInfo: MCS tree → gen_user
   ignores level/range, range = s0[-s0:CATS] with macros resolved
   (mls/mcs_systemhigh, mcs_allcats); standalone: hostLevelLimits() from
   /sys/fs/selinux/mls), media/user.js levelHelp() (#lvhelp refreshed per
   plan), quick choices, datalist of setrans names. Findings: RHEL 9
   container_t binds 72/72 yet 48 shared accesses unchecked (connectto,
   msg, shm/sem/msgq read; fifo read/write fd-only); CLIP 8 staff_t
   isolated, CLIP 9 staff_t 144 unchecked; RHEL init_t → setrans_t at
   s0-s0:c0.c1023; CLIP 8 init_t starts 9 domains at fixed levels.

13. **A host's local changes** (done, 0.16.0; user 2026-10-14: "lets
   do the host semanage compare next … run full regression tests after
   adding all unit tests"). server/localmods.js (pure): parseExport (the
   `semanage export` format from seobject.py customized(): boolean -m -1/-0,
   login -a -s [-r], user -a [-L -r] -R, port -a -t [-r] -p, interface,
   node -M -p -t, fcontext -a -f FTYPE -t [-r] SPEC / -a -e SOURCE TARGET,
   module -d, permissive -a, ibpkey, ibendport; "X -D" reset lines skipped;
   after "#### modules" `semodule --list-modules=full` lines PRIO NAME LANG
   [disabled]; unknown lines kept), localModules (priority ≠ 100, not
   permissive_*), compare(items, facts) → state local|override|present|
   redundant|broken|info + note + severity warn (permissive, priority 400,
   unconfined_u logins, admin roles) + `was` (override: the policy's type),
   describe, snippets, fixes: fcontextFix (append to owner .fc),
   fcontextReplace (override: type on the policy's own line — a second line
   for a path conflicts), portFix (number onto NAME_port_t's network_port
   line; override moves it from `was`'s line — duplicate portcon fails),
   subsFix, booleanFix, loginFix (before __default__), moduleOffFix (base
   untouched). policy_query op `hostfacts` (types+attrs, bool defaults,
   users roles/range, roles, portcons, netifcons, nodecons). Server
   hostPolicy (default: build, else running), hostFacts (fc map from
   fcLists minus `.local` specs; subs dist; loginConfig seusers; tree
   moduleKinds + built .pp set; containsLocal for installed policies),
   requests selinux/hostChanges {text, against}, selinux/hostChangesLocal
   (no root: file_contexts.local, .subs, running booleans ≠ default as
   export lines), selinux/hostChangeFix {item, against} (fixTarget: owner
   .fc / fcSourceOf line for overrides, subs_dist, booleans.conf overlay or
   tree, appconfig seusers, corenetwork.te.in, effectiveModulesConf part;
   plan {path, text, line, inserted} applied with applyDenialFix). Client
   showHostChanges (media/hostmods.js; sudo via terminal "SELinux Host
   Changes": `sudo sh -c 'semanage export; echo "#### modules"; semodule
   --list-modules=full' > f.part; mv`, fs.watchFile), command
   selinux.compareHostChanges, FEATURES, lockdown walkthrough step
   hostchanges. Found + fixed: refpolicy's tmp/generated_definitions.conf
   (booleans.conf → NAME_conf defines, flask, base modules) has no make
   prerequisites, so booleans.conf edits never applied incrementally;
   build.forgetStaleDefinitions() removes it when those inputs change.
   Tests: test/localmods-test.js (npm test), policy_query_test.py
   hostfacts, build-test forgetStaleDefinitions, test/hostmods-e2e.js
   (melody; running targeted + CLIP copy: write every fixable change,
   rebuild, all present after), in test:clip-all.

14. **Contexts that won't load** (user 2026-10-22: "scans compiled
   policies to find problems which would prevent contexts from loading …
   'unable to get valid context for <user>'"; agreed plan: phase 1 logins,
   phase 2 every other context file — file_contexts (+ homedirs as
   genhomedircon writes them, .local), failsafe/default_type/initrc/
   removable/userhelper/virtual_*/lxc/x/dbus/sepgsql/systemd/openssh
   contexts, media, securetty_types, customizable_types).
   Phase 1, login contexts (done, unreleased): libselinux behaviour checked
   in its source: 3.x get_ordered_context_list (get_context_user): the first
   line of contexts/users/<seuser> whose first field has fromcon's
   role:type, then default_contexts' first such line; entries seuser:entry
   with fromcon's range (get_ordered_context_list_with_level replaces
   fromcon's range by the seusers level); kept when security_check_context
   passes (NO transition check); none → failsafe_context (seuser:<line>,
   validity only) → else "unable to get valid context". 2.9 (RHEL 8):
   security_compute_user(fromcon, user) = valid + process transition
   (TE + constraints), range from mls_setup_user_range; file entries only
   order them. getseuserbyname: own line > first %group > __default__ >
   the login's own name (no level). policy_query op `logincontexts` {items:
   info | resolve (m4 macros mls/mcs_systemhigh/low, mcs_allcats; sens/cats
   sorted by the number in the name) | valid (context_valid) | transition
   (avc process transition + constraints()) | userrange (mls_setup_user_range
   with setools Levels)} → answers by id. server/loginctx.js (pure,
   analyze(cfg, ask)): targets = seusers lines + users with an own contexts
   file and no seusers line (hypothetical, at their default level; problems
   collapsed into one info `unmapped`); per target the system_r sources of
   its own file + default_contexts (fromcon system_u:system_r:S:<login
   level or system_u's range>; skipped when fromcon itself isn't valid,
   e.g. unconfined_u's stale `system_r:sysadm_su_t` line); a source is
   "meant" when its own file has a line or a candidate's role is the
   user's; works3 = first valid candidate (or failsafe) AND transition ok,
   works2 = first candidate valid at the userrange and reachable (or
   failsafe + transition). Problems: nodefault, duplicate, range, nouser,
   noway, nocontext / nocontext3 (RHEL 9+ only) / nocontext2 (RHEL 8
   only), failsafe (warning), skipped (info on the contexts line); errors
   only for LOGIN_PROGRAMS (logins.ENTRY_LABELS + rshd_t), other callers
   (initrc_t) info. Server: loginConfig() has `failsafe`;
   loginContextReport(lp) (running policy → runningBooleans());
   `selinux/loginContexts` {against}; publishLoginContexts() after each
   good tree build (diagnostics source 'selinux-logins' on the seusers /
   contexts lines, relatedInformation = candidate lines; loginCtxUris
   cleared when gone) and on watched changes of LOGIN_FILES (client
   watcher glob adds seusers, default_contexts, failsafe_context,
   *_default_contexts). Client showLoginContexts (media/loginctx.js:
   policy picker, verdict, problems with line links, per login the ways
   with RHEL 9+ / RHEL 8 result and candidates with reasons), command
   selinux.checkLoginContexts, FEATURES "Fix problems". Findings: RHEL 8/9
   installed targeted: only info (initrc_t → unconfined_t); CLIP RHEL 9:
   users' crontabs fail (no role authorized for cronjob_t — CLIP's roles
   don't call cron_role; no crond_t → staff_t/sysadm_t rule); CLIP RHEL 8:
   works on RHEL 8 (kernel picks staff_r:cronjob_t) but RHEL 9's libselinux
   takes staff_r:staff_t, reachable only with cron_userdomain_transition
   (off). README Findings "Login contexts in CLIP" (not yet confirmed on a
   running CLIP host). Tests: test/loginctx-test.js (npm test: fake
   policy, every problem kind, the webview), policy_query_test.py
   (logincontexts), test/loginctx-e2e.js (melody CLIP 9 + ricardo CLIP 8;
   in test:clip-all as `loginctx`), test/loginctx-survey.js (installed /
   tree / build <tree>: prints every problem).
   Phase 2, context files (done, unreleased; "ok lets do phase 2"):
   libsemanage/libselinux 3.6 source read: semodule runs setfiles -c on
   file_contexts only (invalid context or "Multiple different/same
   specifications" → refused); semanage_fcontext_validate_local on every
   commit (stale .local line → every commit fails); genhomedircon
   (homedir_template = lines starting HOME_DIR/HOME_ROOT or containing ROLE
   or USER; per seusers user: ROLE → prefix (users_extra, default "user"),
   context user → sename, level → user's default level (MLS/MCS), role →
   prefix when it is object_r or one of the user's roles; check_line drops
   invalid lines silently; fallback from __default__ else user_u); .local
   and .homedirs are not validated by setfiles at install (lookup →
   setfilecon EINVAL). server/ctxfiles.js (pure, analyze(cfg, ask)): FILES
   catalog (format context | partial | roletype | keyed | typekey | labels |
   x | dbus | types; owners = the reader's domains, none present → problems
   collapsed to one info `unused`; sev; effect); parseFile, parseUsersExtra,
   templateKind, homeUsers. Kinds: invalid, format, notype, nodyntrans
   (openssh: system_r role + sshd_t dyntransition + setcurrent), fc-main,
   fc-duplicate, fc-local, fc-homedirs, fc-associate, homedir (on the
   login's seusers line, related = template lines; prefix-is-a-role hint),
   unused. default_type severity: role of a mapped user → error, of any
   user → warning, else info; dbus name whose type is missing → info.
   policy_query logincontexts kinds types / roletype / associate (any
   unconditional allow T|attr *:filesystem associate) / dyntrans;
   context_valid no longer requires the user to have object_r (setools
   leaves it out of user.roles). Server: reportDiags (source → path →
   diagnostics, merged into publish() and publishBuild; publishLoginContexts
   uses it too), contextFilesConfig(pol) (tree: appconfig files, base.fc +
   tmp/*.mod.fc, tmp/users_extra, host .local when an installed policy has
   the build's NAME; module: its .mod.fc + host files; installed:
   contexts/, contexts/files/media, file_contexts(.homedirs, .local)),
   `selinux/contextFiles` {against}, publishContextFiles() after every tree
   build whose policy.bin is fresh (res.startedAt; also when validate's
   setfiles failed), CONTEXT_FILES watched (client glob). Client
   showReport(viewType) shared by both panels (reportPanels),
   selinux.checkContextFiles, media/ctxfiles.js. Findings: targeted RHEL 8/9
   clean; CLIP RHEL 8: 13 gnome/telepathy/xserver home types not file types
   (xdg_*_content in optional_policy, xdg off) → not associable; both CLIP:
   default_type unconfined_r:unconfined_t (warning). Tests:
   test/ctxfiles-test.js (npm test), policy_query_test.py, test/ctxfiles-e2e.js
   (melody CLIP 9 + ricardo CLIP 8; clip-all `ctxfiles`),
   test/ctxfiles-survey.js (installed | tree <copy> [TYPE] | build <tree>).

15. **Logins that bounce** (done, unreleased; user 2026-10-22: "giving a
   user can cause the login to bounce … SELinux thinks the rights were
   elevated too much and kills the login even though everything compiles …
   helpful suggestions based on the actual policy … preferable to …
   audit2allow"; "lets do both": the session checks + the audit records,
   which the user didn't paste; journals had none, audit.log needs root).
   Kernel facts used: exec into the session domain D from login program S
   needs D entrypoint on the program's label (symlinks followed: /bin/sh →
   bash), the loader D read/open/getattr/execute/map on its libs (ldd) and
   read/open/getattr/map on /etc/ld.so.cache; inherited files are
   revalidated (flush_unauthorized_files): D S:fd use + chr_file read write
   ioctl getattr on the terminal, else /dev/null and the shell exits; ssh
   pty = type_transition S devpts_t:chr_file (sshd_devpts_t), relabeled by
   type_change D old:chr_file when S has relabelfrom/relabelto (sshd keeps
   going if setfilecon fails); console = tty_device_t + type_change.
   NoNewPrivileges/nosuid (policycap nnp_nosuid_transition): process2
   nnp_transition / nosuid_transition, else D bounded by S, else exec fails
   with SELINUX_ERR op=security_bounded_transition (the user's "rights
   elevated too much"). compute_sid of a process type_transition keeps the
   role (unless role_transition); invalid → exec refused (SELINUX_ERR
   security_compute_sid invalid_context). typebounds mask the child's extra
   perms at run time (op=security_compute_av reason=bounds). RHEL 9:
   userdom_login_user_template puts users in login_userdomain; init_t,
   local_login_t, xdm_t have nnp_transition to it (userdom_nnp_transition_
   login_userdomain); sshd_t has none; RHEL 9 compiled policy has 0
   typebounds; no login unit sets NoNewPrivileges on melody.
   policy_query logincontexts kinds computed (type_transition/type_change,
   unnamed, active cond), avc (perms the class lacks dropped), nnp
   (nnp_check: statuses, bounded_by via policy.bounds(), polcaps, nnpTo =
   S's unconditional nnp rules, `holds` = session domains in an attribute),
   autoinvalid (auto_invalid: reach() states up to `depth`, type_transition
   on exec types the state may execute, computed role invalid), bounds
   (bounds_masked). server/sessions.js (pure, analyze(report, facts, ask)):
   starts = each way's v3 / v2 context (both when different, `on`),
   FIRST_PROGRAM (shell | /bin/sh for crond_t | systemd for init_t),
   TERMINALS (sshd_t/sshd_session_t pty, local_login_t tty), checks entry /
   libs / tty / nnp per session; problems session-entry, session-libs,
   session-fd, session-tty (hint: a user pty type via type_change),
   session-relabel (info), session-nnp (unit sets NoNewPrivileges),
   session-nosuid (program on a nosuid mount), session-nnp-other (warning:
   S may nnp into other sessions' domains / an attribute holding one, not
   D), session-invalid (info per user, depth 0 only, grouped by target; the
   whole reach was noise: daemons reached through others), bounds
   (warning); `need` {source,target,tclass,perms} + `attrs` for fixes;
   END_TEXT per login program; hypothetical logins → info. Server:
   loginContextReport runs it after loginctx (report.sessions/invalid/
   bounds, problems merged, so they reach seusers with
   publishLoginContexts); sessionFacts(pol, cfg) (passwd shells for host
   policies, ldd, realpath, /proc/self/mountinfo nosuid, systemctl show
   NoNewPrivileges for the login programs' units, 30 s cache);
   `selinux/sessionFix` {against, need, attrs} → suggestInterfaces on a
   synthetic missing group + joins (attributeInterfaces(): 1-arg .if
   interfaces with `typeattribute $1 A`, pure first). Denial assistant:
   parseDenials reads SELINUX_ERR oldcontext/newcontext (tclass process),
   older "invalid context X for", reason, perms; groups keep invalids /
   reasons; errorVerdict(): nnp (bounded_transition; allowed when the policy
   now allows/bounds it), invalid (context_valid reasons; role to
   authorize; allowed when valid), bounds (parent from bounds_masked),
   validatetrans, generic; the nnp_transition AVC gets a note. Server
   analyzeDenials asks nnp / valid / bounds for error groups;
   suggestForErrors(): synthetic group → suggestInterfaces + joins, invalid
   → roleInterfaces(T) (2-arg interfaces with `role $2 types T`, *_run
   first) as calls (S, R); denialFix takes 2-arg calls. Webviews:
   loginctx.js Session starts card + How to fix (Add… → selinux/denialFix →
   Apply → applyDenialFix; showReport handles sessionFix/fix/applyFix);
   denials.js badges nnp/invalid/bounds, x.call, joins with their own
   domain. Tests: test/sessions-test.js (npm test), denials-test (records +
   verdicts), policy_query_test.py (computed, nnp, auto_invalid,
   bounds_masked), test/sessions-e2e.js (melody CLIP 9 + ricardo CLIP 8:
   running targeted 54 sessions start; CLIP + module brk
   (domain_user_exemption_target needed, else CLIP's process_user_target
   constraint refuses the transition; loginctx reported that first):
   session-entry/fd/tty → corecmd_shell_entry_type, domain_use_interactive_
   fds, term_use_all_ptys suggested, applied, rebuilt, gone; denial records
   against the build; in clip-all as `sessions`); loginctx-survey prints
   the session checks (VERBOSE=1 every check). Survey: every session starts
   on RHEL 8/9 targeted and both CLIP trees; note: sysadm_t can't run
   rpc.nfsd (CLIP). Open question for the user: ricardo's
   ro_u_default_contexts has only a console line, so ro logins over ssh
   would get no context.

16. **Restricted logins** (done, unreleased; user 2026-10-26: "detect and
   fix issues which arrive from role transitions and permissions …
   restricted user login transitions, roles associated with the domains,
   domain transfers, processes allowed to run, and then later in a file any
   new domains … some of these additional allow statements prevent the
   restricted user from logging in but the policy will compile and install
   … do not appear to leave any trace in the AVC denials"; no sample
   available; plan agreed, "go ahead in the order specified": 1 silent
   failures, 3 which edit broke it, 2 what they run, 4 fixes checked by a
   rebuild). Found on melody's ro_user + rpmwrap (the user's uncommitted CLIP
   9 work, built in a copy ~/sepol-test/exp-ro with a login rouser): the
   restricted template gives ro_user_t 71 dontaudit rules (exec_type execute,
   default_t reads, init_t/initrc_t/xdm_t fd use); rpmwrap_rpm_t has the
   user terminals but not fd use on sshd_t/local_login_t, so the wrapper
   prints nothing (README Findings; wrapper.DEFAULT_IFACES now adds
   domain_use_interactive_fds for new programs).
   1. server/audittrace.js (pure): trace { record avc | none (dontaudit,
   hidden rules) | selinux_err | log, text } — avcTrace (AVC unless every
   refused perm is dontaudited), transitionTrace, selinuxErrTrace, logTrace
   (pam_selinux / sshd messages per login program, LOGS). policy_query avc()
   returns per refused perm `dontaudit` (active rules); logincontexts
   transition carries it; computed returns the rule. loginctx nocontext*
   get traces (RHEL 9 chosen-but-unreachable → AVC at exec, else log; RHEL 8
   always log). sessions.js every problem/check has trace; checks append
   "(no AVC: dontaudit hides it)". denials.loginRefusals(text): pam_selinux /
   sshd / crond lines (audit records skipped) → { program, source, login,
   kind, count }; server explainRefusals() runs the login check and attaches
   the problems of that login's seusers line (logins.resolveLogins); webview
   refusal cards ("no audit record", Open Check Login Contexts); client
   ausearch also greps the journal (pam_selinux|ssh_selinux|SELinux context).
   3. build.syncTree(…, changed) → res.changed (tree-relative); server
   loginPending (+ watched login files), traceLoginProblems (explainRule on
   currentSide for trace.hidden and causes → origin + related lines "Causes
   it" / "Keeps the denial out of the audit log"), compareWithLastBuild
   (loginBaseline keys kind|login|way|source|domain|need|on of error/
   warning problems; new → isNew, since, text "New with this build (changed:
   …)" / "New since the last check"; notification selinux/loginsChanged
   {broken, fixed, changed}; client loginsChanged(): warning with *Show
   Login Contexts* / *Go to the Line*, info when fixed), causeDiagnostics
   (code `<kind>-cause` on the causing line: "This line (via) <what>: …").
   Causes: session-invalid / run-* (type_transition), session-tty (the
   type_change / pty type_transition). loginContexts request marks isNew from
   the baseline too. Fixed: sessions.js q2 ids repeated across follow-up
   batches (answers merged into one map).
   2. policy_query exec_check(user, role, s, e, states, uroles, terms,
   origin): execute; no transition → execute_no_trans; computed role
   (role_transition) → invalid (SELINUX_ERR, reason, role), role allow
   (roleallow), process transition (AVC/dontaudit), proc_ok constraints,
   entrypoint; inherited terminal (fd use on the opener, chr_file rw) and the
   session's pipes (fd use + fifo_file on origin; origin False = skip) only
   when T may read/write one of the terminals (interactive; chkpwd etc. are
   not). runs(user, starts, states, roles, depth=2, terms) over reach()
   states: every type_transition on an executable type, pipes only for depth
   0. logincontexts kinds exec / runs. sessions.js: per user runs (terms =
   its logins' (opener, tty)), RESTRICTED_REACH 12 (reached in 2 steps,
   not hypothetical) → run-fails / run-terminal warnings + session-invalid
   warning with roleFix; others: report.runs only (no problems), invalid as
   before (info, depth 0). Login path: facts.setupOf(m, role) (settings
   `selinux.logins.sessions` {login|%group|user: {shell, command, chroot}},
   else wrapperChroots() by wrapper-user role), FORCED_COMMAND (sshd only)
   → session-command(-tty) error, startupPrograms(chroot) (server: first
   words of commands in /etc/profile, /etc/bashrc, /etc/profile.d/*.sh on
   PATH, not builtins/functions) → session-startup warning; chrooted
   programs/libraries looked up inside the chroot; shellOf for tree builds
   when the login exists in this host's passwd. Webview: badges (new with
   this build, no AVC / SELINUX_ERR / no audit record), Caused by / Hidden by
   lines, *Programs the sessions run* card, command/startup checks.
   4. sessionFix {role: {role, type, domain}} → roleInterfaces calls (domain,
   role) + `role R types T;` (Add… → denialFix rule; insertFix knows role
   statements are already there). Settings change re-publishes.
   Tests: sessions-test (traces, causes, runs, restricted vs not, forced
   command, chroot, startup, webview badges/cards), loginctx-test (traces),
   denials-test (loginRefusals + card), policy_query_test (avc dontaudit,
   computed rule, exec_check, runs), test/restricted-e2e.js (melody CLIP 9;
   restricted user rt with login rtuser: works; domtrans to rtw_t without
   the role → SELINUX_ERR, cause rt.te line diagnostic, denial verdict, fixed;
   base template → new errors with rt.te as change + notification, back →
   fixed; rtw_t without sshd fds → run-terminal, domain_use_interactive_fds
   suggested/applied; forced command /usr/bin/rtw without the role → error,
   role fix written, gone; in clip-all as `restricted`). Survey: stock RHEL 9
   targeted unchanged (session-invalid notes only); exp-ro: the 2 rpmwrap
   warnings.
   Speed (found by the full regression: build-rhel's first rule query
   waited 65 s behind the after-build login check, which took 83 s on RHEL 9
   targeted): runs `restrict` (sessions.js passes RESTRICTED_REACH, -1 for
   hypothetical logins) checks only depth 0 for wide users and caps reach()
   (`cap`: stops after that many states); exec_check results memoized per
   user/role/s/e/terms/origin/booleans; avc() keeps each (source, class)'s
   allow/dontaudit rule list (`_avc_src`). Now 2.3 s (0.4 s before step 16),
   same findings. loginctx-survey VERBOSE=1 prints questions per kind.

17. **Dropped optional blocks + install profiles** (done, unreleased; user
   2026-10-28: "parse comps.xml also and grey out optional components that
   won't be used … when hovering they need to show what they would actually
   expand to"; CLIP's conf/yum/comps.xml is RHEL's stock group file and
   names no module packages, so the agreed source is the kickstarts:
   "yes use the kickstart profiles"). server/kickstart.js (pure):
   parseComps (groups/environments → mandatory/default/optional/
   conditional), evalCondition (Mako `% if` subset: ==/!=/</>, and/or/not,
   float()/int(); unknown → null, Kleene), renderMako (lines + unsure),
   readKickstart (%packages, %include relative to kickstart/, missing file
   → .tmpl rendered with CONFIG_BUILD vars, @group [--nodefaults/--optional]
   via comps, -name removes group packages, explicit names win; absolute
   includes noted, include-at-runtime ignored), profileModules
   (selinux-policy-<type>-<mod> for SEPARATE_PKGS; globs; installed/unsure/
   absent), findProfiles (kickstart/<n>/<n>.ks up to 6 levels above the
   tree, comps, CONFIG_BUILD). diagnostics.js droppedOptionalBlocks(idx, f,
   loaded): active, decided, not-in-def optional_policy blocks without an
   else part; requirements = the block's own require entries + callRequires
   (mandatory) of its calls (scopeOf = innermost block); a name whose
   declaring modules (type/attribute/role/bool decls in module .te files,
   aliases included) are all loaded() === false → missing; nested blocks
   go with a dropped parent. Server: installProfiles() (SEPARATE_PKGS from
   <tree>/../Makefile via specconfig.makeVars, type from CONFIG_BUILD or
   NAME=; cached by the mtimes of every file read), settings.installProfiles
   {treeRoot: name} (client workspaceState 'selinux.installProfiles'),
   moduleLoaded(m) (isEnabled, then the profile's state), droppedBlocksOf
   (WeakMap per parse, keyed by profile + moduleKinds + defs);
   selinux/inactiveRanges adds { dropped, reason, missing }; hover wrapper
   (hoverAt = the old handler): "Not in the linked policy" + why, on
   optional_policy the whole block's statements (expansionOfLines), on a
   call expansionOfCall (statements of calls inside optional blocks sit on
   the block's first line in tmp/<mod>.tmp; entries under the one whose via
   is the call — also fixed the general "Compiles to" for such calls);
   INFO profile-not-installed on policy_module; requests
   selinux/installProfiles, selinux/selectInstallProfile (publishAll +
   inactiveChanged); watched .ks/.tmpl/comps.xml/CONFIG_BUILD/Makefile.
   build.cilBuild takes exclude + root. Client selinux.selectInstallProfile
   (quick pick with "Every built module"), FEATURES entry. CLIP RHEL 9:
   37 separate modules; clip-sftp-dropbox installs ssh + aide (GUI off),
   clip-minimal ssh aide rngd bind, clip-apache ssh postfix mysql apache;
   639 blocks dropped without a profile (nis, nscd, container, … off),
   whole tree ~20-80 ms. Tests: test/kickstart-test.js, diagnostics-test
   (qux.te), test/profile-e2e.js (melody, CLIP layout copy; CIL links of all
   packages vs the profile's: all 130 profile-dimmed blocks need a type the
   profile's policy lacks, 0 of 243 checkable kept blocks lost own rules;
   in clip-all as `profile`). Found on the way: the user's uncommitted
   CLIP 9 work on melody doesn't link with semodule/CIL (legacy validate
   passes): ro_user.te declares `role ro_user_r;` while
   userdom_restricted_user_template gen_requires it ("Re-declaration of
   role"; stock staff.te has `#role staff_r;`; rpmwrap then fails only
   because it needs ro_user_t). The user editor writes that `role R;` line
   (userUnits) and user-e2e only checks legacy validate. Reported to the
   user; not fixed yet. RHEL 8 CLIP: 147/147 confirmed, 0 of 257 lost.

The GitHub repo (github.com/tomtrostel/selinux-policy-tools) is
**public**; releases are visible to everyone.

## Working setup (how this project is developed and tested)

- Dev machine is Windows (D:\src\selinux-policy-tools, Git Bash +
  PowerShell); `npm test` runs locally (build tests skip on Windows).
- Linux test host: `ssh melody` (Rocky 9.8, key auth, user ttrostel; sudo
  needs a password, so ask the user for package installs). Test copy of the
  extension at ~/sepol-test/tools (sync with
  `tar czf - server test client package.json syntaxes | ssh melody 'cd ~/sepol-test/tools && tar xzf -'`),
  trees: ~/sepol-test/rhel9 (+ ~/sepol-test/srpm unpacked SRPM),
  ~/sepol-test/clip (git clone, tree in packages/selinux-policy/selinux-policy),
  ~/sepol-test/clip8 (CLIP branch RHEL8, same layout; pass its tree as the
  e2e tests' first argument; test/clip-args.js reads either CLIP's make
  arguments from its spec + Makefile),
  ~/sepol-test/mymodule (standalone module).
- RHEL 8 test host: `ssh ricardo` (Rocky 8.10, key auth since 2026-10-14,
  user ttrostel, sudo needs a password; checkpolicy 2.9, setools 4.3,
  Python 3.6, libselinux/libsemanage 2.9). Extension copy at
  ~/sepol-test/tools (same tar sync), CLIP RHEL8 clone at ~/sepol-test/clip8.
  RHEL 8's nodejs is 10 (too old for vscode-jsonrpc's `?.`): tests run with
  Node 20 from ~/opt/node, so prefix `export PATH=~/opt/node/bin:$PATH;`.
  `node test/clip-all.js ~/sepol-test/clip8/packages/selinux-policy/selinux-policy`
  passes there (multi-tree skips: no RHEL 10 tree).
  RHEL 8 differences found (handled): libsemanage 2.9 sorts equally
  specific fc lines with a file kind FIRST (filelabel `sortSpecs(specs,
  typedFirst)`, `typedFirstIn()`; server `hostTypedFirst()` reads the
  running file_contexts), and matchpathcon -f validates contexts against
  the running policy ("line N has invalid context"; no option to stop it),
  so the server's `expectedContexts(pol, paths, mode)` uses matchpathcon only
  for the running policy and fcLists otherwise; matchpathcon -m wants
  `pipe`, not `fifo_file` (unknown names are silently ignored).
- Run on melody: `node test/build-e2e.js`, `test/build-tree-e2e.js`,
  `test/build-rhel-e2e.js`, `test/diff-e2e.js`, `test/preview-e2e.js`,
  `test/checks-e2e.js`, `test/module-checks-e2e.js`, `test/scratch-e2e.js`,
  `test/service-e2e.js` (+ rhel9/rhel10 with their specs);
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
  define()d in the sources. Other names (0.8.0): `idx.branchState(f, b)`
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
- `server/denials.js`: denial assistant (audit parsing, grouping, verdicts);
  `media/denials.js` its webview.
- `server/packaging.js`: RPM spec and Makefile for standalone modules.
- `server/logins.js`: logins view (seusers/contexts/passwd parsing, ways in,
  paths); `media/logins.js` its webview.
- `server/levels.js`: level canonical form, setrans.conf names, descriptions.
- `server/loginctx.js`: login contexts (libselinux 3.x / 2.x context selection per seusers line and way in, problems); `media/loginctx.js` the Login Contexts webview (also session starts and How to fix).
- `server/sessions.js`: session starts after the context is picked (entrypoint, libraries, inherited terminal, NoNewPrivileges/nosuid, forced command, startup scripts, what the sessions run, typebounds).
- `server/kickstart.js`: install profiles from CLIP kickstarts (%packages, %include, Mako .tmpl, comps groups, separately packaged modules).
- `server/audittrace.js`: what a host logs for a refusal (AVC, hidden by dontaudit, SELINUX_ERR, the login program's log only).
- `server/ctxfiles.js`: context files (file_contexts, .local, home lines as genhomedircon writes them, the application context files); `media/ctxfiles.js` the Context Files webview.
- `server/localmods.js`: a host's local changes (semanage export parsing,
  comparison, fixes); `media/hostmods.js` the Host Changes webview.
- `media/levels.js`: Levels and Categories webview (context check, who
  ignores levels); the analysis is in policy_query.py (`levels`, `context`).
- `server/wrapper.js`: wrapped-programs module (model, render, read back,
  validate, checks, setup commands); `media/wrapper.js` its webview.
- `server/filelabel.js`: file-context parsing, fc_sort order, libselinux
  lookup order / subs / home templates; `media/filelabel.js` the File
  Labels webview.
- `server/userfiles.js`: user editor's users / seusers / contexts / kernel.te
  edits; the user model itself lives in `server/service.js` (model.user);
  `media/user.js` its webview.
- `server/service.js`: service editor model (catalogs, render, recognize,
  minimal edits by unit diff); `media/service.js` its webview form.
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
- `test/lsp-e2e.js` (in `npm test`): drives the server over stdio LSP against
  a workspace with a seeded test module (`policy/modules/local/myapp.*`,
  rewritten each run); 23 assertions (was print-only until 2026-10-14);
  makes the workspace from ../selinux-policy or $SELINUX_POLICY_SRC, skips
  without one.
- Unit tests added 2026-10-14 (all in `npm test`, any OS): test/diagnostics-test.js
  (synthetic tree: unknown-*, missing-require, missing-te-require scopes /
  unsure / tunable / ifdef / base, link-missing, net-port*, gen_user;
  diagnostics carry `msg`, not `message`), test/checks-test.js (whole checks
  language), test/build-test.js (parseBuildOutput, parseExpansion/rulesAt/
  renderExpanded — m4 -s repeats `#line N` before every line of a multi-line
  expansion —, alignGenerated/mapGeneratedDiagnostics, disableModules/
  overlaySource, findTrees/treeRootOf/treeOption, syncTree/treeSources/
  forgetStaleModuleSet, now exported), test/explain-test.js,
  test/policy_query_test.py via test/policy-query-test.js (fake setools
  module in sys.modules; Index built from a fake SELinuxPolicy; Python 3.9
  compatible; tries python3/python/py -3, skips without),
  test/client-test.js (stand-in vscode; extension.js exports FEATURES,
  showFeatures, addCheckLine, specPickItem, _setClient). specconfig-test also
  covers RHEL 9/10 specs; webview-transitions-test joined npm test (ranged
  edges).
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
- `test/webview-transitions-test.js` (in `npm test`; `npm run test:webview`):
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
- `test/service-test.js` (in `npm test`, any OS; `npm run test:service
  -- ../selinux-policy/policy` adds every daemon module): service editor
  model, minimal edits, webview with a fake DOM.
- `test/service-e2e.js` (`npm run test:service-e2e`, melody): new + edited
  service built with the tree; args `[tree [spec [variant]]]` (RHEL: copies
  the spec dir so modules.conf edits stay in the copy); standalone too.
- `test/package-e2e.js` (`npm run test:package`, melody): standalone service
  modules from a tree workspace, built and packaged as RPMs.
- `test/walkthrough-test.js` (in `npm test`) and `test/tutorial-e2e.js`
  (`npm run test:tutorial`, melody): the walkthroughs and the practice module.
- `test/denials-test.js` (in `npm test`) and `test/denials-e2e.js`
  (`npm run test:denials-e2e`, melody; optional tree arg, default CLIP);
  `test/denials-bench.js` (`npm run test:denials-bench`, melody).
- `test/logins-test.js` (in `npm test`) and `test/logins-e2e.js`
  (`npm run test:logins-e2e`, melody; optional tree arg, default CLIP).
- `test/loginctx-test.js` (in `npm test`), `test/loginctx-e2e.js`
  (`npm run test:loginctx-e2e`, melody/ricardo; optional tree arg, default
  CLIP RHEL 9) and `test/loginctx-survey.js` (installed | tree | build).
- `test/sessions-test.js` (in `npm test`) and `test/sessions-e2e.js`
  (`npm run test:sessions-e2e`, melody/ricardo; optional tree arg; in
  clip-all as `sessions`).
- `test/kickstart-test.js` (in `npm test`) and `test/profile-e2e.js`
  (`npm run test:profile-e2e`, melody; optional tree arg, needs CLIP's
  layout around it; in clip-all as `profile`).
- `test/restricted-e2e.js` (`npm run test:restricted-e2e`, melody/ricardo;
  optional tree arg; in clip-all as `restricted`).
- `test/ctxfiles-test.js` (in `npm test`), `test/ctxfiles-e2e.js`
  (`npm run test:ctxfiles-e2e`, melody/ricardo; optional tree arg) and
  `test/ctxfiles-survey.js` (installed | tree | build).
- `test/localmods-test.js` (in `npm test`) and `test/hostmods-e2e.js`
  (`npm run test:hostmods-e2e`, melody; optional tree arg, default CLIP).
- `test/levels-test.js` (in `npm test`) and `test/levels-e2e.js`
  (`npm run test:levels-e2e`, melody; optional tree arg, default CLIP).
- `test/wrapper-test.js` (in `npm test`) and `test/wrapper-e2e.js`
  (`npm run test:wrapper-e2e`, melody; `[tree [spec [variant]]]`).
- `test/filelabel-test.js` (in `npm test`) and `test/filelabel-e2e.js`
  (`npm run test:filelabel-e2e`, melody; optional tree arg, default CLIP).
- `test/specconfig-test.js` (in `npm test`): CLIP spec + Makefile reading.
  `test/clip-args.js`: CLIP make arguments for a tree (from its spec).
- `test/user-test.js` (in `npm test`) and `test/user-e2e.js`
  (`npm run test:user-e2e`, melody; `[tree [spec [variant]]]` like
  service-e2e).
- `test/clip-all.js` (`npm run test:clip-all`, melody; 2026-10-14): every
  tree-based e2e test (build-tree checks diff preview filelabel logins
  loginctx sessions restricted ctxfiles denials service user wrapper package levels hostmods profile multi-tree) on CLIP RHEL 8
  and RHEL 9 (or named trees; `--only a,b`), then diag-survey (`--json`)
  per tree vs test/survey-baseline.json keyed by the tree's VERSION
  (2.20200229: 8 findings, 2.20240226: 4; all reviewed, real);
  `--update-baseline` after review. Logs in /tmp/clip-all-*.
- `test/tmpdirs.js`: `tempDir(prefix)` for every test's temp dirs (not
  clip-all's logs, not lsp-e2e's fixed workspace); removed on exit, Ctrl-C
  and kill; `KEEP_TMP=1` keeps them and prints their paths. Before it, every
  e2e run left its tree copies in /tmp (filled ricardo's root disk along
  with PCP's pmlogger archives).
- `test/diag-survey.js` (prints undecided branch counts with `--make`; `--json FILE` writes every finding): runs all diagnostics over a tree and summarizes;
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
- CLIP for RHEL 8 (branch `RHEL8`, refpolicy 2.20200229, MCS, ~/sepol-test/
  clip8; user request 2026-10-13: "all of these tools to also work with the
  RHEL 8 version of CLIP"). specconfig.js `clipBuildConfigs()`: specs
  without %makeCmds but with `%installCmds A B C D E` → the installCmds
  body's base.pp make line with %N / %{…} filled in; type from the repo's
  CONFIG_BUILD, enable_modules/separatePkgs from `makeVars()` of the
  Makefile next to the spec (+=, ?=, continuations, comments, ifeq/ifneq
  on plain variables decided with what's set so far); files {} (the tree's
  own modules.conf); result `clip: true`. RHEL 9 CLIP gives exactly the old
  hand-written list; RHEL 8 adds denyhosts + consolekit; it has -cil and
  -nocil specs (the Makefile uses -cil for OS_REL >= 7.3). All tree e2e
  tests pass on it (build-tree, checks, diff, preview, filelabel, logins,
  denials, service, user, wrapper, package); test adjustments only (no
  shadow_history_t, files_pid_file instead of files_runtime_file, rpm.fc
  line, cron.te's auth_use_pam already requiring shadow_t). Survey: 8
  findings, all real (rpm_run lacks rpm_script_t, ssh_server_template lacks
  ssh_server, 4 unknown interfaces (3 in cockpit, off), 2 undefined
  *_inherited_file_perms in userdomain.if). 1905 types. Builds with RHEL 9's
  checkpolicy (policy.33; OUTPUT_POLICY=31 for RHEL 8's version).
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
