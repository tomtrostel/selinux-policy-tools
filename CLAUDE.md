# SELinux Policy Tools: project context

VS Code extension + language server for editing **uncompiled refpolicy-style
SELinux policy** (RHEL 9/10 `selinux-policy` source and CLIP-style locked-down
policies derived from it). Plain JavaScript (CommonJS), no build step.

## Goals and roadmap

Status as of 2026-10-11: **v0.10.1 released** (GitHub release `v0.10.1`;
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
ranked keyword search for interfaces.
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
   Grouping long lists (item 4, done, unreleased): extraSection groups
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
   Ideas not done: file access under a
   boolean, gen_bool.

7. **Tutorials** (done, 0.9.0; user request: "tutorials … integrate
   them into the vsix … how to use the add-on and how it can help them
   making and maintaining SELinux policies"). package.json
   `contributes.walkthroughs`: getStarted (8 steps), services (9), denials
   (4), lockdown (7); pages in media/walkthroughs/<wt>/<step>.md; step
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
  ~/sepol-test/mymodule (standalone module).
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
