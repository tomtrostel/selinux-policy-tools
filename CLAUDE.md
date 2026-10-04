# SELinux Policy Tools: project context

VS Code extension + language server for editing **uncompiled refpolicy-style
SELinux policy** (RHEL 9/10 `selinux-policy` source and CLIP-style locked-down
policies derived from it). Plain JavaScript (CommonJS), no build step.

## Goals and roadmap

1. **Navigation and authoring help** (v0.1, done): definition, references,
   hover docs, completion, signature help, outline, Policy Explorer sidebar,
   diagnostics with quick fixes.
2. **"What did this change actually grant"** (in progress): run the real build
   (m4 + checkpolicy, refpolicy Makefile), map compiled rules back to source
   lines, show `sediff` against the last commit, show the expanded rules
   behind an interface call on hover. Done for standalone modules (devel
   headers) and full refpolicy trees (verified on CLIP RHEL 9): build on
   save, compiler + link diagnostics, "Compiles to" hover, expanded view.
   Next: sediff against the last commit (setools-console is on melody).
3. **Lockdown workflows**: module enable/disable with dependency warnings
   (removing a module silently disables `optional_policy` blocks elsewhere),
   users/roles/MLS editing, domain-transition graph, property checks via
   Datalog (Soufflé) and SMT (Z3) on the compiled policy (setools export).
4. Hardening: test against real RHEL 9/10 trees, performance, docs.

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
  to `<tmpdir>/selinux-policy-tools/<hash>/` and `make -f <devel Makefile>
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
  persistent scratch copy `<tmpdir>/selinux-policy-tools/tree-<hash>/`,
  synced before each build by rewriting only files whose content differs
  (so make's incremental rebuild works; outputs listed in refpolicy's
  .gitignore and generated corenetwork.te/.if are not copied). The tree's
  own Makefile runs with `selinux.build.tree.makeArgs` (the RPM spec's
  variables; build.conf otherwise). Phase 1 `base.pp modules` (~0.5 s
  incremental) publishes compile errors; phase 2 `validate` (~6 s: link
  3.4 s + expand 2.9 s) adds link errors. semodule_link reports only
  "<mod>'s global requirements were not met: type X"; the server places it
  on the first reference to X in that module's .te. Hover/expanded view
  read `tmp/<mod>.tmp` (loadable modules) or `base.conf` (base modules),
  parsed lazily and cached by mtime.
- **Compiled Policy view** shows the linked kernel policy of the last tree
  build (tmp/policy.bin), not the sources, so it reflects exactly what the
  lockdown enabled. `server/policy_model.py` (python3-setools) exports it as
  JSON (~0.6 s for CLIP); the server attaches a source location + module to
  each element from the index (types/attributes/roles/bools from decls,
  template-generated names via their call site, users from gen_user calls),
  cached by policy.bin mtime. The client tree is lazy and path-keyed;
  relationships (attributes, members, roles, domain transitions in/out) are
  derived client-side. Standalone-module mode has no linked policy.
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
  missing gen_require entries in `.if` interfaces, syntax balance.
- `server/server.js`: LSP features and custom requests
  (`selinux/modules`, `selinux/moduleContents`, `selinux/stats`,
  `selinux/reindex`, `selinux/build`, `selinux/expansion`,
  `selinux/expandedPolicy`; notifications `selinux/indexing`, `selinux/build`
  with states start / validating / done).
- `server/build.js`: toolchain detection, scratch-dir module build, tree
  build with scratch sync, parsers for checkmodule/m4/refpolicywarn/
  semodule_link output and the m4 `#line` expansion map.
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
- `test/build-tree-e2e.js` (`npm run test:tree`): full-tree build checks on
  a copy of a refpolicy tree (default: the CLIP RHEL 9 clone on melody, with
  CLIP's RPM make arguments built in); same conventions as build-e2e.
- `test/diag-survey.js`: runs all diagnostics over a tree and summarizes;
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
  Test host: `ssh melody` (~/sepol-test). RHEL 10 not yet verified.
- CLIP for RHEL 9: github.com/sealingtech/CLIP branch `RHEL9`, cloned on
  melody at ~/sepol-test/clip. Its policy is upstream refpolicy 2.20240226
  (not RHEL's fork) at `packages/selinux-policy/selinux-policy/`; the
  lockdown is `policy/modules.conf` (12 base, 55 module, 326 off) plus
  SEPARATE_PKGS passed as APPS_MODS. Survey: 2 missing-require + 2
  unknown-macro, all real latent bugs in uncalled interfaces. Builds
  90 packages, policy.33 with 1973 types. The tree has VS Code settings
  with CLIP's makeArgs in `.vscode/settings.json` (gitignored).
- Tree builds of the RHEL selinux-policy tree are untested (it ships no
  modules.conf; the spec copies modules-targeted-*.conf in).
- VS Code UI (Policy Explorer, status bar) has not been exercised in a real
  VS Code instance; the server is covered by the e2e test.
- `.te` files aren't checked for missing `require` blocks.
- `ifdef`/`ifelse` branches are all indexed as active.
- Windows paths: indexed paths come from `URI.fsPath` (lowercase drive
  letter); keep all path keys going through `toPath()` for consistency.

## Conventions

- Keep dependencies minimal (vscode-languageserver/client, vscode-uri).
- Every new diagnostic needs a survey run showing no new false positives.
- Prefer user-visible messages that say what to do, not just what's wrong.
