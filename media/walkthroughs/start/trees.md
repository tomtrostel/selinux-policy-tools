# Work on a full policy tree

A tree is built with **its own Makefile**, the way its RPM builds it:
`base.pp modules` first (compile errors in about a second), then
`make validate` (links every module, expands the policy and checks file
contexts, a few seconds more).

**RHEL and Fedora trees** need the variables and config files the RPM spec
passes in: policy name, type, `modules.conf`, `booleans.conf`, `users`.
Run **SELinux: Configure Build from Spec File…**, pick `selinux-policy.spec`
(from the unpacked source RPM or the dist-git checkout) and the variant
(targeted, minimum, mls, …). The settings are written to the workspace,
and your tree is never modified: config files are put into the scratch copy
only.

**CLIP** (the RHEL 8 and RHEL 9 branches): run the same command and pick
CLIP's spec, `packages/selinux-policy/selinux-policy.spec` (RHEL 9) or
`selinux-policy-cil.spec` (RHEL 8). Its make variables come from the spec,
and `APPS_MODS` from `SEPARATE_PKGS` in the Makefile next to it; the tree's
own `modules.conf` is used.

**Other trees**: put the make variables in `selinux.build.tree.makeArgs`,
for example `["NAME=clip", "TYPE=mcs", "APPS_MODS=…"]`.

**Several trees in one workspace** (RHEL 9, RHEL 10 and your own fork, say):
the extension works on one at a time. Opening a file of another tree
switches to it, or use **SELinux: Select Policy Tree…** (or click the
status bar). Each tree keeps its own build settings and results.

`ifdef` blocks are decided with the same flags the build uses, so the
dimmed code is exactly the code your configuration doesn't compile.
