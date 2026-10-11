# Set up the Linux host

Navigation, completion and source diagnostics work wherever VS Code runs.
Building, and everything that looks at the compiled policy, runs the real
SELinux toolchain, so it needs a Linux host (RHEL, Rocky, Alma, Fedora).

**On Windows or macOS**, connect to such a host with the **Remote-SSH**
extension and open the policy folder there. Install this extension in the
remote window: it runs on the host, next to the toolchain.

**On the host**, install the tools once:

```
sudo dnf install make m4 checkpolicy policycoreutils policycoreutils-devel \
    selinux-policy-devel setools-console git-core
```

| You want | Needs |
| --- | --- |
| Standalone module builds | `make`, `m4`, `checkpolicy`, `selinux-policy-devel` |
| Full tree builds | also `policycoreutils-devel`, `python3` |
| Compiled Policy view, Changes since HEAD, property checks | `setools-console` (python3-setools), `git-core` |

**Trust the workspace** when VS Code asks. Building runs the tree's own
Makefile, so builds are off in Restricted Mode (navigation still works).

The status bar shows `SELinux: N modules, N interfaces` once the folder is
indexed. Click it for details.
