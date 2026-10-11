# Build, and see what a line really grants

**Saving builds.** Every save compiles the module (or the whole tree) in a
private scratch directory with the real Makefile, unsaved edits included,
so nothing is written next to your sources. Compiler errors, link errors
and deprecation warnings land on the source line that caused them, even
when the real culprit is deep inside an interface.

**"Compiles to" hover.** After a build, hover an interface call, e.g.
`dev_read_urand(notesd_t)` in the practice module, to see the actual
`allow` rules it produced, nested calls included. This is the quickest way to
learn what an interface really does, and to spot one that grants more
than you wanted.

**Show Expanded Policy** opens the whole module after m4, each block headed
by the source line that produced it.

**Build** (🔧 in the editor title) for a standalone module also writes
`notesd.pp` next to the `.te`. **SELinux: Install Module** builds it and
runs `sudo semodule -i notesd.pp` in a terminal on the policy host. For a
tree, set `selinux.build.tree.outputDir` to keep the packages and
`policy.bin` of each explicit build.

Build output goes to the **SELinux Build** output channel.
