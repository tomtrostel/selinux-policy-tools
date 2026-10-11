# Check what you actually granted

An interface name is a promise. Before you ship, check what it delivers.

**"Compiles to" hover.** Save (that builds), then hover the line you
added: you see the exact rules it produced. If `files_manage_etc_files`
shows write access to every file in `/etc`, that's more than "write my
config". Use your own config type instead.

**Changes since HEAD** (trees in git). **SELinux: Compare Compiled Policy
with HEAD** compares the compiled policy with the committed version:

```
allow notesd_t urandom_device_t:chr_file   +getattr +ioctl +lock +open +read
    notesd.te:40   via dev_read_urand(notesd_t)
```

Every added or removed permission is listed and traced to your line. It also
shows the side effects you didn't write, such as an interface that grants a
second type, or a type added to an attribute that carries rules of its own.
"No effective policy change" means the grant was already there and the
denial has another cause (often a label, or a `dontaudit` hiding the real
denial; `semodule -DB` disables those).

**Property checks keep it from coming back.** If a fix must never grow
into something dangerous, write it down in `selinux.checks`:

```
never notesd_t may write shadow_t
never notesd_t reaches unconfined_t
```

Checks are re-run after every build. A violation is reported with the rules
and the source lines that cause it.

Then retest: `sudo semodule -i …` (or ship the tree), repeat the action,
and `ausearch -m avc -ts recent` should stay empty.
