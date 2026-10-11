# Ask: is the policy wrong, or the label?

Before adding any rule, decide which of these it is. Only the first
needs new policy.

**1. A legitimate need.** The service really must do this, and the object
has the right label. Add a grant (next step).

**2. A wrong label.** In the example, `notes.db` is `var_lib_t`, the
generic `/var/lib` type, instead of `notesd_var_lib_t`. The service is fine;
the file was created before the policy was installed, copied in with `cp`,
or its path isn't in the `.fc`. Check:

```
matchpathcon /var/lib/notesd/notes.db     # what the policy says it should be
ls -Z /var/lib/notesd/notes.db            # what it is
sudo restorecon -Rv /var/lib/notesd       # fix it
```

If `matchpathcon` itself says `var_lib_t`, the `.fc` is missing the path:
add it there (or under the file type's paths in the service editor).

**3. Harmless noise.** Programs often probe things they don't need (look
into home directories, read `/proc` of other processes) and work fine
when refused. Don't allow it: silence it with a `dontaudit` interface, or
leave it.

**4. Something only some sites need.** Grant it under a boolean.

**Use the extension to decide:** **Ctrl+T** → type the target type (e.g.
`var_lib_t`) → hover it: you see its module and the paths that get it.
In the **Compiled Policy** view, open the type → **Accessed by** to see
which domains may already use it and why. If a similar service already has
the access, its rule shows the interface it used.
