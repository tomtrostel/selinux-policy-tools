# Turn modules off, without surprises

A locked-down policy ships only the modules it needs. But turning a module
off in `modules.conf` does more than remove its types:

* other modules that **hard-depend** on it fail to link;
* every `optional_policy` block in other modules that mentions it
  **drops out entirely**, together with any unrelated rules in the same
  block.

**SELinux: Preview Turning a Module Off/On…** (or right-click a module in the
Policy Explorer) builds the tree with that one change in a separate scratch
copy, so your normal build is untouched, and shows:

* **link errors**, placed on the interface call in the other module that
  needs the missing type (`postfix.te:313: mta_getattr_spool(…)`);
* **optional blocks that drop out** (or come alive when turning a module on),
  each clickable;
* the resulting **rule, type and role changes**, traced to source.

**Apply** edits the module's line in `modules.conf` (or the RHEL spec's
`modules-*.conf`) for you to review and save. A module forced on through
`APPS_MODS` is handled too.

Even before building, the editor marks modules whose hard dependencies are
off (diagnostic *link-missing*), all of them at once. `semodule_link`
reports only one per build, and with no line.

The `optional_policy` blocks the linker drops are **dimmed** in the editor,
like inactive `ifdef` branches; hovering one says which type it needs and
which module (off in `modules.conf`) declares it, and shows what the block
would compile to. In a CLIP tree, **SELinux: Select Install Profile…** picks a
kickstart, so modules packaged on their own that its hosts don't install count
as absent too.
