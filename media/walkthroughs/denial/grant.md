# Grant it with an interface, not a raw rule

`audit2allow` would write:

```
allow notesd_t urandom_device_t:chr_file { open read };
```

That works today, but it reaches into another module's private type,
needs a `require` block, breaks if that module renames the type, and
usually forgets related permissions (`getattr`, `ioctl`), which leads to
the next denial. The module that owns the type offers an **interface**
that does it properly:

```
dev_read_urand(notesd_t)
```

**Finding the interface:**

* Type the beginning in a `.te` (`dev_read`, `files_read`, `logging_`):
  completion lists interfaces with their summaries and inserts them with
  named parameters.
* Interfaces are named `<module>_<verb>_<object>`, and the module is the one
  that owns the type: hover the type to see which module that is, then
  **Ctrl+Alt+M** to open the module and scan its `.if` outline.
* In the service editor, **Other interfaces** searches names *and*
  descriptions: "random", "nfs read", "journal".
* Hover a candidate to read its documentation and what it requires;
  **F12** shows its body.

For services you edit with the form, prefer the form: many common needs are
in **System access** in plain words.

When no interface fits (your own module's types, or `self` rules), a plain
`allow` rule is right. Write it with completion: after `:` you get the
object classes, then only the permissions valid for that class.
