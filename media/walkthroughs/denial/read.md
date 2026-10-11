# Read the denial

When SELinux blocks something, the kernel logs an **AVC denial**:

```
type=AVC msg=audit(1728650000.123:456): avc:  denied  { write } for
  pid=1234 comm="notesd" name="notes.db" dev="dm-0" ino=5678
  scontext=system_u:system_r:notesd_t:s0
  tcontext=system_u:object_r:var_lib_t:s0 tclass=file permissive=0
```

Find yours with `sudo ausearch -m avc -ts recent` (add `-c notesd` to filter
by program), or in `journalctl -t setroubleshoot` if setroubleshoot is
installed.

The four parts that matter:

| Field | Here | Meaning |
| --- | --- | --- |
| `scontext` type | `notesd_t` | **who**: the domain of the process |
| `{ … }` | `write` | **what** it tried |
| `tclass` | `file` | **on what kind of object** |
| `tcontext` type | `var_lib_t` | **the object's type**: its label |

Read it as one sentence: *notesd_t was denied write on a file of type
var_lib_t*.

**Let the extension read them:** **SELinux: Analyze Denials…** takes pasted
records, a saved log, or runs `ausearch` for you in a terminal (sudo asks
for your password there). It groups the denials by who, what and on what,
and joins each one with the program and the full path from the same audit
event.

`permissive=1` means it was only logged (the domain or the system is in
permissive mode). `name=` and `ino=` identify the object. With
`find / -inum 5678` or `ausearch -i` you can get the full path, which you
will need in the next step.
