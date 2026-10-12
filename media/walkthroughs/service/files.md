# Give it files of its own

Each **+ button** in *Files* adds a type for one kind of file the service
owns:

| Kind | Typical path | Default access |
| --- | --- | --- |
| Runtime files | `/run/mydaemon/` (PID file, sockets) | manage |
| State data | `/var/lib/mydaemon/` | manage |
| Log files | `/var/log/mydaemon/` | create and append |
| Configuration | `/etc/mydaemon.conf` | read only |
| Cache, spool | `/var/cache/…`, `/var/spool/…` | manage |
| Temporary files, shared memory, lock files | none: labeled when created | manage |
| systemd unit file, init script | the unit / script | label only |

**Paths.** A path ending in `/` means the directory *and everything in it*
(`/var/lib/mydaemon(/.*)?` in the `.fc`). Anything else is a single file.
Add `-d` (directories only) or `--` (plain files only) after a path to
narrow it: `/usr/share/mydaemon/ -d`. Existing modules show these flags
where their `.fc` has them.

**Access levels.** *Create and append* lets the service add to its logs but
not rewrite or delete them, so an attacker who takes it over can't hide their
tracks. *Label only* gives the service no access at all, which is useful for
files other programs use (the unit file, so that policy can say who may
start the service). In an existing module, a file type whose rules match
none of the levels (e.g. `mmap_manage_files_pattern`) reads **custom (kept
as written)**: its rules are listed under the row, click one to open it, and
**Show what they allow** sums them up. Picking a level replaces them.

**Type transitions are automatic.** What the service creates directly in
`/run`, `/var/lib`, `/tmp`, … gets its own type without any extra rule.

Why bother? Files labeled `mydaemon_var_lib_t` can be readable by your
service and nobody else, unlike generic types such as `var_lib_t` that half
the system can read.
