# Find your way around

Policy is a web of interfaces calling interfaces. These are the moves you
will use all the time:

| Keys | Does |
| --- | --- |
| hover | Interface docs, parameters and what it requires; for a type, its attributes and the paths that get it; for a class, all its permissions |
| **F12** | Go to the definition, including names templates generate (`httpd_sys_content_t`, `corenet_tcp_bind_http_port`) |
| **Shift+F12** | Every use: who calls this interface, who touches this type |
| **Ctrl+T** | Jump to any type, interface or boolean by name |
| **Ctrl+Alt+M** | Open a module by name |
| **Ctrl+Shift+O** | Outline of the current file |

**Try it in the practice module:** open `notesd.te`, hover
`init_daemon_domain`, press F12 on it, then Shift+F12 on `notesd_log_t`.

The **Policy Explorer** (shield icon in the activity bar) lists layers →
modules → their types, attributes, booleans, interfaces and file contexts.
Right-click a module to edit it as a service or preview turning it off.

**Every feature in one menu:** click **SELinux** in the status bar (or
[All Features…](command:selinux.showFeatures)). Right-click any file,
in the explorer or the editor, for the **SELinux** menu: **Look Up File
Label** shows what label a file or program gets from each policy, the
line that sets it, who may access it and which domain running it starts.
[Look up /usr/bin/rpm](command:selinux.lookUpFile?%22%2Fusr%2Fbin%2Frpm%22)

Blocks the build doesn't compile, ``ifdef(`distro_debian', …)`` for
example, are **dimmed**, and they are left out of the index and the
diagnostics. Hover the condition to see why.
