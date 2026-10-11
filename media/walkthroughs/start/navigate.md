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

Blocks the build doesn't compile, ``ifdef(`distro_debian', …)`` for
example, are **dimmed**, and they are left out of the index and the
diagnostics. Hover the condition to see why.
