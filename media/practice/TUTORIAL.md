# SELinux Policy Tools: practice module

`notesd` is a made-up daemon: it keeps notes in `/var/lib/notesd/`, logs to
`/var/log/notesd.log`, and listens on a TCP port. Its policy has **four
deliberate mistakes** for you to find and fix with the editor.

The walkthrough **Get started with SELinux Policy Tools** (*SELinux: Open
Tutorials*) explains each step. This page is the short version.

## 1. Look around

* Hover `init_daemon_domain` in `notesd.te`, then press **F12** on it.
* **Shift+F12** on `notesd_log_t` lists every place it is used.
* **Ctrl+T**, type `urandom`: jump to any type or interface by name.

## 2. Fix the mistakes

Open the Problems panel (**Ctrl+Shift+M**) and use the quick fixes
(**Ctrl+.**):

1. `notesd.te`: `lisen` is not a `tcp_socket` permission.
2. `notesd.te`: `logging_send_syslog_mesg` is misspelled.
3. After fixing 2, a new warning appears: `urandom_device_t` comes from
   another module. Rather than adding a `require`, replace the line with the
   interface made for it: type `dev_read` and pick `dev_read_urand`.
4. `notesd.if`: `notesd_var_lib_t` is missing from `gen_require`.

## 3. Build

Save the files: each save builds the module in a scratch directory (needs
`selinux-policy-devel` on a Linux host). Then hover
`dev_read_urand(notesd_t)` to see the rules it compiled to, and run
**SELinux: Show Expanded Policy** for the whole module after m4.

## 4. Check properties

Open `selinux.checks`: after a build, each line shows whether it holds for
the module linked with this host's installed policy. Try adding
`never notesd_t may read shadow_t`: on RHEL it fails, and the Problems
panel shows the rule responsible.

## 5. Edit it as a service

**SELinux: Edit Service…** → `notesd` opens the module in the service editor.
Add a cache directory, a port, or a helper program, and watch the preview
change only the lines that need to.

## Solutions

<details>
<summary>The fixed lines</summary>

```
allow notesd_t self:tcp_socket { create bind listen accept };
logging_send_syslog_msg(notesd_t)
dev_read_urand(notesd_t)
```

and in `notesd.if`:

```
	gen_require(`
		type notesd_var_lib_t;
	')
```

</details>
