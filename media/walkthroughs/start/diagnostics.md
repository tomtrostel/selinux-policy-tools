# Fix problems as you type

The extension checks policy while you type, long before a build would fail,
and offers a **quick fix** (light bulb, or **Ctrl+.**) where it can.

It reports:

* interfaces and macros that don't exist (with the closest names);
* object classes that don't exist, and permissions a class doesn't have;
* in an `.if`, types an interface uses but forgot in its `gen_require`;
* in a loadable module's `.te`, types of other modules used without a
  `require`;
* in a tree, modules that will fail to link because a module they need is
  off in `modules.conf`;
* port numbers that are out of range or declared twice, unbalanced quotes
  and parentheses, and bad users, roles and MLS levels.

## Practice

Open the **Problems** panel (**Ctrl+Shift+M**) with the practice module open:

1. `notesd.te`: **`lisen`** isn't a `tcp_socket` permission. Use the
   quick fix: *Change to 'listen'*.
2. `notesd.te`: **`logging_send_syslog_mesg`** doesn't exist. Quick fix:
   *Change to 'logging_send_syslog_msg'*.
3. Now a third warning appears: **`urandom_device_t`** comes from another
   module, and a loadable module must `require` it. (It only showed up once
   every interface in the file was known: when it can't be sure, the
   extension stays quiet rather than guess.) The quick fix adds the
   require, but the better fix is to replace the whole line with the
   interface made for it: `dev_read_urand(notesd_t)`. Type `dev_read` and
   pick it from the completion list.
4. `notesd.if`: **`notesd_var_lib_t`** is used but missing from
   `gen_require`. Quick fix: *Add 'type notesd_var_lib_t;' to gen_require*.

Diagnostics are tuned to stay quiet when unsure: on the whole Fedora policy
they report nothing that isn't a real problem.
