# Split off helper programs

Many services run other programs: a script on each event, a worker
process, a small privileged helper. By default these run in the service's
own domain, with **all** of its rights. Often they need far fewer, or
different ones: a backup hook that only reads the data, a helper that alone
needs a dangerous capability, so that the service itself doesn't.

**+ New helper program** gives such a program a domain of its own:

* **name**: the domain is `NAME_t` and its program's type `NAME_exec_t`
  (`mydaemon_helper_t` if you leave it empty);
* **program**: its path(s). When the service runs it, the process switches
  into the helper's domain (`domtrans_pattern`);
* **the service may signal it**: so it can stop the helper;
* **access to the service's files**: for each file type, none, read,
  append or manage. A helper that only reads the state data gets exactly
  that;
* **the helper may also**: system access, process rights, capabilities,
  ports and interfaces, chosen separately from the service's.

The helper inherits **nothing** from the service. Its rules go into a
`# NAME_t local policy` section of their own.

**Example:** a mail-sending hook that reads the state data and sends mail.
The service doesn't get *Send mail*, only the helper does, and the helper can't
touch the service's sockets, logs or network ports.

A path can have only one label. The form refuses to give the same path to
the service's program and to a helper's, since `setfiles` would reject the
policy.
