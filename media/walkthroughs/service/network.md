# Network: ports it serves and ports it uses

SELinux controls network access by **port type**: `http_port_t` covers 80,
443, 8080 and more; `postgresql_port_t` covers 5432.

* **Listens on**: ports clients connect to. Allows binding and listening on
  that port type, plus the socket rules.
* **Connects to**: ports of other servers it talks to.

Type a few letters to pick a port type: the list shows each type's port
numbers. `all` means any port, so use it only when the service really
connects anywhere (a proxy, a monitoring agent), and consider putting it
under a boolean.

**A port no type covers yet?** **+ New port type** creates one for the
service:

* in a **tree**, it adds `network_port(mydaemon, tcp,9999,s0)` to
  `corenetwork.te.in` (shown as a fourth file in the preview), and the
  service gets the usual `corenet_*` interfaces for it;
* in a **standalone module**, the module declares the type itself. A loadable
  module can't set port numbers, so the form lists the
  `semanage port -a -t mydaemon_port_t -p tcp 9999` command to run after
  installing.

A port number that already belongs to another type is refused: each port
number has exactly one type. Pick that type instead.

Binding a port below 1024 also needs the **net_bind_service** capability
(under *Process and capabilities*).
