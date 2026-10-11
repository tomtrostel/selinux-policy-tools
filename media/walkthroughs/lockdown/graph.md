# Who can become whom: the transition graph

Confinement is only as strong as the ways *out* of a domain. If a confined
daemon can execute a program that runs in an unconfined domain, the
daemon effectively is unconfined.

**SELinux: Show Domain Transition Graph** draws the domain transitions of
the last build, starting from `init_t`, the domain under the cursor, or any
domain you pick:

* **click** a domain to expand where it can go; switch to *who can
  enter* to see who can reach it instead;
* **double-click** opens its declaration; **Alt+click** makes it the root;
* solid arrows are automatic transitions, dashed ones explicit
  (`setexec`: `runcon`, `sudo`), dotted ones dynamic; orange ones depend
  on a boolean. Hover an arrow to see its entry point.

A transition is drawn only when the compiled policy allows all of it: the
`transition` permission, plus an entry point the source can execute.

Questions to ask of a locked-down policy:

* Which domains can reach `sysadm_t` or `unconfined_t`?
* Can a network-facing daemon reach a domain that can write `shadow_t`?
* What does `user_t` reach through setuid programs?

Found a path you never want? Turn it into a property check:
`never user_t reaches sysadm_t`.
