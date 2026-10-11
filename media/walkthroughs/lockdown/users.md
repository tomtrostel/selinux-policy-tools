# Users, roles and MLS levels

Who logs in as what is part of the lockdown too. In `policy/users`, the
`gen_user(...)` lines are checked as you type:

* roles that aren't declared anywhere;
* sensitivities and categories outside what the build defines (an MCS
  build has only `s0`), ranges whose high level is below the low level;
* a user defined twice in the same configuration.

Role names and MLS macros complete inside `gen_user`, and hovering a user
shows its roles, range and the Linux logins mapped to it in the last build.

In the **Compiled Policy** view:

* **Users** → their roles, MLS range, default level and Linux logins
  (from the tree's `seusers`);
* **Roles** → the domains they may run, the roles they may switch to, role
  transitions, and the users that have them.

Turn the important facts into checks:
`only sysadm_r may run sysadm_t`, `never staff_u may use sysadm_r`.
