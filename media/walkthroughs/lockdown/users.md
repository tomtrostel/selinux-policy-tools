# Users, roles and logins

Who logs in as what is part of the lockdown too. In `policy/users`, the
`gen_user(...)` lines are checked as you type:

* roles that aren't declared anywhere;
* sensitivities and categories outside what the build defines (an MCS
  build has only `s0`), ranges whose high level is below the low level;
* a user defined twice in the same configuration.

Role names and MLS macros complete inside `gen_user`, and hovering a user
shows its roles, range and the Linux logins mapped to it in the last build.

**SELinux: Logins and Users…** (the person icon in the Policy Explorer)
answers the question a reviewer asks: *who can do what once logged in?*

* **Linux logins**: which SELinux user each login gets (`seusers`), with
  warnings such as `__default__` on a user with an admin role, or a login
  mapped to `unconfined_u`;
* **SELinux users**: for each one, where ssh, the console, cron jobs and the
  other ways in land, and every domain its sessions can reach by running
  programs and changing role (`newrole`, `sudo -r`);
* **Risky abilities within reach**, with the path there: running
  unconfined, loading a policy, switching to permissive, reading
  `/etc/shadow`, writing raw disks;
* **Ask**: "can `staff_u` read `/etc/shadow`?": yes with the path and the
  rule, or no;
* on the host itself, **people's** and **service accounts**: a service runs
  as `system_u` in its own domain whatever its account; the account's
  seusers line matters only if it can log in (a `postgres` account with
  `/bin/bash`).

Choose **Policy → Last build** to review your tree's own `seusers` and
contexts before it ships.

**SELinux: New User…** (or *New User…* in that panel) creates a user in the
tree from a form: what kind of user (ordinary, restricted, administrator,
or an admin role entered from another role), its Linux logins, how it may
log in, the roles it may switch to, sudo and the services it administers.
The preview shows every file it writes: the role module, its `gen_user`
line, the role in `kernel.te`, `seusers` and its own contexts file. After
the build, **Logins and Users** shows where its logins land and what it can
reach.

For an account that scripts log in as (Ansible, backups), **Start from →
Automation account** sets up ssh and cron logins with sudo into one narrow
role, and shows the sudoers line to add. **Preview what it can reach**
builds the policy with the planned files in a scratch copy and shows where
its logins land and what they can reach, before anything is written; for
an existing user, what the change adds or takes away.

A new user can also be **Standalone**: a module of its own built against
the host's devel headers, with an RPM spec whose install script creates the
SELinux user and its logins with `semanage` and installs its contexts file.
Package it with **SELinux: Build RPM**.

**SELinux: Edit User…** opens an existing user (staff, sysadm, guest, a
confined admin role, …) in the same form and changes only the lines of the
settings you change. Taking a way in away (say, console logins for staff_u)
also takes its context off that line in the shared `default_contexts`,
since logins fall back to it.

In the **Compiled Policy** view:

* **Users** → their roles, MLS range, default level and Linux logins
  (from the tree's `seusers`);
* **Roles** → the domains they may run, the roles they may switch to, role
  transitions, and the users that have them.

Turn the important facts into checks:
`only sysadm_r may run sysadm_t`, `never staff_u may use sysadm_r`.
