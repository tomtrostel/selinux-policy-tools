# Compare with a host's local changes

Administrators change a running system with `semanage` (a file context
here, a port there, a boolean turned on, a login mapped to another user, a
module turned off, a domain made permissive) or add modules with
`semodule -i`. Those local changes survive policy updates, so hosts drift
from the policy you ship.

**SELinux: Compare Host's Local Changes…** shows them against your policy:

* **Read this host (sudo)** runs `semanage export` and
  `semodule --list-modules=full` in a terminal (enter your password there).
* **Read without sudo** gets what anyone can see: `file_contexts.local`,
  equivalences, and booleans whose value differs from the default.
* **Open file…** or paste: run the command it shows on another host and
  bring the file over.

Compare with **your last build** (the default). Each change gets a verdict:

* **only on the host**: your policy doesn't have it;
* **overrides your policy**: the host changes something your policy sets
  differently (a port your policy gives another type, a path it labels
  otherwise, a boolean it defaults the other way);
* **already in your policy** / **same as the default**: redundant on a
  host running your policy;
* **not in your policy**: it names a type, user, role or boolean your
  policy doesn't have. On a host running your policy it would fail.

Permissive domains, modules installed by hand, and logins mapped to
`unconfined_u` or users with admin roles are flagged.

**Write into the policy** shows the edit, then writes it:

* a file context goes into the `.fc` of the module that owns the type. An
  override changes the policy's own line for that path instead of adding a
  conflicting second one;
* a port goes onto its type's `network_port` line in `corenetwork.te.in`
  (an override moves the number from the other type);
* a boolean goes into `booleans.conf`, a login into the tree's `seusers`, an
  equivalence into `file_contexts.subs_dist`, and a module turned off into
  `modules.conf`.

The tree builds, and the changes then show as "already in your policy".
For the rest (users, permissive domains, interfaces), **copy line** gives
the source line to add by hand.
