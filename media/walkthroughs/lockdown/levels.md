# Levels and categories (MLS / MCS)

Every context ends in a **level**: `s0`, or `s0:c1,c2` with categories, or a
range `low-high` for a process (`s0-s0:c0.c1023`). In an **MCS** policy (the
RHEL default) there is only `s0`. Categories are what keep two containers or
two virtual machines apart: each gets its own pair, and a process may use an
object only if its clearance covers all of the object's categories. **MLS**
adds ordered sensitivities (`s0` to `s15`): no read up, no write down.

Open **SELinux: Levels and Categories…** (also in the All Features menu).
*Rules from* picks an installed policy or your last build.

**Can it access?** Give a process context, an object context (or a file, to
use its label), a class and permissions. The answer says whether the source
context is possible at all (role, type, level within the user's range),
what the type rules allow, and every constraint with its comparisons in
plain words: "the process's clearance (s0:c1.c2) covers the object's high
level (s0:c1,c3)" ✗. Try the *Two containers* example. A denial caused by a
constraint has **Check in Levels and Categories** in the denial assistant.

**Who ignores levels** groups the domains by the level constraints they
pass *whatever the levels*, and says why: "not in mcs_constrained_type"
(upstream MCS binds only the domains in that attribute) or "in mlsfileread"
(an exemption attribute). It reads the compiled constraints, so it works for
any way a policy writes them. Compare two policies: CLIP for RHEL 8 holds
192 of its domains to every constraint; CLIP for RHEL 9 holds none.

**Kept apart by levels?** Two containers share `container_t` and the same
file types; only their categories tell them apart. For the domains you give,
this lists the accesses to objects two of their processes can share that no
level constraint checks: `connectto` on another container's socket, System V
shared memory, and so on.

**Level names** from `setrans.conf` (`SystemLow`, `SystemHigh`, …) show in
these answers, in File Labels and Logins and Users, and when you hover a
level in the sources. **Range transitions** (a program started at a fixed
level) are purple edges in the transition graph.

Pin what you rely on in `selinux.checks` (*Add check* writes them):

```
never container_t svirt_t may ignore levels
require container_t isolated by levels
only init_t kernel_t udev_t may ignore levels
```
