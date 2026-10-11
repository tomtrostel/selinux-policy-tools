# Compare with what is installed

**SELinux: Compare Build with Installed Policy** answers "what would change
on this host if I installed my build?".

It loads every module package of your build into a scratch policy store
with `semodule`, the way an installed system builds its policy (no root
needed), and compares the result with `/etc/selinux/<name>/policy`:

* **+** would be added by installing your build, traced to your sources;
* **−** exists only on the host: separately packaged modules (such as
  container-selinux), local modules, `semanage` and `setsebool -P`
  customizations, or things your build removes.

Use it before rolling a policy out, to find local customizations that would
be lost or that your build should adopt.
