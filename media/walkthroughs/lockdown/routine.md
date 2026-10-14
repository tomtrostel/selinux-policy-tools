# A lockdown routine

Putting it together, a repeatable way to shrink and harden a policy:

1. **Decide what to drop.** Browse the Compiled Policy view: modules, the
   domains they add, and who reaches them in the transition graph.
2. **Preview** turning a module off. Fix or accept link errors and dropped
   optional blocks, then **Apply**.
3. **Save** `modules.conf`. The tree builds, and the *link-missing*
   diagnostics show any module left without a dependency.
4. **Checks** run automatically. Anything the change broke (logging,
   administration paths, which logins reach what, who ignores levels)
   shows as ✗ with its cause.
5. **Compare with the last release tag** and read the compiled differences,
   not the text diff.
6. **Compare with the installed policy** on a representative host, and with
   **its local changes** (*Compare Host's Local Changes…*): write the ones
   that belong into the policy, so hosts stop depending on them.
7. **Build** with `selinux.build.tree.outputDir` set to keep the packages,
   `policy.bin` and a `build-info.json` record of exactly what was built.

Commit the `modules.conf` change and the checks file together. The checks
then document *why* the policy looks the way it does, and they keep holding
it to that.
