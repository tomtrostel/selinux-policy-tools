# What did this change grant?

Reviewing policy changes by reading diffs of `.te` files is unreliable: one
interface call can expand to dozens of rules, an attribute change affects
every member, and a module turned off silently drops `optional_policy`
blocks elsewhere. Review the **compiled** result instead.

**SELinux: Compare Compiled Policy with HEAD** (Changes view) builds the
committed tree and compares it with your working tree:

* rules added, removed or changed, **per permission**, grouped by
  source domain;
* each change traced to the source line and the interface call that
  produce it, and removed rules to the committed line;
* added or removed types, attributes, attribute memberships, roles,
  users and booleans, and changed boolean defaults.

**SELinux: Compare Compiled Policy with…** compares other versions:

* a **release tag**: "what changed since the last release?";
* **two refs**: what the policy gained between `v1.4` and `v1.5`, traced
  into each version's sources, which is useful for change review and audits;
* a **saved build** exported with `selinux.build.tree.outputDir`.

Builds of committed versions are cached, so switching between them is quick
after the first time.
