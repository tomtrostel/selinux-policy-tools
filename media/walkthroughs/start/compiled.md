# Browse the compiled policy

Sources say what modules *declare*. The **Compiled Policy** view shows what
the policy actually *contains* after the last build, with modules turned on
or off, booleans, attributes and templates all resolved. For a standalone
module, that's your module linked with this host's installed policy.

Under **Modules**, **Domains**, **Types**, **Attributes**, **Roles**,
**Users** and **Booleans**:

* every type shows its attributes, aliases and roles, and the domain
  transitions in and out of it;
* **Can access** lists the allow rules with the type as source, grouped by
  target; **Accessed by** lists them with the type as target. Rules that
  come from an attribute are marked (*via domain*), and conditional ones show
  their boolean;
* expanding a rule shows the **source lines that produce it**, with the
  interface call they came through: `logging.te:77 via init_daemon_domain(…)`.

**SELinux: Find in Compiled Policy** searches everything by name.

This is the view for questions like "who can write this file type?" or "why
is my daemon allowed to do that?". The answer is the rule plus the line that
grants it.
