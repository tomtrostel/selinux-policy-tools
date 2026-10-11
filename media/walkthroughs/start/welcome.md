# What SELinux Policy Tools does

SELinux policy source (the `.te`, `.if` and `.fc` files of refpolicy, RHEL's
`selinux-policy`, or a module of your own) is m4 macros on top of a policy
language. It is hard to read, easy to get subtly wrong, and the compiler
only tells you about problems much later, far from the line that caused them.

This extension helps at three levels:

| Level | What you get |
| --- | --- |
| **Source** | Go to definition, hover docs, completion and diagnostics with quick fixes, for every interface, type, class and permission in your tree. Works on any OS. |
| **Compiled policy** | Real builds with the real toolchain on save, errors on the right line, "what does this line compile to", and a browsable view of the policy as the kernel will see it. Needs a Linux host. |
| **Reviewing and locking down** | What an edit *actually* granted, what turning a module off would break, who can reach which domain, and security properties checked after every build. |

And for the most common job, **writing the policy for a service**, there is
a form that writes correct refpolicy-style modules for you, and edits
existing ones without touching what you didn't change.

## Two kinds of workspace

* **A full policy tree**: the folder with `Makefile`, `Rules.modular`,
  `build.conf` and `policy/` (a `selinux-policy` checkout, upstream
  refpolicy, or a CLIP-style locked-down policy).
* **A standalone module**: a folder with `myapp.te`, `myapp.if` and
  `myapp.fc`, built against the installed `selinux-policy-devel` headers.

Don't have one at hand? **Create a practice module**: a small daemon policy
with four deliberate mistakes that the following steps walk you through.
