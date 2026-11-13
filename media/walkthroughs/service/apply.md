# Create, build, install and test

**Create module** writes the files shown in the preview (and the
`modules.conf` line in a tree) as one undoable edit and saves them. Saving
builds them, and errors would appear in the Problems panel as usual.

**Install and label** (standalone module):

1. **SELinux: Install Module** runs `sudo semodule -i mydaemon.pp`.
2. Label the files that already exist:
   `sudo restorecon -Rv /usr/bin/mydaemon /var/lib/mydaemon /etc/mydaemon.conf`.
3. New port numbers: run the `semanage port -a …` commands the form listed.
4. `sudo systemctl restart mydaemon`, then check it runs confined:
   `ps -eZ | grep mydaemon` shows `…:mydaemon_t:…`.

In a tree, the module is part of the policy you build and ship.

**Fill the form in from the host first.** For a new service, the form's
**From the host** section looks at the program where it runs (this host, or
a connected target host) and fills in what the host already knows: the
package's files as the service's file types, the unit's directories,
capabilities and hardening, the ports it listens on and connects to, how it
is started, and what its libraries say it talks to. Each setting names its
source. *New Service…* from **What Runs Unconfined** does this at once.

**Test in permissive mode first.** With *Permissive while testing* on, the
service works normally and every denial is logged. Exercise everything it
does (start, reload, normal traffic, log rotation, stop), then read the
denials:

```
sudo ausearch -m avc -ts recent | grep mydaemon_t
```

Then open the form's **From a permissive run** section: **Read this host's
log** (or paste the denials, or **Open file…**) and **Apply to the form**.
Each denial of the service's domain becomes a setting of the form rather
than a raw rule: a higher access level on one of its file types, a new file
type for files it uses under a generic label (`/var/lib/mydaemon/…`), a
capability, a port, an access group or the narrowest interface. What the
form has no place for is listed with the rule it would need. Review, apply,
test again; when a full test run logs nothing, turn permissive off. For a
single puzzling denial, the walkthrough **Fix a denial the right way**.

Resist `audit2allow -M`: it turns every denial into a raw rule, including
ones that point to a labeling mistake or that should be a boolean.
