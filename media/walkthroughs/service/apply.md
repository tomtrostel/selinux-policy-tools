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

**Test in permissive mode first.** With *Permissive while testing* on, the
service works normally and every denial is logged. Exercise everything it
does (start, reload, normal traffic, log rotation, stop), then read the
denials:

```
sudo ausearch -m avc -ts recent | grep mydaemon_t
```

Fix each one in the form, or see the walkthrough **Fix a denial the right
way**. When a full test run logs nothing, turn permissive off.

Resist `audit2allow -M`: it turns every denial into a raw rule, including
ones that point to a labeling mistake or that should be a boolean.
