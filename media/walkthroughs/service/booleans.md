# Optional rights: booleans

Some rights only some sites need: connecting to any port, reading users'
home directories, sending mail. Instead of granting them to everybody, put
them under a **boolean** that administrators switch on with
`setsebool -P mydaemon_connect_any on`.

**+ New boolean** declares one in your module:

* **name**: start it with the module name (`mydaemon_connect_any`);
* **description**: what switching it on allows. `semanage boolean -l` shows
  it to administrators, so write it for them;
* **default**: off unless most installations need it.

Then add what it allows while on: system access, process rights,
capabilities, ports, interfaces. **Or use an existing boolean**, such as
`use_nfs_home_dirs`, so that your service follows the site's existing choice.

The form keeps out what conditional policy can't hold. The compiler allows
only plain rules under a boolean, so interfaces that declare attributes or
contain optional blocks (e.g. *Use the D-Bus system bus*) are offered as
always-on only. It also refuses granting the same thing both always and
under a boolean, which would fail the build for domain transitions.

In the `.te` this becomes `gen_tunable(…)` with its description comment, and
`tunable_policy(…)` blocks.
