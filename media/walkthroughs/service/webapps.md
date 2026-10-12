# Web applications (CGI scripts)

A web application such as Bugzilla or MediaWiki isn't a daemon: Apache runs
its CGI scripts, and the policy confines them in a domain of their own.
refpolicy declares that domain and the application's content types with one
call, `apache_content_template(NAME)`.

**New**: choose **What → Web application** in the service editor. The form
then has:

* **CGI scripts**: the scripts' paths, one per line. They get the script
  type (`NAME_script_exec_t`); when Apache runs them, the process enters the
  application's domain (`NAME_script_t`);
* **Run by**: Apache, through `apache_content_template(NAME)`;
* **Web content**: the types the template declares, each with its paths:

| Type | For | Scripts may |
| --- | --- | --- |
| `NAME_content_t` | pages, templates, its installation directory | read |
| `NAME_rw_content_t` | uploads, caches, its data directory | create, change, delete |
| `NAME_ra_content_t` | its own logs | create and append only |
| `NAME_htaccess_t` | `.htaccess` files | (Apache reads them) |

Upstream refpolicy (CLIP) names them `httpd_NAME_script_t`,
`httpd_NAME_content_t`, …; the form uses whatever your tree's template
declares.

Everything else works as for a service, on the script domain: network
(*Connect to* `postgresql`, `smtp`, …), system access, capabilities, file
types of its own (e.g. temporary files), other interfaces, booleans.

**Existing** web applications open the same way with **SELinux: Edit
Service…**: `bugzilla`, `mediawiki`, `awstats`, and the CGI parts of modules
like `collectd`, `git` or `munin` (pick the `…_script_t` domain). What the
template itself grants and declares is fixed; the form changes the module's
own rules and its paths in the `.fc`.

If your tree has the `apache` module turned off, a new web application is
refused: the module couldn't link.
