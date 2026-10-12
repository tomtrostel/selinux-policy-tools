'use strict';
/*
 * RPM packaging for a standalone policy module: a spec for an independent
 * `<name>-selinux` package following Fedora's SELinux policy packaging
 * guidelines (built against the build host's selinux-policy-devel, installed
 * with the %selinux_modules_install macros, file contexts relabeled with
 * %selinux_relabel_pre/post), and a Makefile that builds the module and the
 * RPM from the module's folder. The service's own package can then require
 * `<name>-selinux`.
 */

const DAYS = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
/** %changelog date: "Sun Oct 11 2026". */
const changelogDate = (d) => `${DAYS[d.getDay()]} ${MONTHS[d.getMonth()]} ${String(d.getDate()).padStart(2, '0')} ${d.getFullYear()}`;

/**
 * The spec text.
 *   name: module name; version: policy_module version; summary: one line;
 *   ports: [{ type, proto, port }] port numbers to label after installing
 *          (a loadable module can't carry portcon statements of its own);
 *   packager: "Name <email>"; date: Date;
 *   license: the License: tag (selinux.packaging.license, default MIT).
 */
/*
 * A user role module (user = { U, roles, level, range, prefix, logins: [{ login, range }],
 * grant: [users that also get the role], contexts: true when NAME_u_default_contexts ships }):
 * a loadable module can't declare SELinux users or login mappings, so %post creates them with
 * semanage after the module (and its role) is installed, and %postun removes them first.
 */
function userScripts(user, R) {
  const q = (s) => `'${String(s).replace(/'/g, "'\\''")}'`;
  const add = [], del = [];
  const roles = user.roles.join(' ');
  add.push(`# The SELinux user and its login mappings (a module can't declare them).`,
    `semanage user -a -R ${q(roles)} -L ${q(user.level)} -r ${q(user.range)} -P ${q(user.prefix)} ${user.U} 2>/dev/null || semanage user -m -R ${q(roles)} -L ${q(user.level)} -r ${q(user.range)} -P ${q(user.prefix)} ${user.U} || :`);
  for (const l of user.logins) {
    const r = l.range ? ` -r ${q(l.range)}` : '';
    const who = q(l.login.replace(/%/g, '%%')); // %group: %% is a literal % in a spec
    add.push(`semanage login -a -s ${user.U}${r} ${who} 2>/dev/null || semanage login -m -s ${user.U}${r} ${who} || :`);
    del.push(`    semanage login -d ${who} 2>/dev/null || :`);
  }
  del.push(`    semanage user -d ${user.U} 2>/dev/null || :`);
  // Other users that get the role: their current roles plus this one (and without it again on removal).
  const rolesOf = (u) => `$(semanage user -l | awk -v u=${u} '$1 == u { for (i = 5; i <= NF; i++) printf "%%s ", $i }')`; // %% = a literal % in a spec
  for (const u of user.grant || []) {
    add.push(`r=${rolesOf(u)}; case " $r " in *" ${R} "*) ;; *) [ -n "$r" ] && semanage user -m -R "$r ${R}" ${u} || : ;; esac`);
    del.push(`    r=${rolesOf(u)}; n=$(echo " $r " | sed 's/ ${R} / /g'); [ "$n" != " $r " ] && semanage user -m -R "$n" ${u} || :`);
  }
  return { add: add.join('\n'), del: del.join('\n') };
}

function specText({ name, version = '1.0.0', summary = '', ports = [], packager = 'Your Name <you@example.com>', date = new Date(), license = 'MIT', user = null }) {
  const desc = summary || (user ? `SELinux user ${user.U} and its role ${name}_r` : `SELinux policy for the ${name} service`);
  const semanage = ports.length > 0 || !!user;
  const portAdd = ports.map(p => `semanage port -a -t ${p.type} -p ${p.proto} ${p.port} 2>/dev/null || semanage port -m -t ${p.type} -p ${p.proto} ${p.port} || :`).join('\n');
  const portDel = ports.map(p => `    semanage port -d -t ${p.type} -p ${p.proto} ${p.port} 2>/dev/null || :`).join('\n');
  const us = user ? userScripts(user, `${name}_r`) : null;
  const ctxPath = user && user.contexts ? `%{_sysconfdir}/selinux/%{selinuxtype}/contexts/users/${user.U}` : null;
  return `# SELinux policy module for ${name}, packaged on its own${user ? ` with the SELinux user ${user.U}` : ` so the service's
# package can require it (Requires: ${name}-selinux)`}.
# Build: make rpm   (or: rpmbuild -bb --define "_sourcedir $PWD" ${name}-selinux.spec)
# Written by SELinux Policy Tools; edit freely (keep Version in step with
# policy_module() in ${name}.te).

%global modulename ${name}
%global selinuxtype targeted

Name:           %{modulename}-selinux
Version:        ${version}
Release:        1%{?dist}
Summary:        SELinux policy module for ${name}
# From the selinux.packaging.license setting.
License:        ${license}
Source0:        %{modulename}.te
Source1:        %{modulename}.if
Source2:        %{modulename}.fc
${ctxPath ? `# Where its logins land (contexts/users/${user.U}).\nSource3:        ${user.U}_default_contexts\n` : ''}BuildArch:      noarch

BuildRequires:  selinux-policy-devel
BuildRequires:  make
BuildRequires:  bzip2
Requires:       selinux-policy-%{selinuxtype}
Requires(post): selinux-policy-%{selinuxtype}
${semanage ? 'Requires(post): policycoreutils-python-utils\nRequires(postun): policycoreutils-python-utils\n' : ''}%{?selinux_requires}

%description
${desc}

This package contains the SELinux policy module %{modulename}.

%prep
%setup -q -c -T
cp -p %{SOURCE0} %{SOURCE1} %{SOURCE2} .

%build
make -f %{_datadir}/selinux/devel/Makefile %{modulename}.pp
bzip2 -9 %{modulename}.pp

%install
install -D -m 0644 %{modulename}.pp.bz2 %{buildroot}%{_datadir}/selinux/packages/%{selinuxtype}/%{modulename}.pp.bz2
install -D -p -m 0644 %{modulename}.if %{buildroot}%{_datadir}/selinux/devel/include/distributed/%{modulename}.if
${ctxPath ? `install -D -p -m 0644 %{SOURCE3} %{buildroot}${ctxPath}\n` : ''}
%pre
%selinux_relabel_pre -s %{selinuxtype}

%post
%selinux_modules_install -s %{selinuxtype} %{_datadir}/selinux/packages/%{selinuxtype}/%{modulename}.pp.bz2
${ports.length ? `# Port numbers for the module's port types.\n${portAdd}\n` : ''}${us ? `${us.add}\n` : ''}
%postun
if [ $1 -eq 0 ]; then
${ports.length ? `${portDel}\n` : ''}${us ? `${us.del}\n` : ''}    %selinux_modules_uninstall -s %{selinuxtype} %{modulename}
fi

%posttrans
%selinux_relabel_post -s %{selinuxtype}

%files
%{_datadir}/selinux/packages/%{selinuxtype}/%{modulename}.pp.bz2
%{_datadir}/selinux/devel/include/distributed/%{modulename}.if
${ctxPath ? `%config(noreplace) ${ctxPath}\n` : ''}%ghost %verify(not md5 size mode mtime) %{_sharedstatedir}/selinux/%{selinuxtype}/active/modules/200/%{modulename}

%changelog
* ${changelogDate(date)} ${packager} - ${version}-1
- Initial package
`;
}

/** A Makefile for the module's folder: `make` builds the .pp, `make rpm` the RPM (under ./rpmbuild). */
function makefileText(name, extra = []) {
  return `# Builds the ${name} policy module against this host's selinux-policy-devel,
# and its RPM (${name}-selinux). Written by SELinux Policy Tools.
NAME := ${name}
DEVEL_MAKEFILE ?= /usr/share/selinux/devel/Makefile

all: $(NAME).pp

$(NAME).pp: $(NAME).te $(NAME).if $(NAME).fc
\t$(MAKE) -f $(DEVEL_MAKEFILE) $@

rpm: $(NAME).te $(NAME).if $(NAME).fc $(NAME)-selinux.spec${extra.map(f => ` ${f}`).join('')}
\trpmbuild -bb --define "_sourcedir $(CURDIR)" --define "_topdir $(CURDIR)/rpmbuild" $(NAME)-selinux.spec
\t@find $(CURDIR)/rpmbuild/RPMS -name '$(NAME)-selinux-*.rpm'

clean:
\trm -rf tmp rpmbuild $(NAME).pp

.PHONY: all rpm clean
`;
}

/** Common open source licenses offered in the service editor (SPDX identifiers). */
const LICENSES = [
  { id: 'MIT', label: 'MIT' },
  { id: 'Apache-2.0', label: 'Apache License 2.0' },
  { id: 'GPL-2.0-or-later', label: 'GNU GPL v2 or later' },
  { id: 'GPL-2.0-only', label: 'GNU GPL v2 only' },
  { id: 'GPL-3.0-or-later', label: 'GNU GPL v3 or later' },
  { id: 'LGPL-2.1-or-later', label: 'GNU LGPL v2.1 or later' },
  { id: 'BSD-3-Clause', label: 'BSD 3-Clause' },
  { id: 'BSD-2-Clause', label: 'BSD 2-Clause' },
  { id: 'MPL-2.0', label: 'Mozilla Public License 2.0' },
  { id: 'ISC', label: 'ISC' },
];

/**
 * Why a license can't go into the spec's License: tag, or null. Any text on
 * one line works for rpmbuild (an SPDX expression is the convention, e.g.
 * "MIT AND BSD-3-Clause" or "LicenseRef-Acme-Proprietary"), but % would be
 * expanded as a macro and # starts a comment.
 */
function licenseProblem(s) {
  const t = (s || '').trim();
  if (!t) return 'The license is empty: pick one or enter your own.';
  if (/[%#\r\n]/.test(t)) return `The license "${t}" can't contain %, # or line breaks (rpmbuild reads % as a macro and # as a comment).`;
  if (t.length > 200) return 'The license is longer than 200 characters.';
  return null;
}

module.exports = { specText, makefileText, changelogDate, LICENSES, licenseProblem };
