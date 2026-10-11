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
function specText({ name, version = '1.0.0', summary = '', ports = [], packager = 'Your Name <you@example.com>', date = new Date(), license = 'MIT' }) {
  const desc = summary || `SELinux policy for the ${name} service`;
  const semanage = ports.length > 0;
  const portAdd = ports.map(p => `semanage port -a -t ${p.type} -p ${p.proto} ${p.port} 2>/dev/null || semanage port -m -t ${p.type} -p ${p.proto} ${p.port} || :`).join('\n');
  const portDel = ports.map(p => `    semanage port -d -t ${p.type} -p ${p.proto} ${p.port} 2>/dev/null || :`).join('\n');
  return `# SELinux policy module for ${name}, packaged on its own so the service's
# package can require it (Requires: ${name}-selinux).
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
BuildArch:      noarch

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

%pre
%selinux_relabel_pre -s %{selinuxtype}

%post
%selinux_modules_install -s %{selinuxtype} %{_datadir}/selinux/packages/%{selinuxtype}/%{modulename}.pp.bz2
${semanage ? `# Port numbers for the module's port types.\n${portAdd}\n` : ''}
%postun
if [ $1 -eq 0 ]; then
${semanage ? `${portDel}\n` : ''}    %selinux_modules_uninstall -s %{selinuxtype} %{modulename}
fi

%posttrans
%selinux_relabel_post -s %{selinuxtype}

%files
%{_datadir}/selinux/packages/%{selinuxtype}/%{modulename}.pp.bz2
%{_datadir}/selinux/devel/include/distributed/%{modulename}.if
%ghost %verify(not md5 size mode mtime) %{_sharedstatedir}/selinux/%{selinuxtype}/active/modules/200/%{modulename}

%changelog
* ${changelogDate(date)} ${packager} - ${version}-1
- Initial package
`;
}

/** A Makefile for the module's folder: `make` builds the .pp, `make rpm` the RPM (under ./rpmbuild). */
function makefileText(name) {
  return `# Builds the ${name} policy module against this host's selinux-policy-devel,
# and its RPM (${name}-selinux). Written by SELinux Policy Tools.
NAME := ${name}
DEVEL_MAKEFILE ?= /usr/share/selinux/devel/Makefile

all: $(NAME).pp

$(NAME).pp: $(NAME).te $(NAME).if $(NAME).fc
\t$(MAKE) -f $(DEVEL_MAKEFILE) $@

rpm: $(NAME).te $(NAME).if $(NAME).fc $(NAME)-selinux.spec
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
