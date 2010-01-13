Summary: PAM module providing authentication via ssh-agent
Name: pam_ssh_agent_auth
Version: 0.9.2
Release: 0.rh4
License: BSD
Group: System Environment Base
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-%(id -un)-root
Source0: http://downloads.sourceforge.net/pamsshagentauth/%{name}-%{version}.tar.bz2
Requires: openssl >= 0.9.8, pam, openssh-server, openssh
BuildRequires: openssl-devel >= 0.9.8, pam-devel, perl, sed
Vendor: Jamie Beverly
Packager: Jamie Beverly

%description
pam_ssh_agent_auth is a PAM module which permits PAM authentication via your
keyring in a forwarded ssh-agent.

This module can be used to provide authentication for anything run locally that
supports PAM. It was written specifically with the intention of permitting
authentication for sudo without password entry, and also has been proven useful
for use with su as an alternative to wheel. 

%clean
[ "%{buildroot}" != "/" ] && %{__rm} -rf %{buildroot}

%prep
%setup 

%build
%define _libexecdir /%{_lib}/security
%configure --with-selinux --with-sudo-hack
%{__make} %{?_smp_mflags}

%install
[ "%{buildroot}" != "/" ] && %{__rm} -rf %{buildroot}
%makeinstall

%files
%attr(0755, root, root) %{_libexecdir}/pam_ssh_agent_auth.so
%defattr(-, root, root, 0644)
%doc LICENSE.OpenSSL OPENSSH_LICENSE
%doc %{_mandir}/man8/pam_ssh_agent_auth.8*

%changelog
* Wed Jan 06 2010 Jamie Beverly <jamie.r.beverly@gmail.com> - 0.9.2
- First packaged release.

