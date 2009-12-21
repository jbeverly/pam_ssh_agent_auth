Summary: PAM module providing authentication via ssh-agent
Name: pam_ssh_agent_auth
Version: 0.9
Release: 0
License: BSD
Group: System Environment Base
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-%(id -un)-root
Source0: http://downloads.sourceforge.net/pamsshagentauth/pam_ssh_agent_auth-0.9.tar.bz2
Requires: openssl >= 0.9.8, pam, openssh-server, openssh
BuildRequires: openssl-devel >= 0.9.8, pam-devel, perl, sed
Vendor: Jamie Beverly
Packager: Jamie Beverly

%description
This is a pam module which permits authentication via ssh-agent. To use this, you must forward your ssh-agent socket via ssh, or run an ssh-agent locally. An ssh-agent socket, owned by you, must be listening to the socket defined in $SSH_AUTH_SOCK. For sudo, the $SSH_AUTH_SOCK variable must be in "Defaults env_keep".


%clean
[ "%{buildroot}" != "/" ] && rm -rf %{buildroot}

%prep
%setup -n pam_ssh_agent_auth

%build
%define _libexecdir /lib/security
%configure --with-selinux

%install
[ "%{buildroot}" != "/" ] && rm -rf %{buildroot}
%makeinstall
gzip %{buildroot}%{_mandir}/man8/pam_ssh_agent_auth.8

%files
%attr(0755, root, root) /lib/security/pam_ssh_agent_auth.so
%attr(0644, root, root) %{_mandir}/man8/pam_ssh_agent_auth.8.gz

