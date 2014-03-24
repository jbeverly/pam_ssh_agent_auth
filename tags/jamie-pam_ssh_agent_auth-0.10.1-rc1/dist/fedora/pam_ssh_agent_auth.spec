Summary: PAM module providing authentication via ssh-agent
Name: pam_ssh_agent_auth
Version: 0.10.1
Release: 1%{?dist}
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

Release 0.10.1 is stable, and has been tested on FreeBSD, Solaris 10, Solaris 11,
RHEL5, RHEL6, Debian Wheezy, Ubuntu 12.04 (LTS), Ubuntu 13.10,
and MacOS X 10.7.

This module can be used to provide authentication for anything run locally that
supports PAM. It was written specifically with the intention of permitting
authentication for sudo without password entry, and also has been proven useful
for use with su as an alternative to wheel.

It serves as middle ground between the two most common, and suboptimal
alternatives for large-scale system administration: allowing rootlogin via ssh,
or using NOPASSWD in sudoers. This module allows for ssh public-key
authentication, and it does this by leveraging an authentication mechanism you
are probably already using, ssh-agent.

There are caveats of course, ssh-agent forwarding has it’s own security risks
which must be carefully considered for your environment. In cases where there
are not untrustworthy intermediate servers, and you wish to retain traceability,
accountability, and required authentication for privileged command invocation,
the benefits should outweigh the risks. Release 0.10.1 can be downloaded from
SourceForge: https://sourceforge.net/project/showfiles.php?group_id=249556

If you encounter any issues with usability or security, please use the project's
SourceForge tracker:
https://sourceforge.net/tracker2/?group_id=249556&atid=1126337

Note that if you wish to use this for sudo, you will need a version of sudo that
preserves the env_keep environment during authentication; and ideally a version
incorporating my minor patch which ensures RUSER is set during PAM authentication.

sudo 1.6.8p12 does not work correctly with this PAM module, because it clears the
environment (even env_keep variables) prior to attempting PAM authentication.

sudo 1.7.2p1 or later is preferred, as it correctly sets PAM_RUSER for
authentication.

%clean
[ "%{buildroot}" != "/" ] && %{__rm} -rf %{buildroot}

%prep
%setup 

%build
%define _libexecdir /%{_lib}/security
%configure --with-selinux --enable-sudo-hack
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
* Thu Jan 9 2014 Jamie Beverly <soupboy@sourceforge.net> - 0.10.1
- Added support for authorized_keys_command and authorized_keys_command_user
* Sun 22 Sep 2013 Jamie Beverly <soupboy@sourceforge.net> - 0.9.6
- Fixed moderate security issue where the random cookie would rarely
  be generated with zero length, creating an easily replayable authentication.
- Added metadata embedded in the information sent to ssh-agent, allowing agents
  to present the user with more information about the authentication request,
  so their decision to authorize the request can be an informed one.
* Thu Feb 21 2013 Jamie Beverly <soupboy@sourceforge.net> - 0.9.5
- portability fixes
* Wed Jun 26 2012 Jamie Beverly <soupboy@sourceforge.net> - 0.9.4
- Prefixed symbol names to avoid collision with globally dl_open'd symbols names
- updated Makefile.in as per http://sourceforge.net/tracker/?func=detail&aid=3510464&group_id=249556&atid=1126337
- updated documentation for pam configuration
* Wed Jan 26 2011 Jamie Beverly <jamie.r.beverly@gmail.com> - 0.9.3
- Minor bug fixes
- Moved logging of signature and key file from debug to normal output
* Wed Jan 06 2010 Jamie Beverly <jamie.r.beverly@gmail.com> - 0.9.2
- First packaged release.
