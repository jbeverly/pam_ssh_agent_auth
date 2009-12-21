# New ports collection makefile for: pam_ssh_agent_auth
# Date created:        18 January 2009
# Whom:                Jamie BEverly
#
# $FreeBSD$
#

PORTNAME       = pam_ssh_agent_auth
PORTVERSION    = 0.9
CATEGORIES     = security
MASTER_SITES   = http://downloads.sourceforge.net/pamsshagentauth/pam_ssh_agent_auth-0.9.tar.bz2
EXTRACT_SUFX   = .tar.bz2
WRKSRC         = ${WRKDIR}/$(PORTNAME)

MAINTAINER     = soupboy@sourceforge.net
COMMENT        = A PAM module implementing authentication via ssh-agent

MAN8           = pam_ssh_agent_auth.8
MANCOMPRESSED  = no

GNU_CONFIGURE  = yes
USE_GMAKE      = yes
PREFIX         = /
MANPREFIX      = /usr/share
CONFIGURE_ARGS = --libexecdir=/usr/lib --with-mantype=man

.include <bsd.port.mk>
