/* $OpenBSD: uidswap.c,v 1.35 2006/08/03 03:34:42 deraadt Exp $ */
/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 * Code for uid-swapping.
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 */

#include "includes.h"

#include <sys/param.h>
#include <errno.h>
#include <pwd.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>

#include <grp.h>

#include "log.h"
#include "uidswap.h"
#include "xmalloc.h"

/*
 * Note: all these functions must work in all of the following cases:
 *    1. euid=0, ruid=0
 *    2. euid=0, ruid!=0
 *    3. euid!=0, ruid!=0
 * Additionally, they must work regardless of whether the system has
 * POSIX saved uids or not.
 */

#if defined(_POSIX_SAVED_IDS) && !defined(BROKEN_SAVED_UIDS)
/* Lets assume that posix saved ids also work with seteuid, even though that
   is not part of the posix specification. */
#define SAVED_IDS_WORK_WITH_SETEUID
/* Saved effective uid. */
static uid_t 	saved_euid = 0;
static gid_t	saved_egid = 0;
#endif

/* Saved effective uid. */
static int	privileged = 0;
static int	temporarily_use_uid_effective = 0;
static gid_t	*saved_egroups = NULL, *user_groups = NULL;
static int	saved_egroupslen = -1, user_groupslen = -1;

/*
 * Temporarily changes to the given uid.  If the effective user
 * id is not root, this does nothing.  This call cannot be nested.
 */
void
pamsshagentauth_temporarily_use_uid(struct passwd *pw)
{
	/* Save the current euid, and egroups. */
#ifdef SAVED_IDS_WORK_WITH_SETEUID
	saved_euid = geteuid();
	saved_egid = getegid();
	pamsshagentauth_debug("temporarily_use_uid: %u/%u (e=%u/%u)",
	    (u_int)pw->pw_uid, (u_int)pw->pw_gid,
	    (u_int)saved_euid, (u_int)saved_egid);
#ifndef HAVE_CYGWIN
	if (saved_euid != 0) {
		privileged = 0;
		return;
	}
#endif
#else
	if (geteuid() != 0) {
		privileged = 0;
		return;
	}
#endif /* SAVED_IDS_WORK_WITH_SETEUID */

	privileged = 1;
	temporarily_use_uid_effective = 1;

	saved_egroupslen = getgroups(0, NULL);
	if (saved_egroupslen < 0)
		pamsshagentauth_fatal("getgroups: %.100s", strerror(errno));
	if (saved_egroupslen > 0) {
		saved_egroups = pamsshagentauth_xrealloc(saved_egroups,
		    saved_egroupslen, sizeof(gid_t));
		if (getgroups(saved_egroupslen, saved_egroups) < 0)
			pamsshagentauth_fatal("getgroups: %.100s", strerror(errno));
	} else { /* saved_egroupslen == 0 */
		if (saved_egroups != NULL)
			pamsshagentauth_xfree(saved_egroups);
	}

	/* set and save the user's groups */
	if (user_groupslen == -1) {
		if (initgroups(pw->pw_name, pw->pw_gid) < 0)
			pamsshagentauth_fatal("initgroups: %s: %.100s", pw->pw_name,
			    strerror(errno));

		user_groupslen = getgroups(0, NULL);
		if (user_groupslen < 0)
			pamsshagentauth_fatal("getgroups: %.100s", strerror(errno));
		if (user_groupslen > 0) {
			user_groups = pamsshagentauth_xrealloc(user_groups,
			    user_groupslen, sizeof(gid_t));
			if (getgroups(user_groupslen, user_groups) < 0)
				pamsshagentauth_fatal("getgroups: %.100s", strerror(errno));
		} else { /* user_groupslen == 0 */
			if (user_groups)
				pamsshagentauth_xfree(user_groups);
		}
	}
	/* Set the effective uid to the given (unprivileged) uid. */
	if (setgroups(user_groupslen, user_groups) < 0)
		pamsshagentauth_fatal("setgroups: %.100s", strerror(errno));
#ifndef SAVED_IDS_WORK_WITH_SETEUID
	/* Propagate the privileged gid to all of our gids. */
	if (setgid(getegid()) < 0)
		pamsshagentauth_debug("setgid %u: %.100s", (u_int) getegid(), strerror(errno));
	/* Propagate the privileged uid to all of our uids. */
	if (setuid(geteuid()) < 0)
		pamsshagentauth_debug("setuid %u: %.100s", (u_int) geteuid(), strerror(errno));
#endif /* SAVED_IDS_WORK_WITH_SETEUID */
	if (setegid(pw->pw_gid) < 0)
		pamsshagentauth_fatal("setegid %u: %.100s", (u_int)pw->pw_gid,
		    strerror(errno));
	if (seteuid(pw->pw_uid) == -1)
		pamsshagentauth_fatal("seteuid %u: %.100s", (u_int)pw->pw_uid,
		    strerror(errno));
}

/*
 * Restores to the original (privileged) uid.
 */
void
pamsshagentauth_restore_uid(void)
{
	/* it's a no-op unless privileged */
	if (!privileged) {
		pamsshagentauth_debug("restore_uid: (unprivileged)");
		return;
	}
	if (!temporarily_use_uid_effective)
		pamsshagentauth_fatal("restore_uid: temporarily_use_uid not effective");

#ifdef SAVED_IDS_WORK_WITH_SETEUID
	pamsshagentauth_debug("restore_uid: %u/%u", (u_int)saved_euid, (u_int)saved_egid);
	/* Set the effective uid back to the saved privileged uid. */
	if (seteuid(saved_euid) < 0)
		pamsshagentauth_fatal("seteuid %u: %.100s", (u_int)saved_euid, strerror(errno));
	if (setegid(saved_egid) < 0)
		pamsshagentauth_fatal("setegid %u: %.100s", (u_int)saved_egid, strerror(errno));
#else /* SAVED_IDS_WORK_WITH_SETEUID */
	/*
	 * We are unable to restore the real uid to its unprivileged value.
	 * Propagate the real uid (usually more privileged) to effective uid
	 * as well.
	 */
	setuid(getuid());
	setgid(getgid());
#endif /* SAVED_IDS_WORK_WITH_SETEUID */

	if (setgroups(saved_egroupslen, saved_egroups) < 0)
		pamsshagentauth_fatal("setgroups: %.100s", strerror(errno));
	temporarily_use_uid_effective = 0;
}


