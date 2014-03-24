/*
 * Copyright (c) 2000 Markus Friedl.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/* Taken from auth.c to avoid the unnecessary (for this project) requirements of auth.c */

#include "includes.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>

#include <netinet/in.h>

#include <errno.h>
#ifdef HAVE_PATHS_H
# include <paths.h>
#endif
#include <pwd.h>
#ifdef HAVE_LOGIN_H
#include <login.h>
#endif
#ifdef USE_SHADOW
#include <shadow.h>
#endif
#ifdef HAVE_LIBGEN_H
#include <libgen.h>
#endif
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "xmalloc.h"
#include "match.h"
#include "log.h"
#include "buffer.h"
#include "key.h"
#include "misc.h"


/*
 * Check a given file for security. This is defined as all components
 * of the path to the file must be owned by either the owner of
 * of the file or root and no directories must be group or world writable.
 *
 * XXX Should any specific check be done for sym links ?
 *
 * Takes an open file descriptor, the file name, a uid and and
 * error buffer plus max size as arguments.
 *
 * Returns 0 on success and -1 on failure
 */

int
pamsshagentauth_auth_secure_path(const char *name, struct stat *stp,
        const char *pw_dir, uid_t uid, char *err, size_t errlen)
{
	char buf[MAXPATHLEN], homedir[MAXPATHLEN];
	char *cp;
	int comparehome = 0;
	struct stat st;

    pamsshagentauth_verbose("auth_secure_filename: checking for uid: %u", uid);

	if (realpath(name, buf) == NULL) {
		snprintf(err, errlen, "realpath %s failed: %s", name,
		    strerror(errno));
		return -1;
	}
	/* if (realpath(pw->pw_dir, homedir) != NULL) */
    if (pw_dir != NULL && realpath(pw_dir, homedir) != NULL)
		comparehome = 1;

	/* check the open file to avoid races */
	/* 
     * if (fstat(fileno(f), &st) < 0 ||
	 *    (st.st_uid != 0 && st.st_uid != uid) ||
	 *    (st.st_mode & 022) != 0) {
    */
    if (!S_ISREG(stp->st_mode)) {
        snprintf(err, errlen, "%s is not a regular file", buf);
        return -1;
    }

    if ((stp->st_uid != 0 && stp->st_uid != uid) ||
            (stp->st_mode & 022) != 0) {
		snprintf(err, errlen, "bad ownership or modes for file %s",
		    buf);
		return -1;
	}

	/* for each component of the canonical path, walking upwards */
	for (;;) {
		if ((cp = dirname(buf)) == NULL) {
			snprintf(err, errlen, "dirname() failed");
			return -1;
		}
		pamsshagentauth_strlcpy(buf, cp, sizeof(buf));

		pamsshagentauth_verbose("secure_filename: checking '%s'", buf);
		if (stat(buf, &st) < 0 ||
		    (st.st_uid != 0 && st.st_uid != uid) ||
		    (st.st_mode & 022) != 0) {
			snprintf(err, errlen,
			    "bad ownership or modes for directory %s", buf);
			return -1;
		}

		/* If are passed the homedir then we can stop */
		if (comparehome && strcmp(homedir, buf) == 0) {
			pamsshagentauth_verbose("secure_filename: terminating check at '%s'",
			    buf);
			break;
		}
		/*
		 * dirname should always complete with a "/" path,
		 * but we can be paranoid and check for "." too
		 */
		if ((strcmp("/", buf) == 0) || (strcmp(".", buf) == 0))
			break;
	}
	return 0;
}

/*
 * Version of secure_path() that accepts an open file descriptor to
 * avoid races.
 *
 * Returns 0 on success and -1 on failure
 */
int
pamsshagentauth_secure_filename(FILE *f, const char *file, struct passwd *pw,
    char *err, size_t errlen)
{
   struct stat st;
   char buf[MAXPATHLEN] = { 0 };

   /* check the open file to avoid races */
   if (fstat(fileno(f), &st) < 0) {
       snprintf(err, errlen, "cannot stat file %s: %s",
           buf, strerror(errno));
       return -1;
   }
   return pamsshagentauth_auth_secure_path(file, &st, pw->pw_dir, pw->pw_uid, err, errlen);
}

