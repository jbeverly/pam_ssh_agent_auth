/* 
 * Copyright, 2008  Jamie Beverly
 * pam_ssh_agent_auth PAM module
 * 
 * This program is free software; you can redistribute it and/or modify 
 * it under the terms of the GNU General Public License as published by 
 * the Free Software Foundation; either version 3 of the License, or 
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful, but 
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY 
 * or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License 
 * for more details.
 * 
 * You should have received a copy of the GNU General Public License along 
 * with this program; if not, write to the Free Software Foundation, Inc., 
 * 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 *
 *
 * In addition, as a special exception, the copyright holders give
 * permission to link the code of portions of this program with the
 * OpenSSL library under certain conditions as described in each
 * individual source file, and distribute linked combinations
 * including the two.
 * You must obey the GNU General Public License in all respects
 * for all of the code used other than OpenSSL.  If you modify
 * file(s) with this exception, you may extend this exception to your
 * version of the file(s), but you are not obligated to do so.  If you
 * do not wish to do so, delete this exception statement from your
 * version.  If you delete this exception statement from all source
 * files in the program, then also delete it here.
 */

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
#ifdef HAVE_UNISTD_H
#include <unistd.h>
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

#include "xmalloc.h"
#include "ssh.h"
#include "ssh2.h"
#include "compat.h"
#include "pathnames.h"
#include "secure_filename.h"

#include "identity.h"
#include "pam_user_key_allowed2.h"

extern char    *authorized_keys_file;
extern uint8_t  allow_user_owned_authorized_keys_file;

static          size_t
xstrnlen(const char *s, size_t maxlen)
{
#if HAVE_STRNLEN
    return strnlen(s, maxlen);
#else
    return strlen(s);
#endif
}

static void
expand_path_percent_notations(const char *abrev, const char *replacement)
{
    char           *index_ptr = NULL;
    char           *authorized_keys_file_buf = NULL;

    size_t          replacement_len;
    size_t          authorized_keys_file_len;
    size_t          abrev_len;

    index_ptr = strstr(authorized_keys_file, abrev);

    if(index_ptr) {
        replacement_len = xstrnlen(replacement, MAXPATHLEN);
        authorized_keys_file_len = xstrnlen(authorized_keys_file, MAXPATHLEN);
        abrev_len = xstrnlen(abrev, MAXPATHLEN);

        do {
            *index_ptr = '\0';
            authorized_keys_file_len += replacement_len;
            replacement_len += replacement_len;

            authorized_keys_file_buf = calloc(1, authorized_keys_file_len + 1);
            snprintf(authorized_keys_file_buf, MAXPATHLEN, "%s%s%s", authorized_keys_file, replacement, index_ptr + abrev_len);
            free(authorized_keys_file);

            authorized_keys_file = calloc(1, authorized_keys_file_len + 1);
            memcpy(authorized_keys_file, authorized_keys_file_buf, authorized_keys_file_len);
            free(authorized_keys_file_buf);

        } while((index_ptr = strstr(authorized_keys_file, abrev)));

    }
}

void
authorized_key_file_translate(const char *user, const char *authorized_keys_file_input)
{
    size_t          authorized_keys_file_input_len = 0;
    struct passwd  *pw = getpwnam(user);
    char            hostname[HOST_NAME_MAX] = "no_gethostname_function_on_this_platform";

    /* 
     * Just use the provided tilde_expand_filename function for ~
     */
    if(*authorized_keys_file_input == '~') {
        allow_user_owned_authorized_keys_file = 1;
        authorized_keys_file = tilde_expand_filename(authorized_keys_file_input, pw->pw_uid);
    }

    if(strstr(authorized_keys_file_input, "%h"))
        allow_user_owned_authorized_keys_file = 1;


    authorized_keys_file_input_len = xstrnlen(authorized_keys_file_input, MAXPATHLEN);
    authorized_keys_file = calloc(1, authorized_keys_file_input_len + 1);

    strncpy(authorized_keys_file, authorized_keys_file_input, authorized_keys_file_input_len);

    expand_path_percent_notations("%h", pw->pw_dir);
    expand_path_percent_notations("%u", user);
#if HAVE_GETHOSTNAME
    gethostname(hostname, HOST_NAME_MAX);
#endif
    expand_path_percent_notations("%H", hostname);
}

int
pam_user_key_allowed(Key * key, uid_t uid)
{
    if(allow_user_owned_authorized_keys_file) {
        verbose("Allowing user-owned authorized_keys file");
        return pam_user_key_allowed2(getpwuid(uid), key, authorized_keys_file)
            || pam_user_key_allowed2(getpwuid(0), key, authorized_keys_file);
    }

    return pam_user_key_allowed2(getpwuid(0), key, authorized_keys_file);
}
