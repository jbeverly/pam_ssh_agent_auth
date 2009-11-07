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
uid_t           authorized_keys_file_allowed_owner_uid;

void
parse_authorized_key_file(const char *user, const char *authorized_keys_file_input)
{
    char            fqdn[HOST_NAME_MAX] = "";
    char            hostname[HOST_NAME_MAX] = "";
    char            auth_keys_file_buf[4096] = "";
    char           *slash_ptr = NULL;
    char            owner_uname[128] = "";
    size_t          owner_uname_len = 0;

    /*
     * temporary copy, so that both tilde expansion and percent expansion both get to apply to the path
     */
    strncat(auth_keys_file_buf, authorized_keys_file_input, 4096);

    if(allow_user_owned_authorized_keys_file)
        authorized_keys_file_allowed_owner_uid = getpwnam(user)->pw_uid;

    if(*auth_keys_file_buf == '~') {
        if(*(auth_keys_file_buf+1) == '/') {
            authorized_keys_file_allowed_owner_uid = getpwnam(user)->pw_uid;
        }
        else {
            slash_ptr = strchr(auth_keys_file_buf,'/');
            if(!slash_ptr)
                fatal("cannot expand tilde in path without a `/'");

            owner_uname_len = slash_ptr - auth_keys_file_buf - 1;
            if(owner_uname_len > 127) 
                fatal("Username too long");

            strncat(owner_uname, auth_keys_file_buf + 1, owner_uname_len);
            if(!authorized_keys_file_allowed_owner_uid)
                authorized_keys_file_allowed_owner_uid = getpwnam(owner_uname)->pw_uid;
        }
        authorized_keys_file = tilde_expand_filename(auth_keys_file_buf, authorized_keys_file_allowed_owner_uid);
        strncpy(auth_keys_file_buf, authorized_keys_file, 4096);
        xfree(authorized_keys_file) /* when we percent_expand later, we'd step on this, so free it immediately */;
    }

    if(strstr(auth_keys_file_buf, "%h")) {
        authorized_keys_file_allowed_owner_uid = getpwnam(user)->pw_uid;
    }

#if HAVE_GETHOSTNAME
    *hostname = '\0';
    gethostname(fqdn, HOST_NAME_MAX);
    strncat(hostname, fqdn, strcspn(fqdn,"."));
#endif
    authorized_keys_file = percent_expand(auth_keys_file_buf, "h", getpwnam(user)->pw_dir, "H", hostname, "f", fqdn, "u", user, NULL);
}

int
pam_user_key_allowed(Key * key)
{
    return pam_user_key_allowed2(getpwuid(authorized_keys_file_allowed_owner_uid), key, authorized_keys_file)
        || pam_user_key_allowed2(getpwuid(0), key, authorized_keys_file);
}
