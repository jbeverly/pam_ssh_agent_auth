/* 
 * Copyright (c) 2008, Jamie Beverly. 
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without modification, are
 * permitted provided that the following conditions are met:
 * 
 *    1. Redistributions of source code must retain the above copyright notice, this list of
 *       conditions and the following disclaimer.
 * 
 *    2. Redistributions in binary form must reproduce the above copyright notice, this list
 *       of conditions and the following disclaimer in the documentation and/or other materials
 *       provided with the distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY Jamie Beverly ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
 * FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL Jamie Beverly OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 * ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 * 
 * The views and conclusions contained in the software and documentation are those of the
 * authors and should not be interpreted as representing official policies, either expressed
 * or implied, of Jamie Beverly.
 */


#include "includes.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>

#ifndef HOST_NAME_MAX
#ifdef MAXHOSTNAMELEN
#define HOST_NAME_MAX MAXHOSTNAMELEN
#endif
#endif

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

extern char *authorized_keys_file;

extern char *authorized_keys_command;

extern char *authorized_keys_command_user;

extern uint8_t allow_user_owned_authorized_keys_file;

uid_t authorized_keys_file_allowed_owner_uid;

/* Returns 0 on success, -1 if the path cannot be resolved; authorized_keys_file is then unset. */
int
parse_authorized_key_file(const char *user,
                          const char *authorized_keys_file_input)
{
    char fqdn[HOST_NAME_MAX] = "";
    char hostname[HOST_NAME_MAX] = "";
    char auth_keys_file_buf[4096] = "";
    char *slash_ptr = NULL;
    char owner_uname[128] = "";
    size_t owner_uname_len = 0;
    struct passwd *user_pw, *owner_pw;
    uid_t user_uid;
    char *user_dir;

    authorized_keys_file = NULL;

    if((user_pw = getpwnam(user)) == NULL) {
        pamsshagentauth_logerror("parse_authorized_key_file: unknown user %s", user);
        return -1;
    }
    /* Copy now: the getpwnam below for ~owner/ overwrites the static result. */
    user_uid = user_pw->pw_uid;
    user_dir = pamsshagentauth_xstrdup(user_pw->pw_dir);

    /*
     * temporary copy, so that both tilde expansion and percent expansion both
     * get to apply to the path
     */
    strncat(auth_keys_file_buf, authorized_keys_file_input,
            sizeof(auth_keys_file_buf) - 1);

    if(allow_user_owned_authorized_keys_file)
        authorized_keys_file_allowed_owner_uid = user_uid;

    if(*auth_keys_file_buf == '~') {
        if(*(auth_keys_file_buf + 1) == '/') {
            authorized_keys_file_allowed_owner_uid = user_uid;
        } else {
            slash_ptr = strchr(auth_keys_file_buf, '/');
            if(!slash_ptr) {
                pamsshagentauth_logerror("cannot expand tilde in path without a `/'");
                pamsshagentauth_xfree(user_dir);
                return -1;
            }

            owner_uname_len = slash_ptr - auth_keys_file_buf - 1;
            if(owner_uname_len > (sizeof(owner_uname) - 1)) {
                pamsshagentauth_logerror("Username too long");
                pamsshagentauth_xfree(user_dir);
                return -1;
            }

            strncat(owner_uname, auth_keys_file_buf + 1, owner_uname_len);
            if(!authorized_keys_file_allowed_owner_uid) {
                if((owner_pw = getpwnam(owner_uname)) == NULL) {
                    pamsshagentauth_logerror("parse_authorized_key_file: unknown user %s", owner_uname);
                    pamsshagentauth_xfree(user_dir);
                    return -1;
                }
                authorized_keys_file_allowed_owner_uid = owner_pw->pw_uid;
            }
        }
        authorized_keys_file =
            pamsshagentauth_tilde_expand_filename(auth_keys_file_buf,
                                                  authorized_keys_file_allowed_owner_uid);
        strncpy(auth_keys_file_buf, authorized_keys_file,
                sizeof(auth_keys_file_buf) - 1);
        pamsshagentauth_xfree(authorized_keys_file)        /* when we
                                                              percent_expand
                                                              later, we'd step
                                                              on this, so free
                                                              it immediately */ ;
    }

    if(strstr(auth_keys_file_buf, "%h")) {
        authorized_keys_file_allowed_owner_uid = user_uid;
    }
#if HAVE_GETHOSTNAME
    *hostname = '\0';
    gethostname(fqdn, HOST_NAME_MAX);
    strncat(hostname, fqdn, strcspn(fqdn, "."));
#endif
    authorized_keys_file =
        pamsshagentauth_percent_expand(auth_keys_file_buf, "h",
                                       user_dir, "H", hostname,
                                       "f", fqdn, "u", user, NULL);
    pamsshagentauth_xfree(user_dir);
    return 0;
}

int
pam_user_key_allowed(const char *ruser, Key * key)
{
    struct passwd *pw;

    if(authorized_keys_file != NULL) {
        if((pw = getpwuid(authorized_keys_file_allowed_owner_uid)) != NULL
           && pamsshagentauth_user_key_allowed2(pw, key, authorized_keys_file))
            return 1;
        if((pw = getpwuid(0)) != NULL
           && pamsshagentauth_user_key_allowed2(pw, key, authorized_keys_file))
            return 1;
    }
    if((pw = getpwnam(ruser)) != NULL
       && pamsshagentauth_user_key_command_allowed2(authorized_keys_command,
                                                    authorized_keys_command_user,
                                                    pw, key))
        return 1;
    return 0;
}
