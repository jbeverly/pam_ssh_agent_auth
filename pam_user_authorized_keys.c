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
#include "pam_user_authorized_keys.h"

#define MAX_AUTHORIZED_KEY_FILES 16

char *authorized_keys_files[MAX_AUTHORIZED_KEY_FILES];
unsigned int nr_authorized_keys_files = 0;

extern char *authorized_keys_command;

extern char *authorized_keys_command_user;

extern uint8_t allow_user_owned_authorized_keys_file;

uid_t authorized_keys_file_allowed_owner_uid;

void
parse_authorized_key_files(const char *user,
                           const char *authorized_keys_file_input)
{
    const char *pos = authorized_keys_file_input;
    char hostname[HOST_NAME_MAX] = "";
    char fqdn[HOST_NAME_MAX] = "";

#if HAVE_GETHOSTNAME
    *hostname = '\0';
    gethostname(fqdn, HOST_NAME_MAX);
    strncat(hostname, fqdn, strcspn(fqdn,"."));
#endif

    while (pos) {
        const char *colon = strchr(pos, ':');
        char auth_keys_file_buf[4096] = "";
        char *slash_ptr = NULL;
        char owner_uname[128] = "";
        size_t owner_uname_len = 0;

        strncat(auth_keys_file_buf, pos, sizeof(auth_keys_file_buf) - 1);
        if (colon) {
            auth_keys_file_buf[colon - pos] = 0;
            pos = colon + 1;
        } else {
            pos = 0;
        }

        if(allow_user_owned_authorized_keys_file)
            authorized_keys_file_allowed_owner_uid = getpwnam(user)->pw_uid;

        if(*auth_keys_file_buf == '~') {
            if(*(auth_keys_file_buf+1) == '/') {
                authorized_keys_file_allowed_owner_uid = getpwnam(user)->pw_uid;
            }
            else {
                slash_ptr = strchr(auth_keys_file_buf,'/');
                if(!slash_ptr)
                    pamsshagentauth_fatal("cannot expand tilde in path without a `/'");

                owner_uname_len = slash_ptr - auth_keys_file_buf - 1;
                if(owner_uname_len > (sizeof(owner_uname) - 1) )
                    pamsshagentauth_fatal("Username too long");

                strncat(owner_uname, auth_keys_file_buf + 1, owner_uname_len);
                if(!authorized_keys_file_allowed_owner_uid)
                    authorized_keys_file_allowed_owner_uid = getpwnam(owner_uname)->pw_uid;
            }
            char *tmp = pamsshagentauth_tilde_expand_filename(auth_keys_file_buf, authorized_keys_file_allowed_owner_uid);
            strncpy(auth_keys_file_buf, tmp, sizeof(auth_keys_file_buf) - 1 );
            pamsshagentauth_xfree(tmp);
        }

        if(strstr(auth_keys_file_buf, "%h")) {
            authorized_keys_file_allowed_owner_uid = getpwnam(user)->pw_uid;
        }

        if (nr_authorized_keys_files >= MAX_AUTHORIZED_KEY_FILES)
            pamsshagentauth_fatal("Too many authorized key files");
        authorized_keys_files[nr_authorized_keys_files++] =
            pamsshagentauth_percent_expand(auth_keys_file_buf, "h", getpwnam(user)->pw_dir, "H", hostname, "f", fqdn, "u", user, NULL);
    }
}

void
free_authorized_key_files()
{
    unsigned int n;
    for (n = 0; n < nr_authorized_keys_files; n++)
        free(authorized_keys_files[n]);
    nr_authorized_keys_files = 0;
}

const char *
pam_user_key_allowed(const char *ruser, Key * key)
{
    unsigned int n;
    for (n = 0; n < nr_authorized_keys_files; n++) {
        if (pamsshagentauth_user_key_allowed2(getpwuid(authorized_keys_file_allowed_owner_uid), key, authorized_keys_files[n])
            || pamsshagentauth_user_key_allowed2(getpwuid(0), key, authorized_keys_files[n])
            || pamsshagentauth_user_key_command_allowed2(authorized_keys_command, authorized_keys_command_user, getpwnam(ruser), key))
            return authorized_keys_files[n];
    }
    return 0;
}
