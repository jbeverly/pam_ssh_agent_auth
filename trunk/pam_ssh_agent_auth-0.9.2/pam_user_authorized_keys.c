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
