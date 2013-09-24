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
#include "config.h"

#include "openbsd-compat/sys-queue.h"
#include "xmalloc.h"
#include "log.h"
#include "buffer.h"
#include "key.h"
#include "authfd.h"
#include <stdio.h>
#include <openssl/evp.h>
#include "ssh2.h"
#include "misc.h"

#include "userauth_pubkey_from_id.h"
#include "identity.h"
extern char **environ;

void
pamsshagentauth_session_id2_gen(Buffer * session_id2, const char * user, const char * ruser, const char * servicename)
{
    char *cookie = NULL;
    uint8_t i = 0;
    uint32_t rnd = 0;
    uint8_t cookie_len;
    char * action = NULL;
    char empty[1] = "";
    char hostname[256] = { 0 };
    char pwd[1024] = { 0 };
    time_t ts;

    rnd = pamsshagentauth_arc4random();
    cookie_len = ((uint8_t) rnd) + 16;                                          /* Add 16 bytes to the size to ensure that while the length is random, the length is always reasonable; ticket #18 */

    cookie = calloc(1,cookie_len);

    for (i = 0; i < cookie_len; i++) {
        if (i % 4 == 0) {
            rnd = pamsshagentauth_arc4random();
        }
        cookie[i] = (char) rnd;
        rnd >>= 8;
    }

    /* This obviously only works with sudo; I'd like to find a better alternative */
    action = getenv("SUDO_COMMAND");
    if(!action) {
        action = getenv("PAM_AUTHORIZED_ACTION");
        if(!action) {
            action = empty;
        }
    }

    gethostname(hostname, sizeof(hostname) - 1);
    getcwd(pwd, sizeof(pwd) - 1);
    time(&ts);

    pamsshagentauth_buffer_init(session_id2);

    pamsshagentauth_buffer_put_int(session_id2, PAM_SSH_AGENT_AUTH_REQUESTv1);
    pamsshagentauth_debug("cookie: %s", pamsshagentauth_tohex(cookie, cookie_len));
    pamsshagentauth_buffer_put_string(session_id2, cookie, cookie_len);
    pamsshagentauth_debug("user: %s", user);
    pamsshagentauth_buffer_put_cstring(session_id2, user);
    pamsshagentauth_debug("ruser: %s", ruser);
    pamsshagentauth_buffer_put_cstring(session_id2, ruser);
    pamsshagentauth_debug("servicename: %s", servicename);
    pamsshagentauth_buffer_put_cstring(session_id2, servicename);
    pamsshagentauth_debug("pwd: %s", pwd);
    pamsshagentauth_buffer_put_cstring(session_id2, pwd);
    pamsshagentauth_debug("action: %s", action);
    pamsshagentauth_buffer_put_cstring(session_id2, action);
    pamsshagentauth_debug("hostname: %s", hostname);
    pamsshagentauth_buffer_put_cstring(session_id2, hostname);
    pamsshagentauth_debug("ts: %ld", ts);
    pamsshagentauth_buffer_put_int64(session_id2, (uint64_t) ts);

    free(cookie);
    return;
}

int
pamsshagentauth_find_authorized_keys(const char * user, const char * ruser, const char * servicename)
{
    Buffer session_id2 = { 0 };
    Identity *id;
    Key *key;
    AuthenticationConnection *ac;
    char *comment;
    uint8_t retval = 0;
    uid_t uid = getpwnam(ruser)->pw_uid;

    OpenSSL_add_all_digests();
    pamsshagentauth_session_id2_gen(&session_id2, user, ruser, servicename);

    pamsshagentauth_verbose("command execution: %s (%u)", ruser, uid);

    if ((ac = ssh_get_authentication_connection(uid))) {
        pamsshagentauth_verbose("Contacted ssh-agent of user %s (%u)", ruser, uid);
        for (key = ssh_get_first_identity(ac, &comment, 2); key != NULL; key = ssh_get_next_identity(ac, &comment, 2)) 
        {
            if(key != NULL) {
                id = pamsshagentauth_xcalloc(1, sizeof(*id));
                id->key = key;
                id->filename = comment;
                id->ac = ac;
                if(userauth_pubkey_from_id(ruser, id, &session_id2)) {
                    retval = 1;
                }
                pamsshagentauth_buffer_free(&session_id2);
                pamsshagentauth_xfree(id->filename);
                pamsshagentauth_key_free(id->key);
                pamsshagentauth_xfree(id);
                if(retval == 1)
                    break;
            }
        }
        ssh_close_authentication_connection(ac);
    }
    else {
        pamsshagentauth_verbose("No ssh-agent could be contacted");
    }
    /* pamsshagentauth_xfree(session_id2); */
    EVP_cleanup();
    return retval;
}
