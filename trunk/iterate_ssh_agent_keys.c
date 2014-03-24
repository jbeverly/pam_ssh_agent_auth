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


#include <string.h>

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
#include "get_command_line.h"
extern char **environ;

static char *
log_action(char ** action, size_t count)
{
    size_t i;
    char *buf = NULL;

    if (count == 0)
        return NULL;
   
    buf = pamsshagentauth_xcalloc((count * MAX_LEN_PER_CMDLINE_ARG) + (count * 3), sizeof(*buf));
    for (i = 0; i < count; i++) {
        strcat(buf, (i > 0) ? " '" : "'");
        strncat(buf, action[i], MAX_LEN_PER_CMDLINE_ARG);
        strcat(buf, "'");
    }
    return buf;
}

void
agent_action(Buffer *buf, char ** action, size_t count)
{
    size_t i;
    pamsshagentauth_buffer_init(buf);

    pamsshagentauth_buffer_put_int(buf, count);

    for (i = 0; i < count; i++) {
        pamsshagentauth_buffer_put_cstring(buf, action[i]);
    }
}


void
pamsshagentauth_session_id2_gen(Buffer * session_id2, const char * user,
                                const char * ruser, const char * servicename)
{
    char *cookie = NULL;
    uint8_t i = 0;
    uint32_t rnd = 0;
    uint8_t cookie_len;
    char hostname[256] = { 0 };
    char pwd[1024] = { 0 };
    time_t ts;
    char ** reported_argv = NULL;
    size_t count = 0;
    char * action_logbuf = NULL;
    Buffer action_agentbuf;
    uint8_t free_logbuf = 0;

    rnd = pamsshagentauth_arc4random();
    cookie_len = ((uint8_t) rnd);
    while (cookie_len < 16) { 
        cookie_len += 16;                                          /* Add 16 bytes to the size to ensure that while the length is random, the length is always reasonable; ticket #18 */
    }

    cookie = pamsshagentauth_xcalloc(1,cookie_len);

    for (i = 0; i < cookie_len; i++) {
        if (i % 4 == 0) {
            rnd = pamsshagentauth_arc4random();
        }
        cookie[i] = (char) rnd;
        rnd >>= 8;
    }

    count = pamsshagentauth_get_command_line(&reported_argv);
    if (count > 0) { 
        free_logbuf = 1;
        action_logbuf = log_action(reported_argv, count);
        agent_action(&action_agentbuf, reported_argv, count);
        pamsshagentauth_free_command_line(reported_argv, count);
    }
    else {
        action_logbuf = "unknown on this platform";
        pamsshagentauth_buffer_init(&action_agentbuf); /* stays empty, means unavailable */
    }
    
    /*
    action = getenv("SUDO_COMMAND");
    if(!action) {
        action = getenv("PAM_AUTHORIZED_ACTION");
        if(!action) {
            action = empty;
        }
    }
    */

    gethostname(hostname, sizeof(hostname) - 1);
    getcwd(pwd, sizeof(pwd) - 1);
    time(&ts);

    pamsshagentauth_buffer_init(session_id2);

    pamsshagentauth_buffer_put_int(session_id2, PAM_SSH_AGENT_AUTH_REQUESTv1);
    /* pamsshagentauth_debug3("cookie: %s", pamsshagentauth_tohex(cookie, cookie_len)); */
    pamsshagentauth_buffer_put_string(session_id2, cookie, cookie_len);
    /* pamsshagentauth_debug3("user: %s", user); */
    pamsshagentauth_buffer_put_cstring(session_id2, user);
    /* pamsshagentauth_debug3("ruser: %s", ruser); */
    pamsshagentauth_buffer_put_cstring(session_id2, ruser);
    /* pamsshagentauth_debug3("servicename: %s", servicename); */
    pamsshagentauth_buffer_put_cstring(session_id2, servicename);
    /* pamsshagentauth_debug3("pwd: %s", pwd); */
    pamsshagentauth_buffer_put_cstring(session_id2, pwd);
    /* pamsshagentauth_debug3("action: %s", action_logbuf); */
    pamsshagentauth_buffer_put_string(session_id2, action_agentbuf.buf + action_agentbuf.offset, action_agentbuf.end - action_agentbuf.offset);
    if (free_logbuf) { 
        pamsshagentauth_xfree(action_logbuf);
        pamsshagentauth_buffer_free(&action_agentbuf);
    }
    /* pamsshagentauth_debug3("hostname: %s", hostname); */
    pamsshagentauth_buffer_put_cstring(session_id2, hostname);
    /* pamsshagentauth_debug3("ts: %ld", ts); */
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
                pamsshagentauth_xfree(id->filename);
                pamsshagentauth_key_free(id->key);
                pamsshagentauth_xfree(id);
                if(retval == 1)
                    break;
            }
        }
        pamsshagentauth_buffer_free(&session_id2);
        ssh_close_authentication_connection(ac);
    }
    else {
        pamsshagentauth_verbose("No ssh-agent could be contacted");
    }
    /* pamsshagentauth_xfree(session_id2); */
    EVP_cleanup();
    return retval;
}
