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

#include "userauth_pubkey_from_id.h"
#include "identity.h"

u_char * session_id2 = NULL;
uint8_t session_id_len = 0;

u_char *
session_id2_gen()
{
    char *cookie = NULL;
    uint8_t i = 0;
    uint32_t rnd = 0;

    rnd = arc4random();
    session_id_len = (uint8_t) rnd;

    cookie = calloc(1,session_id_len);

    for (i = 0; i < session_id_len; i++) {
        if (i % 4 == 0) {
            rnd = arc4random();
        }
        cookie[i] = (char) rnd;
        rnd >>= 8;
    }

    return cookie;
}

int
find_authorized_keys(uid_t uid)
{
    Identity *id;
    Key *key;
    AuthenticationConnection *ac;
    char *comment;
    uint8_t retval = 0;

    OpenSSL_add_all_digests();
    session_id2 = session_id2_gen();

    if ((ac = ssh_get_authentication_connection(uid))) {
        verbose("Contacted ssh-agent of user %s (%u)", getpwuid(uid)->pw_name, uid);
        for (key = ssh_get_first_identity(ac, &comment, 2); key != NULL; key = ssh_get_next_identity(ac, &comment, 2)) 
        {
            if(key != NULL) {
                id = xcalloc(1, sizeof(*id));
                id->key = key;
                id->filename = comment;
                id->ac = ac;
                if(userauth_pubkey_from_id(id)) {
                    retval = 1;
                }
                xfree(id->filename);
                key_free(id->key);
                xfree(id);
                if(retval == 1)
                    break;
            }
        }
        ssh_close_authentication_connection(ac);
    }
    else {
        verbose("No ssh-agent could be contacted");
    }
    xfree(session_id2);
    EVP_cleanup();
    return retval;
}
