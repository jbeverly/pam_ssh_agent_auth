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
uint8_t session_id2_len = 0;

u_char *
session_id2_gen(uint8_t * session_id_len)
{
    char *cookie = NULL;
    uint8_t i = 0;
    uint32_t rnd = 0;

    rnd = arc4random();
    *session_id_len = (uint8_t) rnd;

    cookie = xcalloc(1,*session_id_len);

    for (i = 0; i < *session_id_len; i++) {
        if (i % 4 == 0)
            rnd = arc4random();
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
    session_id2 = session_id2_gen(&session_id2_len);

    if ((ac = ssh_get_authentication_connection(uid))) {
        verbose("Contacted ssh-agent");
        for (key = ssh_get_first_identity(ac, &comment, 2); key != NULL; key = ssh_get_next_identity(ac, &comment, 2)) 
        {
            if(key != NULL) {
                id = xcalloc(1, sizeof(*id));
                id->key = key;
                id->filename = comment;
                id->ac = ac;
                if(userauth_pubkey_from_id(id,uid)) {
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
