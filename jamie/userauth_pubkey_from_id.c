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
#include <stdio.h>

#include "xmalloc.h"
#include "ssh.h"
#include "ssh2.h"
#include "buffer.h"
#include "log.h"
#include "compat.h"
#include "key.h"
#include "pathnames.h"
#include "misc.h"
#include "secure_filename.h"

#include "identity.h"
#include "pam_user_authorized_keys.h"

extern u_char  *session_id2;
extern uint8_t  session_id_len;

int
userauth_pubkey_from_id(Identity * id)
{
    Buffer          b = { 0 };
    char           *pkalg = NULL;
    u_char         *pkblob = NULL, *sig = NULL;
    u_int           blen = 0, slen = 0;
    int             authenticated = 0;

    pkalg = (char *) key_ssh_name(id->key);

    if(key_to_blob(id->key, &pkblob, &blen) == 0)
        goto user_auth_clean_exit;

    /* construct packet to sign and test */
    buffer_init(&b);

    buffer_put_string(&b, session_id2, session_id_len);
    buffer_put_char(&b, SSH2_MSG_USERAUTH_REQUEST);
    buffer_put_cstring(&b, "root");
    buffer_put_cstring(&b, "ssh-userauth");
    buffer_put_cstring(&b, "publickey");
    buffer_put_char(&b, 1);
    buffer_put_cstring(&b, pkalg);
    buffer_put_string(&b, pkblob, blen);

    if(ssh_agent_sign(id->ac, id->key, &sig, &slen, buffer_ptr(&b), buffer_len(&b)) != 0)
        goto user_auth_clean_exit;

    /* test for correct signature */
    if(pam_user_key_allowed(id->key) && key_verify(id->key, sig, slen, buffer_ptr(&b), buffer_len(&b)) == 1)
        authenticated = 1;

  user_auth_clean_exit:
    if(&b != NULL)
        buffer_free(&b);
    if(sig != NULL)
        xfree(sig);
    if(pkblob != NULL)
        xfree(pkblob);
    CRYPTO_cleanup_all_ex_data();
    return authenticated;
}
