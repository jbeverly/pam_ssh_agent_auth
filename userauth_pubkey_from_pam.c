/*
 * Copyright (c) 2019, Hound Technology, Inc.
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
 * or implied, of Liz Fong-Jones or Hound Technology, Inc.
 */

#include "userauth_pubkey_from_pam.h"
#include "config.h"

#include <string.h>

#include "defines.h"
#include "key.h"
#include "log.h"

#include "pam_user_authorized_keys.h"

int userauth_pubkey_from_pam(const char* ruser, const char* ssh_auth_info) {
    int authenticated = 0;
    const char* method = "publickey ";

    char* ai = strdup(ssh_auth_info);
    char* saveptr;
    if (ai == NULL) {
        return authenticated;
    }

    char* auth_line = strtok_r(ai, "\n", &saveptr);
    while (auth_line != NULL) {
        if (strncmp(auth_line, method, strlen(method)) == 0) {
            char* key_str = auth_line + strlen(method);
            Key* key = pamsshagentauth_key_new(KEY_UNSPEC);
            if (key == NULL) {
                continue;
            }
            int r = 0;
            if ((r = pamsshagentauth_key_read(key, &key_str)) == 1) {
                if (pam_user_key_allowed(ruser, key)) {
                    authenticated = 1;
                }
            } else {
                pamsshagentauth_verbose("Failed to create key for %s: %d", auth_line, r);
            }
            pamsshagentauth_key_free(key);
        }
        auth_line = strtok_r(NULL, "\n", &saveptr);
    }

    free(ai);
    return authenticated;
}

