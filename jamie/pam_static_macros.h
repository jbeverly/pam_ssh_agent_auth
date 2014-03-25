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

#ifndef __PAM_STATIC_MACROS_H
#define __PAM_STATIC_MACROS_H

#ifndef PAM_EXTERN

#ifdef PAM_STATIC

#define PAM_EXTERN static

struct pam_module {
    const char *name;       /* Name of the module */

    /* These are function pointers to the module's key functions.  */

    int (*pam_sm_authenticate)(pam_handle_t *pamh, int flags,
                   int argc, const char **argv);
    int (*pam_sm_setcred)(pam_handle_t *pamh, int flags,
              int argc, const char **argv);
    int (*pam_sm_acct_mgmt)(pam_handle_t *pamh, int flags,
                int argc, const char **argv);
    int (*pam_sm_open_session)(pam_handle_t *pamh, int flags,
                   int argc, const char **argv);
    int (*pam_sm_close_session)(pam_handle_t *pamh, int flags,
                int argc, const char **argv);
    int (*pam_sm_chauthtok)(pam_handle_t *pamh, int flags,
                int argc, const char **argv);
};

#else /* !PAM_STATIC */

#define PAM_EXTERN extern

#endif /* PAM_STATIC */

#endif /* PAM_EXTERN */

#endif /* __PAM_STATIC_MACROS_H */

