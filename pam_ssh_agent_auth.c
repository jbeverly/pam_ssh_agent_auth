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

#include "config.h"
#include <syslog.h>

#ifdef HAVE_SECURITY_PAM_APPL_H

#include <security/pam_appl.h>
#define PAM_SM_AUTH
#include <security/pam_modules.h>

#elif HAVE_PAM_PAM_APPL_H

#include <pam/pam_appl.h>
#define PAM_SM_AUTH
#include <pam/pam_modules.h>

#endif

#include <stdarg.h>
#include <strings.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <pwd.h>
#include <unistd.h>
#include "iterate_ssh_agent_keys.h"
#include "includes.h"
#include "log.h"
#include "ssh.h"
#include "pam_static_macros.h"
#include "pam_user_authorized_keys.h"
#include "userauth_pubkey_from_pam.h"

#define strncasecmp_literal(A,B) strncasecmp( A, B, sizeof(B) - 1)
#define UNUSED(expr) do { (void)(expr); } while (0)

char           *authorized_keys_file = NULL;
uint8_t         allow_user_owned_authorized_keys_file = 0;
char           *authorized_keys_command = NULL;
char           *authorized_keys_command_user = NULL;
extern uid_t    authorized_keys_file_allowed_owner_uid;

#if ! HAVE___PROGNAME || HAVE_BUNDLE
char           *__progname;
#else
extern char    *__progname;
#endif

PAM_EXTERN int
pam_sm_authenticate(pam_handle_t * pamh, int flags, int argc, const char **argv)
{
    char          **argv_ptr;
    const char     *user = NULL;
    char           *ruser_ptr = NULL;
    char           *servicename = NULL;
    char           *authorized_keys_file_input = NULL;
    char            sshd_service_name[128] = "sshd";
    char            ruser[128] = "";

    int             i = 0;
    int             retval = PAM_AUTH_ERR;

    LogLevel        log_lvl = SYSLOG_LEVEL_INFO;
    SyslogFacility  facility = SYSLOG_FACILITY_AUTH;

#ifdef LOG_AUTHPRIV
    facility = SYSLOG_FACILITY_AUTHPRIV;
#endif

    int             sshd_service = 0;
    int             sshd_only = 0;

    UNUSED(flags);

    /* Options are per call: clear anything a previous call in this process left behind. */
    authorized_keys_file = NULL;
    allow_user_owned_authorized_keys_file = 0;
    authorized_keys_command = NULL;
    authorized_keys_command_user = NULL;
    authorized_keys_file_allowed_owner_uid = 0;

    if(pam_get_item(pamh, PAM_SERVICE, (const void **) &servicename) != PAM_SUCCESS || servicename == NULL)
        return PAM_AUTH_ERR;
    sshd_service = (strncasecmp(servicename, sshd_service_name, sizeof(sshd_service_name) - 1) == 0);
/*
 * XXX:
 * When testing on MacOS (and I presume them same would be true on other a.out systems)
 * I tried '-undefined supress -flat_namespace', but then rather than compilation errors, I
 * received dl_open errors about the unresolvable symbol. So I just made my own symbol, and it
 * works quite nicely... if you know of a better way than this kludge, I'd be most appreciative for
 * a patch 8-)
 */
#if ! HAVE___PROGNAME || HAVE_BUNDLE
    __progname = pamsshagentauth_xstrdup(servicename);
#endif

    for(i = argc, argv_ptr = (char **) argv; i > 0; ++argv_ptr, i--) {
        if(strncasecmp_literal(*argv_ptr, "debug") == 0) {
            log_lvl = SYSLOG_LEVEL_DEBUG3;
        }
        if(strncasecmp_literal(*argv_ptr, "allow_user_owned_authorized_keys_file")  == 0) {
            allow_user_owned_authorized_keys_file = 1;
        }
        if(strncasecmp_literal(*argv_ptr, "file=") == 0 ) {
            authorized_keys_file_input = *argv_ptr + sizeof("file=") - 1;
        }
        if(strncasecmp_literal(*argv_ptr, "authorized_keys_command=") == 0 ) {
            authorized_keys_command = *argv_ptr + sizeof("authorized_keys_command=") - 1;
        }
        if(strncasecmp_literal(*argv_ptr, "authorized_keys_command_user=") == 0 ) {
            authorized_keys_command_user = *argv_ptr + sizeof("authorized_keys_command_user=") - 1;
        }
    }

    pamsshagentauth_log_init(__progname, log_lvl, facility, 0);
    if(pam_get_item(pamh, PAM_USER, (const void **) &user) != PAM_SUCCESS || user == NULL || *user == '\0') {
        pamsshagentauth_verbose("PAM_USER is not set; refusing authentication");
        goto cleanexit;
    }
    if(pam_get_item(pamh, PAM_RUSER, (const void **) &ruser_ptr) != PAM_SUCCESS)
        ruser_ptr = NULL;

    pamsshagentauth_verbose("Beginning pam_ssh_agent_auth for user %s", user);

    if(ruser_ptr && *ruser_ptr) {
        if(strlen(ruser_ptr) >= sizeof(ruser)) {
            pamsshagentauth_logerror("PAM_RUSER is too long; refusing authentication");
            goto cleanexit;
        }
        strncpy(ruser, ruser_ptr, sizeof(ruser) - 1);
    } else if(sshd_service) {
        /*
         * sshd does not set PAM_RUSER. The key it reports in SSH_AUTH_INFO_0 was used to log in
         * as PAM_USER, so that is the user whose keys are checked. No agent is consulted.
         */
        if(strlen(user) >= sizeof(ruser)) {
            pamsshagentauth_logerror("PAM_USER is too long; refusing authentication");
            goto cleanexit;
        }
        strncpy(ruser, user, sizeof(ruser) - 1);
        sshd_only = 1;
    } else {
        /*
         * PAM_RUSER is the only source for the caller's name. The SUDO_USER environment
         * variable and getuid() are not trusted here, so without PAM_RUSER we refuse.
         */
        pamsshagentauth_verbose("PAM_RUSER is not set; refusing authentication");
        goto cleanexit;
    }

    /* Might as well explicitely confirm the user exists here */
    if(! getpwnam(ruser) ) {
        pamsshagentauth_verbose("getpwnam(%s) failed, bailing out", ruser);
        goto cleanexit;
    }
    if( ! getpwnam(user) ) {
        pamsshagentauth_verbose("getpwnam(%s) failed, bailing out", user);
        goto cleanexit;
    }

    if(authorized_keys_file_input && user) {
        /*
         * user is the name of the target-user, and so must be used for validating the authorized_keys file
         */
        parse_authorized_key_file(user, authorized_keys_file_input);
    } else {
        pamsshagentauth_verbose("Using default file=/etc/security/authorized_keys");
        authorized_keys_file = pamsshagentauth_xstrdup("/etc/security/authorized_keys");
    }

    /*
     * PAM_USER and PAM_RUSER do not necessarily have to get set by the calling application, and we may be unable to divine the latter.
     * In those cases we should fail
     */

    if(user && strlen(ruser) > 0) {
        pamsshagentauth_verbose("Attempting authentication: `%s' as `%s' using %s", ruser, user, authorized_keys_file);

        /*
         * Attempt to read data from the sshd if we're being called as an auth agent.
         */
        const char* ssh_user_auth = pam_getenv(pamh, "SSH_AUTH_INFO_0");
        if (sshd_service && ssh_user_auth != NULL) {
            pamsshagentauth_verbose("Got SSH_AUTH_INFO_0: `%.20s...'", ssh_user_auth);
            if (userauth_pubkey_from_pam(ruser, ssh_user_auth) > 0) {
                retval = PAM_SUCCESS;
                pamsshagentauth_logit("Authenticated (sshd): `%s' as `%s' using %s", ruser, user, authorized_keys_file);
                goto cleanexit;
            }
        }

        if (sshd_only) {
            pamsshagentauth_logit("Failed Authentication (sshd): `%s' using %s", user, authorized_keys_file);
            goto cleanexit;
        }

        /*
         * this pw_uid is used to validate the SSH_AUTH_SOCK, and so must be the uid of the ruser invoking the program, not the target-user
         */
        if(pamsshagentauth_find_authorized_keys(user, ruser, servicename)) { /* getpwnam(ruser)->pw_uid)) { */
            pamsshagentauth_logit("Authenticated (agent): `%s' as `%s' using %s", ruser, user, authorized_keys_file);
            retval = PAM_SUCCESS;
        } else {
            pamsshagentauth_logit("Failed Authentication: `%s' as `%s' using %s", ruser, user, authorized_keys_file);
        }
    } else {
        pamsshagentauth_logit("No %s specified, cannot continue with this form of authentication", (user) ? "ruser" : "user" );
    }

cleanexit:

#if ! HAVE___PROGNAME || HAVE_BUNDLE
    free(__progname);
#endif

    free(authorized_keys_file);
    authorized_keys_file = NULL;

    return retval;
}


PAM_EXTERN int
pam_sm_setcred(pam_handle_t * pamh, int flags, int argc, const char **argv)
{
    UNUSED(pamh);
    UNUSED(flags);
    UNUSED(argc);
    UNUSED(argv);
    return PAM_SUCCESS;
}

#ifdef PAM_STATIC
struct pam_module _pam_ssh_agent_auth_modstruct = {
    "pam_ssh_agent_auth",
    pam_sm_authenticate,
    pam_sm_setcred,
    NULL,
    NULL,
    NULL,
    NULL,
};
#endif
