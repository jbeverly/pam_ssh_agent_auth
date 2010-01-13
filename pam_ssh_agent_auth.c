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


char           *authorized_keys_file = NULL;
uint8_t         allow_user_owned_authorized_keys_file = 0;

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
    char            sudo_service_name[128] = "sudo";
    char            ruser[128] = "";

    int             i = 0;
    int             retval = PAM_AUTH_ERR;

    LogLevel        log_lvl = SYSLOG_LEVEL_INFO;
    SyslogFacility  facility = SYSLOG_FACILITY_AUTH;

#ifdef LOG_AUTHPRIV 
    facility = SYSLOG_FACILITY_AUTHPRIV;
#endif

    pam_get_item(pamh, PAM_SERVICE, (void *) &servicename);
/*
 * XXX: 
 * When testing on MacOS (and I presume them same would be true on other a.out systems)
 * I tried '-undefined supress -flat_namespace', but then rather than compilation errors, I
 * received dl_open errors about the unresolvable symbol. So I just made my own symbol, and it 
 * works quite nicely... if you know of a better way than this kludge, I'd be most appreciative for 
 * a patch 8-)
 */
#if ! HAVE___PROGNAME || HAVE_BUNDLE
    __progname = xstrdup(servicename);
#endif

    for(i = argc, argv_ptr = (char **) argv; i > 0; ++argv_ptr, i--) {
        if(strncasecmp(*argv_ptr, "debug", strlen("debug")) == 0) {
            log_lvl = SYSLOG_LEVEL_DEBUG3;
        }
        if(strncasecmp(*argv_ptr, "allow_user_owned_authorized_keys_file", strlen("allow_user_owned_authorized_keys_file")) == 0) {
            allow_user_owned_authorized_keys_file = 1;
        }
        if(strncasecmp(*argv_ptr, "file=", strlen("file=")) == 0) {
            authorized_keys_file_input = *argv_ptr + strlen("file=");
        }
#ifdef ENABLE_SUDO_HACK
        if(strncasecmp(*argv_ptr, "sudo_service_name=", strlen("sudo_service_name=")) == 0) {
            strncpy( sudo_service_name, *argv_ptr + strlen("sudo_service_name="), 127 );
        }
#endif
    }

    log_init(__progname, log_lvl, facility, 0);
    pam_get_item(pamh, PAM_USER, (void *) &user);
    pam_get_item(pamh, PAM_RUSER, (void *) &ruser_ptr);

    if(ruser_ptr) {
        strncpy(ruser, ruser_ptr, 127);
    } else {
        /*
         * XXX: XXX: XXX: XXX: XXX: XXX: XXX: XXX: XXX:
         * This is a kludge to address a bug in sudo wherein PAM_RUSER is left unset at the time 
         * pam_authenticate is called, and so we cannot reliably know who invoked the process except
         * via the SUDO_USER environment variable. I've submitted a patch to sudo which fixes this,
         * and so this should not be enabled with versions of sudo which contain it. 
         */
#ifdef ENABLE_SUDO_HACK
        if( (strlen(sudo_service_name) > 0) && strncasecmp(servicename, sudo_service_name, strlen(sudo_service_name)) == 0 && getenv("SUDO_USER") ) {
            strncpy(ruser, getenv("SUDO_USER"), 127);
            verbose( "Using environment variable SUDO_USER (%s)", ruser );
        } else 
#endif
        {
            strncpy(ruser, getpwuid(getuid())->pw_name, 127);
        }
    }

    if(authorized_keys_file_input && user) {
        /*
         * user is the name of the target-user, and so must be used for validating the authorized_keys file
         */
        parse_authorized_key_file(user, authorized_keys_file_input);
    } else {
        verbose("Using default file=/etc/security/authorized_keys");
        authorized_keys_file = xstrdup("/etc/security/authorized_keys");
    }

    /* 
     * PAM_USER and PAM_RUSER do not necessarily have to get set by the calling application, and we may be unable to divine the latter.
     * In those cases we should fail
     */

    if(user && strlen(ruser) > 0) {
        verbose("Attempting authentication: `%s' as `%s' using %s", ruser, user, authorized_keys_file);

        /* 
         * this pw_uid is used to validate the SSH_AUTH_SOCK, and so must be the uid of the ruser invoking the program, not the target-user
         */
        if(find_authorized_keys(getpwnam(ruser)->pw_uid)) {
            logit("Authenticated: `%s' as `%s' using %s", ruser, user, authorized_keys_file);
            retval = PAM_SUCCESS;
        } else {
            logit("Failed Authentication: `%s' as `%s' using %s", ruser, user, authorized_keys_file);
        }
    } else {
        logit("No %s specified, cannot continue with this form of authentication", (user) ? "ruser" : "user" );
    }
#if ! HAVE___PROGNAME || HAVE_BUNDLE
    free(__progname);
#endif

    free(authorized_keys_file);

    return retval;
}


PAM_EXTERN int
pam_sm_setcred(pam_handle_t * pamh, int flags, int argc, const char **argv)
{
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
