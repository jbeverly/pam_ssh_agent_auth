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
//#include "secure_filename.h"
#include "pam_user_authorized_keys.h"


char * authorized_keys_file = NULL;
uint8_t allow_user_owned_authorized_keys_file = 0;

#if ! HAVE___PROGNAME || HAVE_BUNDLE
char * __progname;
#else
extern char * __progname;
#endif

PAM_EXTERN int 
pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) 
{
    const char * user = NULL;
    char ** v; 
    int i = 0;
    int retval = PAM_AUTH_ERR;
    char * authorized_keys_file_input = NULL;
    uid_t caller_uid = 0;
    LogLevel log_lvl = SYSLOG_LEVEL_INFO;
#ifdef SYSLOG_FACILITY_AUTHPRIV
    SyslogFacility facility = SYSLOG_FACILITY_AUTHPRIV;
#else
    SyslogFacility facility = SYSLOG_FACILITY_AUTH;
#endif

/*
 * XXX: 
 * When testing on MacOS (and I presume them same would be true on other a.out systems)
 * I tried '-undefined supress -flat_namespace', but then rather than compilation errors, I
 * received dl_open errors about the unresolvable symbol. So I just made my own symbol, and it 
 * works quite nicely... if you know of a better way than this kludge, I'd be most appreciative for 
 * a patch 8-)
 */
#if ! HAVE___PROGNAME || HAVE_BUNDLE
    char * servicename;
    pam_get_item(pamh, PAM_SERVICE, (void *) &servicename);
    
    __progname = calloc(1,1024);
    strncpy(__prognam,servicename,1024);
#endif

    for (i=argc,v=(char **) argv; i > 0; ++v, i--) {
        if (strncasecmp(*v, "debug", strlen("debug")) == 0) {
            log_lvl = SYSLOG_LEVEL_DEBUG3;
        }
        if ( strncasecmp(*v, "file=", strlen("file=")) == 0 ) {
            authorized_keys_file_input = *v+strlen("file=");
        }
    }

    log_init(__progname, log_lvl, facility, 0);
    pam_get_item(pamh, PAM_USER, (void *) &user);

    allow_user_owned_authorized_keys_file = 0;
    if(authorized_keys_file_input && user) {
        authorized_key_file_translate( user, authorized_keys_file_input );
    }
    else {
        verbose("Using default file=/etc/security/authorized_keys");
        authorized_keys_file = calloc(1,strlen("/etc/security/authorized_keys") + 1);
        strcpy(authorized_keys_file, "/etc/security/authorized_keys");
    }

    if(user) {
        verbose("Authorized keys file = %s", authorized_keys_file);

        /* 
         * PAM_USER does not necessarily have to get set by the calling application. 
         * In those cases we should silently fail 
         */

        caller_uid = getpwnam(user)->pw_uid;

        if(find_authorized_keys(caller_uid)) {
            logit("Authenticated: user %s via ssh-agent using %s", user, authorized_keys_file);
            retval = PAM_SUCCESS;
        }
    }
    else {
        logit("No user specified, cannot continue with this form of authentication");
    }

#if ! HAVE___PROGNAME || HAVE_BUNDLE
    free(__progname);
#endif

    free(authorized_keys_file);

    return retval;
}
    

PAM_EXTERN int 
pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
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

