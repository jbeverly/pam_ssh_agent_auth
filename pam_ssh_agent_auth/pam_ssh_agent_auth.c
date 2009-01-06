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

char * authorized_keys_file = NULL;

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
    uid_t caller_uid = 0;
    LogLevel log_lvl = SYSLOG_LEVEL_INFO;
#ifdef SYSLOG_FACILITY_AUTHPRIV
    SyslogFacility facility = SYSLOG_FACILITY_AUTHPRIV;
#else
    SyslogFacility facility = SYSLOG_FACILITY_AUTH;
#endif

/* 
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
    snprintf(__progname, 1024, "%s", servicename);
#endif

    for (i=argc,v=(char **) argv; i > 0; ++v, i--) {
        if (strncasecmp(*v, "debug", strlen("debug")) == 0) {
            log_lvl = SYSLOG_LEVEL_DEBUG3;
        }
        if (strncasecmp(*v, "file=", strlen("file=")) == 0) {
            authorized_keys_file = *v+strlen("file=");
        }
    }

    if(! authorized_keys_file) 
        authorized_keys_file = "/etc/security/authorized_keys";

    log_init(__progname, log_lvl, facility, 0);
    debug("Authorized keys file = %s", authorized_keys_file);

    pam_get_item(pamh, PAM_USER, (void *) &user);
    caller_uid = getpwnam(user)->pw_uid;

    if(find_authorized_keys(caller_uid)) {
        logit("Authenticated: user %s via ssh-agent using %s", user, authorized_keys_file);
        retval = PAM_SUCCESS;
    }

#if ! HAVE___PROGNAME || HAVE_BUNDLE
    free(__progname);
#endif

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

