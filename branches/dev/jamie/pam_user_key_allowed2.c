/* 
 * Copyright (c) 2000 Markus Friedl.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/* 
 * Some miniscule portions Copyright, 2008  Jamie Beverly
 * for pam_ssh_agent_auth PAM module
 *
 * Those portions retain the BSD style license of the original
 */

#include "includes.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>

#include <pwd.h>
#include <stdio.h>
#include <signal.h>
#include <errno.h>
#include <string.h>

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
#include "uidswap.h"

#include "identity.h"

/* return 1 if user allows given key */
/* Modified slightly from original found in auth2-pubkey.c */
static int
pamsshagentauth_check_authkeys_file(FILE * f, char *file, Key * key,
                                    struct passwd *pw)
{
    char line[SSH_MAX_PUBKEY_BYTES];
    int found_key = 0;
    u_long linenum = 0;
    Key *found;
    char *fp;

    found_key = 0;
    found = pamsshagentauth_key_new(key->type);

    while(read_keyfile_line(f, file, line, sizeof(line), &linenum) != -1) {
        char *cp = NULL; /* *key_options = NULL; */

        /* Skip leading whitespace, empty and comment lines. */
        for(cp = line; *cp == ' ' || *cp == '\t'; cp++);
        if(!*cp || *cp == '\n' || *cp == '#')
            continue;

        if(pamsshagentauth_key_read(found, &cp) != 1) {
            /* no key? check if there are options for this key */
            int quoted = 0;

            pamsshagentauth_verbose("user_key_allowed: check options: '%s'", cp);
            /* key_options = cp; */
            for(; *cp && (quoted || (*cp != ' ' && *cp != '\t')); cp++) {
                if(*cp == '\\' && cp[1] == '"')
                    cp++;                                  /* Skip both */
                else if(*cp == '"')
                    quoted = !quoted;
            }
            /* Skip remaining whitespace. */
            for(; *cp == ' ' || *cp == '\t'; cp++);
            if(pamsshagentauth_key_read(found, &cp) != 1) {
                pamsshagentauth_verbose("user_key_allowed: advance: '%s'", cp);
                /* still no key? advance to next line */
                continue;
            }
        }
        if(pamsshagentauth_key_equal(found, key)) {
            found_key = 1;
            pamsshagentauth_logit("matching key found: file/command %s, line %lu", file,
                                  linenum);
            fp = pamsshagentauth_key_fingerprint(found, SSH_FP_MD5, SSH_FP_HEX);
            pamsshagentauth_logit("Found matching %s key: %s",
                                  pamsshagentauth_key_type(found), fp);
            pamsshagentauth_xfree(fp);
            break;
        }
    }
    pamsshagentauth_key_free(found);
    if(!found_key)
        pamsshagentauth_verbose("key not found");
    return found_key;
}

/* 
 * Checks whether key is allowed in file.
 * returns 1 if the key is allowed or 0 otherwise.
 */
int
pamsshagentauth_user_key_allowed2(struct passwd *pw, Key * key, char *file)
{
    FILE *f;
    int found_key = 0;
    struct stat st;
    char buf[SSH_MAX_PUBKEY_BYTES];

    /* Temporarily use the user's uid. */
    pamsshagentauth_verbose("trying public key file %s", file);

    /* Fail not so quietly if file does not exist */
    if(stat(file, &st) < 0) {
        pamsshagentauth_verbose("File not found: %s", file);
        return 0;
    }

    /* Open the file containing the authorized keys. */
    f = fopen(file, "r");
    if(!f) {
        return 0;
    }

    if(pamsshagentauth_secure_filename(f, file, pw, buf, sizeof(buf)) != 0) {
        fclose(f);
        pamsshagentauth_logit("Authentication refused: %s", buf);
        return 0;
    }

    found_key = pamsshagentauth_check_authkeys_file(f, file, key, pw);
    fclose(f);
    return found_key;
}

/* 
 * Checks whether key is allowed in output of command.
 * returns 1 if the key is allowed or 0 otherwise.
 */
int
pamsshagentauth_user_key_command_allowed2(char *authorized_keys_command,
                          char *authorized_keys_command_user,
                          struct passwd *user_pw, Key * key)
{
    FILE *f;
    int ok, found_key = 0;
    struct passwd *pw;
    struct stat st;
    int status, devnull, p[2], i;
    pid_t pid;
    char errmsg[512];
    char username[512] = { 0 };
    


    if(authorized_keys_command == NULL || authorized_keys_command[0] != '/')
        return 0;


    /* getpwnam of authorized_keys_command_user will overwrite the statics used by getpwnam (including pw_name) */
    strncpy(username, user_pw->pw_name, sizeof(username) - 1);

    /* If no user specified to run commands the default to target user */
    if(authorized_keys_command_user == NULL) {
        pw = user_pw;
    }
    else {
        pw = getpwnam(authorized_keys_command_user);
        if(pw == NULL) {
            pamsshagentauth_logerror("authorized_keys_command_user \"%s\" not found: %s",
                 authorized_keys_command_user, strerror(errno));
            return 0;
        }
    }

    pamsshagentauth_temporarily_use_uid(pw);

    if(stat(authorized_keys_command, &st) < 0) {
        pamsshagentauth_logerror
            ("Could not stat AuthorizedKeysCommand \"%s\": %s",
             authorized_keys_command, strerror(errno));
        goto out;
    }
    if(pamsshagentauth_auth_secure_path
       (authorized_keys_command, &st, NULL, 0, errmsg, sizeof(errmsg)) != 0) {
        pamsshagentauth_logerror("Unsafe AuthorizedKeysCommand: %s", errmsg);
        goto out;
    }

    /* open the pipe and read the keys */
    if(pipe(p) != 0) {
        pamsshagentauth_logerror("%s: pipe: %s", __func__, strerror(errno));
        goto out;
    }

    pamsshagentauth_debug("Running AuthorizedKeysCommand: \"%s\" as \"%s\" with argument: \"%s\"",
                          authorized_keys_command, pw->pw_name, username);

    /* 
     * Don't want to call this in the child, where it can fatal() and
     * run cleanup_exit() code.
     */
    pamsshagentauth_restore_uid();

    switch ((pid = fork())) {
    case -1:                                              /* error */
        pamsshagentauth_logerror("%s: fork: %s", __func__, strerror(errno));
        close(p[0]);
        close(p[1]);
        return 0;
    case 0:                                               /* child */
        for(i = 0; i < NSIG; i++)
            signal(i, SIG_DFL);

        /* do this before the setresuid so thta they can be logged */
        if((devnull = open(_PATH_DEVNULL, O_RDWR)) == -1) {
            pamsshagentauth_logerror("%s: open %s: %s", __func__, _PATH_DEVNULL,
                                     strerror(errno));
            _exit(1);
        }
        if(dup2(devnull, STDIN_FILENO) == -1 || dup2(p[1], STDOUT_FILENO) == -1
           || dup2(devnull, STDERR_FILENO) == -1) {
            pamsshagentauth_logerror("%s: dup2: %s", __func__, strerror(errno));
            _exit(1);
        }
#if defined(HAVE_SETRESGID) && !defined(BROKEN_SETRESGID)
        if (setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) != 0) {
#else
        if (setgid(pw->pw_gid) != 0 || setegid(pw->pw_gid) != 0) {
#endif
            pamsshagentauth_logerror("setresgid %u: %s", (u_int) pw->pw_gid,
                                     strerror(errno));
            _exit(1);
        }

#ifdef HAVE_SETRESUID
        if(setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid) != 0) {
#else
        if (setuid(pw->pw_uid) != 0 || seteuid(pw->pw_uid) != 0) {
#endif
            pamsshagentauth_logerror("setresuid %u: %s", (u_int) pw->pw_uid,
                                     strerror(errno));
            _exit(1);
        }

        close(p[0]);
        closefrom(STDERR_FILENO + 1);

        execl(authorized_keys_command, authorized_keys_command, username, NULL);

        /* pretty sure this will barf because we are now suid, but since we
           should't reach this anyway, I'll leave it here */
        pamsshagentauth_logerror("AuthorizedKeysCommand %s exec failed: %s",
                                 authorized_keys_command, strerror(errno));
        _exit(127);
    default:                                              /* parent */
        break;
    }

    pamsshagentauth_temporarily_use_uid(pw);

    close(p[1]);
    if((f = fdopen(p[0], "r")) == NULL) {
        pamsshagentauth_logerror("%s: fdopen: %s", __func__, strerror(errno));
        close(p[0]);
        /* Don't leave zombie child */
        while(waitpid(pid, NULL, 0) == -1 && errno == EINTR);
        goto out;
    }
    ok = pamsshagentauth_check_authkeys_file(f, authorized_keys_command, key,
                                             pw);
    fclose(f);

    while(waitpid(pid, &status, 0) == -1) {
        if(errno != EINTR) {
            pamsshagentauth_logerror("%s: waitpid: %s", __func__,
                                     strerror(errno));
            goto out;
        }
    }
    if(WIFSIGNALED(status)) {
        pamsshagentauth_logerror("AuthorizedKeysCommand %s exited on signal %d",
                                 authorized_keys_command, WTERMSIG(status));
        goto out;
    } else if(WEXITSTATUS(status) != 0) {
        pamsshagentauth_logerror("AuthorizedKeysCommand %s returned status %d",
                                 authorized_keys_command, WEXITSTATUS(status));
        goto out;
    }
    found_key = ok;
  out:
    pamsshagentauth_restore_uid();
    return found_key;
}
