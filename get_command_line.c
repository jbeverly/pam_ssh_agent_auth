/*
 * Copyright (c) 2014, Jamie Beverly.
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

#include <stdio.h>
#include <errno.h>
#include <string.h>

#include "includes.h"
#include "xmalloc.h"
#include "get_command_line.h"

#ifdef HAVE_PROC_PID_CMDLINE

static size_t
proc_pid_cmdline(char *** inargv)
{
    pid_t pid;
    FILE *f = NULL;
    char filename[64] = { 0 }, c = '\0';
    char ** argv;
    char argbuf[MAX_LEN_PER_CMDLINE_ARG + 1] = { 0 };
    size_t count = 0, len = 0;

    pid = getpid();
    argv = NULL;

    snprintf(filename, sizeof(filename), "/proc/%d/cmdline", pid);
    f = fopen(filename, "r");

    if (f) { 
        while (!feof(f) && count < MAX_CMDLINE_ARGS) {
            if (len > MAX_LEN_PER_CMDLINE_ARG) {
                while (!feof(f) && (c = fgetc(f)) != '\0');
            }
            else {
                c = fgetc(f);
            }
            switch (c) {
                case EOF:
                case '\0':
                    if (len > 0) { 
                        argv = pamsshagentauth_xrealloc(argv, count + 1, sizeof(*argv));
                        argv[count] = pamsshagentauth_xcalloc(len + 1, sizeof(*argv[count]));
                        strncpy(argv[count++], argbuf, len);
                        memset(argbuf, '\0', MAX_LEN_PER_CMDLINE_ARG + 1);
                        len = 0;
                    }
                    break;
                default:
                    argbuf[len++] = c;
                    break;
            }
        }
        fclose(f);
    }
    *inargv = argv;
    return count;
}
#endif


/*
 * takes a pointer to an unallocated array of arrays of strings, populates the
 * given pointer with the address of the allocated array of strings collected
 */
size_t 
pamsshagentauth_get_command_line(char *** argv)
{
#ifdef HAVE_PROC_PID_CMDLINE
    return proc_pid_cmdline(argv);
#else
    /* No other supported implementations at this time */
    return 0;
#endif
}

void
pamsshagentauth_free_command_line(char ** argv, size_t n_args)
{
    size_t i;
    for (i = 0; i < n_args; i++)
        pamsshagentauth_xfree(argv[i]);

    pamsshagentauth_xfree(argv);
    return;
}

