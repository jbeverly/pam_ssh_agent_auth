#ifndef _GET_COMMAND_LINE_H
#define _GET_COMMAND_LINE_H

#include "includes.h"

size_t pamsshagentauth_get_command_line(char ***);
void pamsshagentauth_free_command_line(char **, size_t);
#define MAX_CMDLINE_ARGS 255
#define MAX_LEN_PER_CMDLINE_ARG 255

#endif
