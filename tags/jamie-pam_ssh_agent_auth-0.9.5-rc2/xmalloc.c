/* $OpenBSD: xmalloc.c,v 1.27 2006/08/03 03:34:42 deraadt Exp $ */
/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 * Versions of malloc and friends that check their results, and never return
 * failure (they call fatal if they encounter an error).
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 */

#include "includes.h"

#include <sys/param.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "xmalloc.h"
#include "log.h"

void *
pamsshagentauth_xmalloc(size_t size)
{
	void *ptr;

	if (size == 0)
		pamsshagentauth_fatal("xmalloc: zero size");
	ptr = malloc(size);
	if (ptr == NULL)
		pamsshagentauth_fatal("xmalloc: out of memory (allocating %lu bytes)", (u_long) size);
	return ptr;
}

void *
pamsshagentauth_xcalloc(size_t nmemb, size_t size)
{
	void *ptr;

	if (size == 0 || nmemb == 0)
		pamsshagentauth_fatal("xcalloc: zero size");
	if (SIZE_T_MAX / nmemb < size)
		pamsshagentauth_fatal("xcalloc: nmemb * size > SIZE_T_MAX");
	ptr = calloc(nmemb, size);
	if (ptr == NULL)
		pamsshagentauth_fatal("xcalloc: out of memory (allocating %lu bytes)",
		    (u_long)(size * nmemb));
	return ptr;
}

void *
pamsshagentauth_xrealloc(void *ptr, size_t nmemb, size_t size)
{
	void *new_ptr;
	size_t new_size = nmemb * size;

	if (new_size == 0)
		pamsshagentauth_fatal("xrealloc: zero size");
	if (SIZE_T_MAX / nmemb < size)
		pamsshagentauth_fatal("xrealloc: nmemb * size > SIZE_T_MAX");
	if (ptr == NULL)
		new_ptr = malloc(new_size);
	else
		new_ptr = realloc(ptr, new_size);
	if (new_ptr == NULL)
		pamsshagentauth_fatal("xrealloc: out of memory (new_size %lu bytes)",
		    (u_long) new_size);
	return new_ptr;
}

void
pamsshagentauth_xfree(void *ptr)
{
	if (ptr == NULL)
		pamsshagentauth_fatal("xfree: NULL pointer given as argument");
	free(ptr);
}

char *
pamsshagentauth_xstrdup(const char *str)
{
	size_t len;
	char *cp;

	len = strlen(str) + 1;
	cp = pamsshagentauth_xmalloc(len);
	pamsshagentauth_strlcpy(cp, str, len);
	return cp;
}

int
pamsshagentauth_xasprintf(char **ret, const char *fmt, ...)
{
	va_list ap;
	int i;

	va_start(ap, fmt);
	i = vasprintf(ret, fmt, ap);
	va_end(ap);

	if (i < 0 || *ret == NULL)
		pamsshagentauth_fatal("xasprintf: could not allocate memory");

	return (i);
}
