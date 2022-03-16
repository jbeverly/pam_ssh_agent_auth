/* $OpenBSD: key.h,v 1.26 2006/08/03 03:34:42 deraadt Exp $ */

/*
 * Copyright (c) 2000, 2001 Markus Friedl.  All rights reserved.
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
#ifndef KEY_H
#define KEY_H

#include <openssl/rsa.h>
#include <openssl/dsa.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include "ed25519-donna/ed25519.h"

typedef struct Key Key;
enum types {
	KEY_RSA1,
	KEY_RSA,
	KEY_DSA,
	KEY_ECDSA,
	KEY_ED25519,
	KEY_UNSPEC
};
enum fp_type {
	SSH_FP_SHA1,
	SSH_FP_MD5,
	SSH_FP_SHA256,
	SSH_FP_SHA384,
	SSH_FP_SHA521
};
enum fp_rep {
	SSH_FP_HEX,
	SSH_FP_BASE64,
	SSH_FP_BUBBLEBABBLE
};

/* key is stored in external hardware */
#define KEY_FLAG_EXT		0x0001

typedef struct ed25519 ED25519;
struct ed25519 {
	ed25519_public_key pk;
	ed25519_secret_key sk;
};

struct Key {
	int	 type;
	int	 flags;
	RSA	*rsa;
	DSA	*dsa;
	EC_KEY *ecdsa;
	ED25519 *ed25519;
};

Key		*pamsshagentauth_key_new(int);
Key		*pamsshagentauth_key_new_private(int);
void		 pamsshagentauth_key_free(Key *);
Key		*pamsshagentauth_key_demote(const Key *);
int		 pamsshagentauth_key_equal(const Key *, const Key *);
char		*pamsshagentauth_key_fingerprint(const Key *, enum fp_type, enum fp_rep);
u_char		*pamsshagentauth_key_fingerprint_raw(const Key *, enum fp_type, u_int *);
const char	*pamsshagentauth_key_type(const Key *);
int		 pamsshagentauth_key_write(const Key *, FILE *);
int		 pamsshagentauth_key_read(Key *, char **);
u_int		 pamsshagentauth_key_size(const Key *);

Key	*pamsshagentauth_key_generate(int, u_int);
Key	*pamsshagentauth_key_from_private(const Key *);
int	 pamsshagentauth_key_type_from_name(char *);

Key		*pamsshagentauth_key_from_blob(const u_char *, u_int);
int		 pamsshagentauth_key_to_blob(const Key *, u_char **, u_int *);
const char	*key_ssh_name(const Key *);
int		 pamsshagentauth_key_names_valid2(const char *);

int	 pamsshagentauth_key_sign(const Key *, u_char **, u_int *, const u_char *, u_int);
int	 pamsshagentauth_key_verify(const Key *, const u_char *, u_int, const u_char *, u_int);

int	 ssh_dss_sign(const Key *, u_char **, u_int *, const u_char *, u_int);
int	 ssh_dss_verify(const Key *, const u_char *, u_int, const u_char *, u_int);
int	 ssh_rsa_sign(const Key *, u_char **, u_int *, const u_char *, u_int);
int	 ssh_rsa_verify(const Key *, const u_char *, u_int, const u_char *, u_int);
int	 ssh_ecdsa_sign(const Key *, u_char **, u_int *, const u_char *, u_int);
int	 ssh_ecdsa_verify(const Key *, const u_char *, u_int, const u_char *, u_int);
int	 ssh_ed25519_sign(const Key *, u_char **, u_int *, const u_char *, u_int);
int	 ssh_ed25519_verify(const Key *, const u_char *, u_int, const u_char *, u_int);

#endif
