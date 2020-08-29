/* $OpenBSD: key.c,v 1.69 2007/07/12 05:48:05 ray Exp $ */
/*
 * read_bignum():
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 *
 *
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
 /*
  * My single line "return -1; / * avoid compiler warning * / is licensed
  * under same BSD style license as the remainder of this file.
  * Feel free to use it for any purpose... ... ... Jamie Beverly ... ... ...
  */

#include "includes.h"

#include <sys/types.h>

#include <openssl/evp.h>
#include <openbsd-compat/openssl-compat.h>
#include <openssl/rand.h>

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "xmalloc.h"
#include "key.h"
#include "rsa.h"
#include "uuencode.h"
#include "buffer.h"
#include "log.h"

#define CB_MAX_ECPOINT	((528 * 2 / 8) + 1)

Key *
pamsshagentauth_key_new(int type)
{
	Key *k;
	RSA *rsa;
	DSA *dsa;
	ED25519 *ed25519;
	k = pamsshagentauth_xcalloc(1, sizeof(*k));
	k->type = type;
	k->dsa = NULL;
	k->rsa = NULL;
	k->ecdsa = NULL;
	k->ed25519 = NULL;
	switch (k->type) {
	case KEY_RSA1:
	case KEY_RSA:
		if ((rsa = RSA_new()) == NULL)
			pamsshagentauth_fatal("key_new: RSA_new failed");
#if OPENSSL_VERSION_NUMBER < 0x10100005L || defined(LIBRESSL_VERSION_NUMBER)
		if ((rsa->n = BN_new()) == NULL)
			pamsshagentauth_fatal("key_new: BN_new failed");
		if ((rsa->e = BN_new()) == NULL)
			pamsshagentauth_fatal("key_new: BN_new failed");
#else
		if (RSA_set0_key(rsa, BN_new(), BN_new(), NULL) != 1)
			pamsshagentauth_fatal("key_new: RSA_set0_key failed");
#endif
		k->rsa = rsa;
		break;
	case KEY_DSA:
		if ((dsa = DSA_new()) == NULL)
			pamsshagentauth_fatal("key_new: DSA_new failed");
#if OPENSSL_VERSION_NUMBER < 0x10100005L || defined(LIBRESSL_VERSION_NUMBER)
		if ((dsa->p = BN_new()) == NULL)
			pamsshagentauth_fatal("key_new: BN_new failed");
		if ((dsa->q = BN_new()) == NULL)
			pamsshagentauth_fatal("key_new: BN_new failed");
		if ((dsa->g = BN_new()) == NULL)
			pamsshagentauth_fatal("key_new: BN_new failed");
		if ((dsa->pub_key = BN_new()) == NULL)
			pamsshagentauth_fatal("key_new: BN_new failed");
#else
		if (DSA_set0_pqg(dsa, BN_new(), BN_new(), BN_new()) != 1)
			pamsshagentauth_fatal("key_new: DSA_set0_pqg failed");
		if (DSA_set0_key(dsa, BN_new(), NULL) != 1)
			pamsshagentauth_fatal("key_new: DSA_set0_key failed");
#endif
		k->dsa = dsa;
		break;
	case KEY_ECDSA:
		// do nothing until we know which group
		break;
	case KEY_ED25519:
		k->ed25519 = pamsshagentauth_xcalloc(1, sizeof(*k->ed25519));
		break;
	case KEY_UNSPEC:
		break;
	default:
		pamsshagentauth_fatal("key_new: bad key type %d", k->type);
		break;
	}
	return k;
}

Key *
pamsshagentauth_key_new_private(int type)
{
	Key *k = pamsshagentauth_key_new(type);
	switch (k->type) {
	case KEY_RSA1:
	case KEY_RSA:
#if OPENSSL_VERSION_NUMBER < 0x10100005L || defined(LIBRESSL_VERSION_NUMBER)
		if ((k->rsa->d = BN_new()) == NULL)
			pamsshagentauth_fatal("key_new_private: BN_new failed");
		if ((k->rsa->iqmp = BN_new()) == NULL)
			pamsshagentauth_fatal("key_new_private: BN_new failed");
		if ((k->rsa->q = BN_new()) == NULL)
			pamsshagentauth_fatal("key_new_private: BN_new failed");
		if ((k->rsa->p = BN_new()) == NULL)
			pamsshagentauth_fatal("key_new_private: BN_new failed");
		if ((k->rsa->dmq1 = BN_new()) == NULL)
			pamsshagentauth_fatal("key_new_private: BN_new failed");
		if ((k->rsa->dmp1 = BN_new()) == NULL)
			pamsshagentauth_fatal("key_new_private: BN_new failed");
#else
		if (RSA_set0_key(k->rsa, NULL, NULL, BN_new()) != 1)
			pamsshagentauth_fatal("key_new: RSA_set0_key failed");
		if (RSA_set0_crt_params(k->rsa, BN_new(), BN_new(), BN_new()) != 1)
			pamsshagentauth_fatal("key_new: RSA_set0_crt_params failed");
		if (RSA_set0_factors(k->rsa, BN_new(), BN_new()) != 1)
			pamsshagentauth_fatal("key_new: RSA_set0_factors failed");
#endif
		break;
	case KEY_DSA:
#if OPENSSL_VERSION_NUMBER < 0x10100005L || defined(LIBRESSL_VERSION_NUMBER)
		if ((k->dsa->priv_key = BN_new()) == NULL)
			pamsshagentauth_fatal("key_new_private: BN_new failed");
#else
		if (DSA_set0_key(k->dsa, NULL, BN_new()) != 1)
			pamsshagentauth_fatal("key_new_private: DSA_set0_key failed");
#endif
		break;
	case KEY_ECDSA:
#if OPENSSL_VERSION_NUMBER < 0x10100005L || defined(LIBRESSL_VERSION_NUMBER)
		if (EC_KEY_set_private_key(k->ecdsa, BN_new()) != 1)
			pamsshagentauth_fatal("key_new_private: EC_KEY_set_private_key failed");
#else
#endif
		break;
	case KEY_ED25519:
		RAND_bytes(k->ed25519->sk, sizeof(k->ed25519->sk));
		break;
	case KEY_UNSPEC:
		break;
	default:
		break;
	}
	return k;
}

void
pamsshagentauth_key_free(Key *k)
{
	if (k == NULL)
		pamsshagentauth_fatal("key_free: key is NULL");
	switch (k->type) {
	case KEY_RSA1:
	case KEY_RSA:
		if (k->rsa != NULL)
			RSA_free(k->rsa);
		k->rsa = NULL;
		break;
	case KEY_DSA:
		if (k->dsa != NULL)
			DSA_free(k->dsa);
		k->dsa = NULL;
		break;
	case KEY_ECDSA:
		if (k->ecdsa != NULL)
			EC_KEY_free(k->ecdsa);
		k->ecdsa = NULL;
		break;
	case KEY_ED25519:
		if (k->ed25519 != NULL)
			pamsshagentauth_xfree(k->ed25519);
		k->ed25519 = NULL;
		break;
	case KEY_UNSPEC:
		break;
	default:
		pamsshagentauth_fatal("key_free: bad key type %d", k->type);
		break;
	}
	pamsshagentauth_xfree(k);
}

int
pamsshagentauth_key_equal(const Key *a, const Key *b)
{
	if (a == NULL || b == NULL || a->type != b->type)
		return 0;
	switch (a->type) {
	case KEY_RSA1:
	case KEY_RSA:
		return a->rsa != NULL && b->rsa != NULL &&
#if OPENSSL_VERSION_NUMBER < 0x10100005L || defined(LIBRESSL_VERSION_NUMBER)
		    BN_cmp(a->rsa->e, b->rsa->e) == 0 &&
		    BN_cmp(a->rsa->n, b->rsa->n) == 0;
#else
		    BN_cmp(RSA_get0_e(a->rsa), RSA_get0_e(b->rsa)) == 0 &&
		    BN_cmp(RSA_get0_n(a->rsa), RSA_get0_n(b->rsa)) == 0;
#endif
	case KEY_DSA:
		return a->dsa != NULL && b->dsa != NULL &&
#if OPENSSL_VERSION_NUMBER < 0x10100005L || defined(LIBRESSL_VERSION_NUMBER)
		    BN_cmp(a->dsa->p, b->dsa->p) == 0 &&
		    BN_cmp(a->dsa->q, b->dsa->q) == 0 &&
		    BN_cmp(a->dsa->g, b->dsa->g) == 0 &&
		    BN_cmp(a->dsa->pub_key, b->dsa->pub_key) == 0;
#else
		    BN_cmp(DSA_get0_p(a->dsa), DSA_get0_p(b->dsa)) == 0 &&
		    BN_cmp(DSA_get0_q(a->dsa), DSA_get0_q(b->dsa)) == 0 &&
		    BN_cmp(DSA_get0_g(a->dsa), DSA_get0_g(b->dsa)) == 0 &&
		    BN_cmp(DSA_get0_pub_key(a->dsa), DSA_get0_pub_key(b->dsa)) == 0;
#endif
	case KEY_ECDSA:
		return a->ecdsa != NULL && b->ecdsa != NULL &&
			EC_KEY_check_key(a->ecdsa) == 1 &&
			EC_KEY_check_key(b->ecdsa) == 1 &&
			EC_GROUP_cmp(EC_KEY_get0_group(a->ecdsa),
				EC_KEY_get0_group(a->ecdsa), NULL) == 0 &&
			EC_POINT_cmp(EC_KEY_get0_group(a->ecdsa),
				EC_KEY_get0_public_key(a->ecdsa),
				EC_KEY_get0_public_key(b->ecdsa), NULL) == 0 &&
			BN_cmp(EC_KEY_get0_private_key(a->ecdsa),
				EC_KEY_get0_private_key(b->ecdsa)) == 0;
	case KEY_ED25519:
		return a->ed25519 != NULL && b->ed25519 != NULL &&
			memcmp(a->ed25519->sk, b->ed25519->sk,
				   sizeof(a->ed25519->sk)) == 0 &&
			memcmp(a->ed25519->pk, b->ed25519->pk,
				   sizeof(a->ed25519->pk)) == 0;
	default:
		pamsshagentauth_fatal("key_equal: bad key type %d", a->type);
	}
    return -1; /* avoid compiler warning */
}

u_char*
pamsshagentauth_key_fingerprint_raw(const Key *k, enum fp_type dgst_type,
    u_int *dgst_raw_length)
{
	const EVP_MD *md = NULL;
	EVP_MD_CTX *ctx;
	u_char *blob = NULL;
	u_char *retval = NULL;
	u_int len = 0;
	int nlen, elen;

	*dgst_raw_length = 0;

	switch (dgst_type) {
	case SSH_FP_MD5:
		md = EVP_md5();
		break;
	case SSH_FP_SHA1:
		md = EVP_sha1();
		break;
	default:
		pamsshagentauth_fatal("key_fingerprint_raw: bad digest type %d",
		    dgst_type);
	}
	switch (k->type) {
	case KEY_RSA1:
#if OPENSSL_VERSION_NUMBER < 0x10100005L || defined(LIBRESSL_VERSION_NUMBER)
		nlen = BN_num_bytes(k->rsa->n);
		elen = BN_num_bytes(k->rsa->e);
		len = nlen + elen;
		blob = pamsshagentauth_xmalloc(len);
		BN_bn2bin(k->rsa->n, blob);
		BN_bn2bin(k->rsa->e, blob + nlen);
#else
		nlen = BN_num_bytes(RSA_get0_n(k->rsa));
		elen = BN_num_bytes(RSA_get0_e(k->rsa));
		len = nlen + elen;
		blob = pamsshagentauth_xmalloc(len);
		BN_bn2bin(RSA_get0_n(k->rsa), blob);
		BN_bn2bin(RSA_get0_e(k->rsa), blob + nlen);
#endif
		break;
	case KEY_DSA:
	case KEY_ECDSA:
	case KEY_ED25519:
	case KEY_RSA:
		pamsshagentauth_key_to_blob(k, &blob, &len);
		break;
	case KEY_UNSPEC:
		return retval;
	default:
		pamsshagentauth_fatal("key_fingerprint_raw: bad key type %d", k->type);
		break;
	}
	if (blob != NULL) {
		retval = pamsshagentauth_xmalloc(EVP_MAX_MD_SIZE);
		/* XXX Errors from EVP_* functions are not hadled */
		ctx = EVP_MD_CTX_create();
		EVP_DigestInit(ctx, md);
		EVP_DigestUpdate(ctx, blob, len);
		EVP_DigestFinal(ctx, retval, dgst_raw_length);
		memset(blob, 0, len);
		pamsshagentauth_xfree(blob);
		EVP_MD_CTX_destroy(ctx);
	} else {
		pamsshagentauth_fatal("key_fingerprint_raw: blob is null");
	}
	return retval;
}

static char *
key_fingerprint_hex(u_char *dgst_raw, u_int dgst_raw_len)
{
	char *retval;
	u_int i;

	retval = pamsshagentauth_xcalloc(1, dgst_raw_len * 3 + 1);
	for (i = 0; i < dgst_raw_len; i++) {
		char hex[4];
		snprintf(hex, sizeof(hex), "%02x:", dgst_raw[i]);
		pamsshagentauth_strlcat(retval, hex, dgst_raw_len * 3 + 1);
	}

	/* Remove the trailing ':' character */
	retval[(dgst_raw_len * 3) - 1] = '\0';
	return retval;
}

static char *
key_fingerprint_bubblebabble(u_char *dgst_raw, u_int dgst_raw_len)
{
	char vowels[] = { 'a', 'e', 'i', 'o', 'u', 'y' };
	char consonants[] = { 'b', 'c', 'd', 'f', 'g', 'h', 'k', 'l', 'm',
	    'n', 'p', 'r', 's', 't', 'v', 'z', 'x' };
	u_int i, j = 0, rounds, seed = 1;
	char *retval;

	rounds = (dgst_raw_len / 2) + 1;
	retval = pamsshagentauth_xcalloc((rounds * 6), sizeof(char));
	retval[j++] = 'x';
	for (i = 0; i < rounds; i++) {
		u_int idx0, idx1, idx2, idx3, idx4;
		if ((i + 1 < rounds) || (dgst_raw_len % 2 != 0)) {
			idx0 = (((((u_int)(dgst_raw[2 * i])) >> 6) & 3) +
			    seed) % 6;
			idx1 = (((u_int)(dgst_raw[2 * i])) >> 2) & 15;
			idx2 = ((((u_int)(dgst_raw[2 * i])) & 3) +
			    (seed / 6)) % 6;
			retval[j++] = vowels[idx0];
			retval[j++] = consonants[idx1];
			retval[j++] = vowels[idx2];
			if ((i + 1) < rounds) {
				idx3 = (((u_int)(dgst_raw[(2 * i) + 1])) >> 4) & 15;
				idx4 = (((u_int)(dgst_raw[(2 * i) + 1]))) & 15;
				retval[j++] = consonants[idx3];
				retval[j++] = '-';
				retval[j++] = consonants[idx4];
				seed = ((seed * 5) +
				    ((((u_int)(dgst_raw[2 * i])) * 7) +
				    ((u_int)(dgst_raw[(2 * i) + 1])))) % 36;
			}
		} else {
			idx0 = seed % 6;
			idx1 = 16;
			idx2 = seed / 6;
			retval[j++] = vowels[idx0];
			retval[j++] = consonants[idx1];
			retval[j++] = vowels[idx2];
		}
	}
	retval[j++] = 'x';
	retval[j++] = '\0';
	return retval;
}

char *
pamsshagentauth_key_fingerprint(const Key *k, enum fp_type dgst_type, enum fp_rep dgst_rep)
{
	char *retval = NULL;
	u_char *dgst_raw;
	u_int dgst_raw_len;

	dgst_raw = pamsshagentauth_key_fingerprint_raw(k, dgst_type, &dgst_raw_len);
	if (!dgst_raw)
		pamsshagentauth_fatal("key_fingerprint: null from pamsshagentauth_key_fingerprint_raw()");
	switch (dgst_rep) {
	case SSH_FP_HEX:
		retval = key_fingerprint_hex(dgst_raw, dgst_raw_len);
		break;
	case SSH_FP_BUBBLEBABBLE:
		retval = key_fingerprint_bubblebabble(dgst_raw, dgst_raw_len);
		break;
	default:
		pamsshagentauth_fatal("key_fingerprint_ex: bad digest representation %d",
		    dgst_rep);
		break;
	}
	memset(dgst_raw, 0, dgst_raw_len);
	pamsshagentauth_xfree(dgst_raw);
	return retval;
}

/*
 * Reads a multiple-precision integer in decimal from the buffer, and advances
 * the pointer.  The integer must already be initialized.  This function is
 * permitted to modify the buffer.  This leaves *cpp to point just beyond the
 * last processed (and maybe modified) character.  Note that this may modify
 * the buffer containing the number.
 */
static int
read_bignum(char **cpp, BIGNUM * value)
{
	char *cp = *cpp;
	int old;

	/* Skip any leading whitespace. */
	for (; *cp == ' ' || *cp == '\t'; cp++)
		;

	/* Check that it begins with a decimal digit. */
	if (*cp < '0' || *cp > '9')
		return 0;

	/* Save starting position. */
	*cpp = cp;

	/* Move forward until all decimal digits skipped. */
	for (; *cp >= '0' && *cp <= '9'; cp++)
		;

	/* Save the old terminating character, and replace it by \0. */
	old = *cp;
	*cp = 0;

	/* Parse the number. */
	if (BN_dec2bn(&value, *cpp) == 0)
		return 0;

	/* Restore old terminating character. */
	*cp = old;

	/* Move beyond the number and return success. */
	*cpp = cp;
	return 1;
}

static int
write_bignum(FILE *f, BIGNUM *num)
{
	char *buf = BN_bn2dec(num);
	if (buf == NULL) {
		pamsshagentauth_logerror("write_bignum: BN_bn2dec() failed");
		return 0;
	}
	fprintf(f, " %s", buf);
	OPENSSL_free(buf);
	return 1;
}

/* returns 1 ok, -1 error */
int
pamsshagentauth_key_read(Key *ret, char **cpp)
{
	Key *k;
	int success = -1;
	char *cp, *space;
	int len, n, type;
	u_int bits;
	u_char *blob;

	cp = *cpp;

	switch (ret->type) {
	case KEY_RSA1:
		/* Get number of bits. */
		if (*cp < '0' || *cp > '9')
			return -1;	/* Bad bit count... */
		for (bits = 0; *cp >= '0' && *cp <= '9'; cp++)
			bits = 10 * bits + *cp - '0';
		if (bits == 0)
			return -1;
		*cpp = cp;
		/* Get public exponent, public modulus. */
#if OPENSSL_VERSION_NUMBER < 0x10100005L || defined(LIBRESSL_VERSION_NUMBER)
		if (!read_bignum(cpp, ret->rsa->e))
			return -1;
		if (!read_bignum(cpp, ret->rsa->n))
			return -1;
#else
		if (!read_bignum(cpp, RSA_get0_e(ret->rsa)))
			return -1;
		if (!read_bignum(cpp, RSA_get0_n(ret->rsa)))
			return -1;
#endif
		success = 1;
		break;
	case KEY_UNSPEC:
	case KEY_RSA:
	case KEY_DSA:
	case KEY_ECDSA:
	case KEY_ED25519:
		space = strchr(cp, ' ');
		if (space == NULL) {
			pamsshagentauth_verbose("key_read: missing whitespace");
			return -1;
		}
		*space = '\0';
		type = pamsshagentauth_key_type_from_name(cp);
		*space = ' ';
		if (type == KEY_UNSPEC) {
			pamsshagentauth_verbose("key_read: missing keytype");
			return -1;
		}
		cp = space+1;
		if (*cp == '\0') {
			pamsshagentauth_verbose("key_read: short string");
			return -1;
		}
		if (ret->type == KEY_UNSPEC) {
			ret->type = type;
		} else if (ret->type != type) {
			/* is a key, but different type */
			pamsshagentauth_verbose("key_read: type mismatch expected %d found %d", ret->type, type);
			return -1;
		}
		len = 2*strlen(cp);
		blob = pamsshagentauth_xmalloc(len);
		n = pamsshagentauth_uudecode(cp, blob, len);
		if (n < 0) {
			pamsshagentauth_logerror("key_read: uudecode %s failed", cp);
			pamsshagentauth_xfree(blob);
			return -1;
		}
		k = pamsshagentauth_key_from_blob(blob, (u_int)n);
		pamsshagentauth_xfree(blob);
		if (k == NULL) {
			pamsshagentauth_logerror("key_read: key_from_blob %s failed", cp);
			return -1;
		}
		if (k->type != type) {
			pamsshagentauth_logerror("key_read: type mismatch: encoding error");
			pamsshagentauth_key_free(k);
			return -1;
		}
/*XXXX*/
		switch (ret->type) {
		case (KEY_RSA):
			if (ret->rsa != NULL)
				RSA_free(ret->rsa);
			ret->rsa = k->rsa;
			k->rsa = NULL;
			success = 1;
#ifdef DEBUG_PK
			RSA_print_fp(stderr, ret->rsa, 8);
#endif
			break;
		case (KEY_DSA):
			if (ret->dsa != NULL)
				DSA_free(ret->dsa);
			ret->dsa = k->dsa;
			k->dsa = NULL;
			success = 1;
#ifdef DEBUG_PK
			DSA_print_fp(stderr, ret->dsa, 8);
#endif
			break;
		case (KEY_ECDSA):
			if (ret->ecdsa != NULL)
				EC_KEY_free(ret->ecdsa);
			ret->ecdsa = k->ecdsa;
			k->ecdsa = NULL;
			success = 1;
#ifdef DEBUG_PK
			EC_KEY_print_fp(stderr, ret->ecdsa, 8);
#endif
			break;
		case (KEY_ED25519):
			if (ret->ed25519 != NULL)
				pamsshagentauth_xfree(ret->ed25519);
			ret->ed25519 = k->ed25519;
			k->ed25519 = NULL;
			success = 1;
#ifdef DEBUG_PK
			pamsshagentauth_dump_base64(stderr, (u_char*)ret->ed25519,
				sizeof(ret->ed25519));
#endif
			break;
		}
/*XXXX*/
		pamsshagentauth_key_free(k);
		if (success != 1)
			break;
		/* advance cp: skip whitespace and data */
		while (*cp == ' ' || *cp == '\t')
			cp++;
		while (*cp != '\0' && *cp != ' ' && *cp != '\t')
			cp++;
		*cpp = cp;
		break;
	default:
		pamsshagentauth_fatal("key_read: bad key type: %d", ret->type);
		break;
	}
	return success;
}

int
pamsshagentauth_key_write(const Key *key, FILE *f)
{
	int n, success = 0;
	u_int len, bits = 0;
	u_char *blob;
	char *uu;

	if (key->type == KEY_RSA1 && key->rsa != NULL) {
		/* size of modulus 'n' */
#if OPENSSL_VERSION_NUMBER < 0x10100005L || defined(LIBRESSL_VERSION_NUMBER)
		bits = BN_num_bits(key->rsa->n);
		fprintf(f, "%u", bits);
		if (write_bignum(f, key->rsa->e) &&
		    write_bignum(f, key->rsa->n)) {
#else
		bits = BN_num_bits(RSA_get0_n(key->rsa));
		fprintf(f, "%u", bits);
		if (write_bignum(f, RSA_get0_e(key->rsa)) &&
		    write_bignum(f, RSA_get0_n(key->rsa))) {
#endif
			success = 1;
		} else {
			pamsshagentauth_logerror("key_write: failed for RSA key");
		}
	} else if ((key->type == KEY_DSA && key->dsa != NULL) ||
	    (key->type == KEY_RSA && key->rsa != NULL)) {
		pamsshagentauth_key_to_blob(key, &blob, &len);
		uu = pamsshagentauth_xmalloc(2*len);
		n = pamsshagentauth_uuencode(blob, len, uu, 2*len);
		if (n > 0) {
			fprintf(f, "%s %s", key_ssh_name(key), uu);
			success = 1;
		}
		pamsshagentauth_xfree(blob);
		pamsshagentauth_xfree(uu);
	}
	return success;
}

const char *
pamsshagentauth_key_type(const Key *k)
{
	switch (k->type) {
	case KEY_RSA1:
		return "RSA1";
	case KEY_RSA:
		return "RSA";
	case KEY_DSA:
		return "DSA";
	case KEY_ECDSA:
		return "ECDSA";
	case KEY_ED25519:
		return "ED25519";
	}
	return "unknown";
}

const char *
key_ssh_name(const Key *k)
{
	switch (k->type) {
	case KEY_RSA:
		return "ssh-rsa";
	case KEY_DSA:
		return "ssh-dss";
	case KEY_ECDSA:
	{
		int nid = EC_GROUP_get_curve_name(EC_KEY_get0_group(k->ecdsa));
		switch (nid) {
		case NID_X9_62_prime256v1:
			return "ecdsa-sha2-nistp256";
		case NID_secp384r1:
			return "ecdsa-sha2-nistp384";
		case NID_secp521r1:
			return "ecdsa-sha2-nistp521";
		}
	}
	case KEY_ED25519:
		return "ssh-ed25519";
	}
	return "ssh-unknown";
}

const char *
group_ssh_name(const Key *k)
{
	switch (k->type) {
	case KEY_ECDSA:
	{
		int nid = EC_GROUP_get_curve_name(EC_KEY_get0_group(k->ecdsa));
		switch (nid) {
		case NID_X9_62_prime256v1:
			return "nistp256";
		case NID_secp384r1:
			return "nistp384";
		case NID_secp521r1:
			return "nistp521";
		}
	}
	}
	return "ssh-unknown";
}

u_int
pamsshagentauth_key_size(const Key *k)
{
	switch (k->type) {
	case KEY_RSA1:
#if OPENSSL_VERSION_NUMBER < 0x10100005L || defined(LIBRESSL_VERSION_NUMBER)
	case KEY_RSA:
		return BN_num_bits(k->rsa->n);
	case KEY_DSA:
		return BN_num_bits(k->dsa->p);
#else
	case KEY_RSA:
		return BN_num_bits(RSA_get0_n(k->rsa));
	case KEY_DSA:
		return BN_num_bits(DSA_get0_p(k->dsa));
#endif
	case KEY_ECDSA:
	{
		int nid = EC_GROUP_get_curve_name(EC_KEY_get0_group(k->ecdsa));
		switch (nid) {
		case NID_X9_62_prime256v1:
			return 256;
		case NID_secp384r1:
			return 384;
		case NID_secp521r1:
			return 521;
		}
	}
	case KEY_ED25519:
		return 32;
	}
	return 0;
}

static RSA *
rsa_generate_private_key(u_int bits)
{
	RSA *private;

	private = RSA_generate_key(bits, 35, NULL, NULL);
	if (private == NULL)
		pamsshagentauth_fatal("rsa_generate_private_key: key generation failed.");
	return private;
}

static DSA*
dsa_generate_private_key(u_int bits)
{
	DSA *private = DSA_generate_parameters(bits, NULL, 0, NULL, NULL, NULL, NULL);

	if (private == NULL)
		pamsshagentauth_fatal("dsa_generate_private_key: DSA_generate_parameters failed");
	if (!DSA_generate_key(private))
		pamsshagentauth_fatal("dsa_generate_private_key: DSA_generate_key failed.");
	if (private == NULL)
		pamsshagentauth_fatal("dsa_generate_private_key: NULL.");
	return private;
}

static EC_KEY*
ecdsa_generate_private_key(u_int bits)
{
	pamsshagentauth_fatal("ecdsa_generate_private_key: implement me");
	return NULL;
}

static ED25519*
ed25519_generate_private_key()
{
	ED25519 *k = pamsshagentauth_xcalloc(1, sizeof(*k));
	RAND_bytes(k->sk, sizeof(k->sk));
	return k;
}

Key *
pamsshagentauth_key_generate(int type, u_int bits)
{
	Key *k = pamsshagentauth_key_new(KEY_UNSPEC);
	switch (type) {
	case KEY_DSA:
		k->dsa = dsa_generate_private_key(bits);
		break;
	case KEY_RSA:
	case KEY_RSA1:
		k->rsa = rsa_generate_private_key(bits);
		break;
	case KEY_ECDSA:
		k->ecdsa = ecdsa_generate_private_key(bits);
		break;
	case KEY_ED25519:
		k->ed25519 = ed25519_generate_private_key();
		break;
	default:
		pamsshagentauth_fatal("key_generate: unknown type %d", type);
	}
	k->type = type;
	return k;
}

Key *
pamsshagentauth_key_from_private(const Key *k)
{
	Key *n = NULL;
	switch (k->type) {
	case KEY_DSA:
		n = pamsshagentauth_key_new(k->type);
#if OPENSSL_VERSION_NUMBER < 0x10100005L || defined(LIBRESSL_VERSION_NUMBER)
		if ((BN_copy(n->dsa->p, k->dsa->p) == NULL) ||
		    (BN_copy(n->dsa->q, k->dsa->q) == NULL) ||
		    (BN_copy(n->dsa->g, k->dsa->g) == NULL) ||
		    (BN_copy(n->dsa->pub_key, k->dsa->pub_key) == NULL))
#else
		if ((BN_copy(DSA_get0_p(n->dsa), DSA_get0_p(k->dsa)) == NULL) ||
		    (BN_copy(DSA_get0_q(n->dsa), DSA_get0_q(k->dsa)) == NULL) ||
		    (BN_copy(DSA_get0_g(n->dsa), DSA_get0_g(k->dsa)) == NULL) ||
		    (BN_copy(DSA_get0_pub_key(n->dsa), DSA_get0_pub_key(k->dsa)) == NULL))
#endif
			pamsshagentauth_fatal("key_from_private: BN_copy failed");
		break;
	case KEY_RSA:
	case KEY_RSA1:
		n = pamsshagentauth_key_new(k->type);
#if OPENSSL_VERSION_NUMBER < 0x10100005L || defined(LIBRESSL_VERSION_NUMBER)
		if ((BN_copy(n->rsa->n, k->rsa->n) == NULL) ||
		    (BN_copy(n->rsa->e, k->rsa->e) == NULL))
#else
		if ((BN_copy(RSA_get0_n(n->rsa), RSA_get0_n(k->rsa)) == NULL) ||
		    (BN_copy(RSA_get0_e(n->rsa), RSA_get0_e(k->rsa)) == NULL))
#endif
			pamsshagentauth_fatal("key_from_private: BN_copy failed");
		break;
	case KEY_ECDSA:
		n = pamsshagentauth_key_new(k->type);
		if (EC_KEY_copy(n->ecdsa, k->ecdsa) == NULL)
			pamsshagentauth_fatal("key_from_private: EC_KEY_copy failed");
		break;
	case KEY_ED25519:
		n = pamsshagentauth_key_new(k->type);
		memcpy(n->ed25519, k->ed25519, sizeof(ED25519));
		break;
	default:
		pamsshagentauth_fatal("key_from_private: unknown type %d", k->type);
		break;
	}
	return n;
}

int
pamsshagentauth_key_type_from_name(char *name)
{
	if (strcmp(name, "rsa1") == 0) {
		return KEY_RSA1;
	} else if (strcmp(name, "rsa") == 0) {
		return KEY_RSA;
	} else if (strcmp(name, "dsa") == 0) {
		return KEY_DSA;
	} else if (strcmp(name, "ssh-rsa") == 0) {
		return KEY_RSA;
	} else if (strcmp(name, "ssh-dss") == 0) {
		return KEY_DSA;
	} else if (strncmp(name, "ecdsa-sha2", 10) == 0) {
		return KEY_ECDSA;
	} else if (strcmp(name, "ssh-ed25519") == 0) {
		return KEY_ED25519;
	}
	pamsshagentauth_verbose("key_type_from_name: unknown key type '%s'", name);
	return KEY_UNSPEC;
}

int
pamsshagentauth_ec_group_from_name(char *name)
{
	// if we get "ecdsa-sha2-" advance past the ecdsa-sha2- bit
	if (strlen(name) > 11)
		name += 11;
	if (strcmp(name, "nistp256") == 0) {
		return NID_X9_62_prime256v1;
	} else if (strcmp(name, "nistp384") == 0) {
		return NID_secp384r1;
	} else if (strcmp(name, "nistp521") == 0) {
		return NID_secp521r1;
	}
	return -1;
}

int
pamsshagentauth_key_names_valid2(const char *names)
{
	char *s, *cp, *p;

	if (names == NULL || strcmp(names, "") == 0)
		return 0;
	s = cp = pamsshagentauth_xstrdup(names);
	for ((p = strsep(&cp, ",")); p && *p != '\0';
	    (p = strsep(&cp, ","))) {
		switch (pamsshagentauth_key_type_from_name(p)) {
		case KEY_RSA1:
		case KEY_UNSPEC:
			pamsshagentauth_xfree(s);
			return 0;
		}
	}
	pamsshagentauth_verbose("key names ok: [%s]", names);
	pamsshagentauth_xfree(s);
	return 1;
}

Key *
pamsshagentauth_key_from_blob(const u_char *blob, u_int blen)
{
	Buffer b;
	int rlen, type;
	char *ktype = NULL;
	Key *key = NULL;

#ifdef DEBUG_PK
	pamsshagentauth_dump_base64(stderr, blob, blen);
#endif
	pamsshagentauth_buffer_init(&b);
	pamsshagentauth_buffer_append(&b, blob, blen);
	if ((ktype = pamsshagentauth_buffer_get_string_ret(&b, NULL)) == NULL) {
		pamsshagentauth_logerror("key_from_blob: can't read key type");
		goto out;
	}

	type = pamsshagentauth_key_type_from_name(ktype);

	switch (type) {
	case KEY_RSA:
		key = pamsshagentauth_key_new(type);
#if OPENSSL_VERSION_NUMBER < 0x10100005L || defined(LIBRESSL_VERSION_NUMBER)
		if (pamsshagentauth_buffer_get_bignum2_ret(&b, key->rsa->e) == -1 ||
		    pamsshagentauth_buffer_get_bignum2_ret(&b, key->rsa->n) == -1) {
#else
		if (pamsshagentauth_buffer_get_bignum2_ret(&b, RSA_get0_e(key->rsa)) == -1 ||
		    pamsshagentauth_buffer_get_bignum2_ret(&b, RSA_get0_n(key->rsa)) == -1) {
#endif
			pamsshagentauth_logerror("key_from_blob: can't read rsa key");
			pamsshagentauth_key_free(key);
			key = NULL;
			goto out;
		}
#ifdef DEBUG_PK
		RSA_print_fp(stderr, key->rsa, 8);
#endif
		break;
	case KEY_DSA:
		key = pamsshagentauth_key_new(type);
#if OPENSSL_VERSION_NUMBER < 0x10100005L || defined(LIBRESSL_VERSION_NUMBER)
		if (pamsshagentauth_buffer_get_bignum2_ret(&b, key->dsa->p) == -1 ||
		    pamsshagentauth_buffer_get_bignum2_ret(&b, key->dsa->q) == -1 ||
		    pamsshagentauth_buffer_get_bignum2_ret(&b, key->dsa->g) == -1 ||
		    pamsshagentauth_buffer_get_bignum2_ret(&b, key->dsa->pub_key) == -1) {
#else
		if (pamsshagentauth_buffer_get_bignum2_ret(&b, DSA_get0_p(key->dsa)) == -1 ||
		    pamsshagentauth_buffer_get_bignum2_ret(&b, DSA_get0_q(key->dsa)) == -1 ||
		    pamsshagentauth_buffer_get_bignum2_ret(&b, DSA_get0_g(key->dsa)) == -1 ||
		    pamsshagentauth_buffer_get_bignum2_ret(&b, DSA_get0_pub_key(key->dsa)) == -1) {
#endif
			pamsshagentauth_logerror("key_from_blob: can't read dsa key");
			pamsshagentauth_key_free(key);
			key = NULL;
			goto out;
		}
#ifdef DEBUG_PK
		DSA_print_fp(stderr, key->dsa, 8);
#endif
		break;
	case KEY_ECDSA:
	{
		// RFC 5656
		EC_KEY *ecdsa = NULL;
		EC_POINT *p = NULL;
		char *identifier = NULL;
		u_int len = 0;
		void *octets = NULL;

		identifier = pamsshagentauth_buffer_get_string_ret(&b, NULL);

		key = pamsshagentauth_key_new(type);
		if ((ecdsa = EC_KEY_new_by_curve_name(pamsshagentauth_ec_group_from_name(identifier))) == NULL) {
			pamsshagentauth_logerror("key_from_blob: can't create EC KEY");
			pamsshagentauth_key_free(key);
			key = NULL;
			goto out;
		}
		key->ecdsa = ecdsa;

		if ((octets = pamsshagentauth_buffer_get_string_ret(&b, &len)) == NULL || len == 0) {
			pamsshagentauth_logerror("key_from_blob: can't get octets from buffer");
			pamsshagentauth_key_free(key);
			key = NULL;
			goto out;
		}

		if ((p = EC_POINT_new(EC_KEY_get0_group(key->ecdsa))) == NULL) {
			pamsshagentauth_logerror("key_from_blob: can't create EC POINT");
			pamsshagentauth_xfree(octets);
			pamsshagentauth_key_free(key);
			key = NULL;
			goto out;
		}

		if (EC_POINT_oct2point(EC_KEY_get0_group(key->ecdsa), p, octets, len, NULL) == -1) {
			pamsshagentauth_logerror("key_from_blob: can't read ecdsa key");
			EC_POINT_free(p);
			pamsshagentauth_xfree(octets);
			pamsshagentauth_key_free(key);
			key = NULL;
			goto out;
		}

		EC_KEY_set_public_key(key->ecdsa, p);
		EC_POINT_free(p);

		if (!EC_KEY_check_key(key->ecdsa)) {
			pamsshagentauth_logerror("key_from_blob: ecdsa key invalid");
			pamsshagentauth_key_free(key);
			key = NULL;
			goto out;
		}
#ifdef DEBUG_PK
		EC_KEY_print_fp(stderr, key->ecdsa, 8);
#endif
		break;
	}
	case KEY_ED25519:
	{
		u_int len = 0;
		key = pamsshagentauth_key_new(type);
		void *kbits = pamsshagentauth_buffer_get_string_ret(&b, &len);
		if (len != pamsshagentauth_key_size(key)) {
			pamsshagentauth_logerror("key_from_blob: ed25519 key invalid (%u bytes read)",
				len);
			pamsshagentauth_xfree(kbits);
			pamsshagentauth_key_free(key);
			key = NULL;
			goto out;
		}
		memcpy(key->ed25519->pk, kbits, sizeof(key->ed25519->pk));
		pamsshagentauth_xfree(kbits);
#ifdef DEBUG_PK
		pamsshagentauth_dump_base64(stderr, (u_char*)key->ed25519,
			sizeof(key->ed25519));
#endif
		break;
	}
	case KEY_UNSPEC:
		key = pamsshagentauth_key_new(type);
		break;
	default:
		pamsshagentauth_logerror("key_from_blob: cannot handle type %s", ktype);
		goto out;
	}
	rlen = pamsshagentauth_buffer_len(&b);
	if (key != NULL && rlen != 0)
		pamsshagentauth_logerror("key_from_blob: remaining bytes in key blob %d", rlen);
 out:
	if (ktype != NULL)
		pamsshagentauth_xfree(ktype);
	pamsshagentauth_buffer_free(&b);
	return key;
}

int
pamsshagentauth_key_to_blob(const Key *key, u_char **blobp, u_int *lenp)
{
	Buffer b;
	int len;

	if (key == NULL) {
		pamsshagentauth_logerror("key_to_blob: key == NULL");
		return 0;
	}
	pamsshagentauth_buffer_init(&b);
	switch (key->type) {
#if OPENSSL_VERSION_NUMBER < 0x10100005L || defined(LIBRESSL_VERSION_NUMBER)
	case KEY_DSA:
		pamsshagentauth_buffer_put_cstring(&b, key_ssh_name(key));
		pamsshagentauth_buffer_put_bignum2(&b, key->dsa->p);
		pamsshagentauth_buffer_put_bignum2(&b, key->dsa->q);
		pamsshagentauth_buffer_put_bignum2(&b, key->dsa->g);
		pamsshagentauth_buffer_put_bignum2(&b, key->dsa->pub_key);
		break;
	case KEY_RSA:
		pamsshagentauth_buffer_put_cstring(&b, key_ssh_name(key));
		pamsshagentauth_buffer_put_bignum2(&b, key->rsa->e);
		pamsshagentauth_buffer_put_bignum2(&b, key->rsa->n);
		break;
#else
	case KEY_DSA:
		pamsshagentauth_buffer_put_cstring(&b, key_ssh_name(key));
		pamsshagentauth_buffer_put_bignum2(&b, DSA_get0_p(key->dsa));
		pamsshagentauth_buffer_put_bignum2(&b, DSA_get0_q(key->dsa));
		pamsshagentauth_buffer_put_bignum2(&b, DSA_get0_g(key->dsa));
		pamsshagentauth_buffer_put_bignum2(&b, DSA_get0_pub_key(key->dsa));
		break;
	case KEY_RSA:
		pamsshagentauth_buffer_put_cstring(&b, key_ssh_name(key));
		pamsshagentauth_buffer_put_bignum2(&b, RSA_get0_e(key->rsa));
		pamsshagentauth_buffer_put_bignum2(&b, RSA_get0_n(key->rsa));
		break;
#endif
	case KEY_ECDSA:
	{
		size_t l = 0;
		u_char buf[CB_MAX_ECPOINT];

		pamsshagentauth_buffer_put_cstring(&b, key_ssh_name(key));
		pamsshagentauth_buffer_put_cstring(&b, group_ssh_name(key));

		if ((l = EC_POINT_point2oct(EC_KEY_get0_group(key->ecdsa),
									EC_KEY_get0_public_key(key->ecdsa),
									POINT_CONVERSION_UNCOMPRESSED,
									NULL, 0, NULL)) == 0 ||
			(l = EC_POINT_point2oct(EC_KEY_get0_group(key->ecdsa),
									EC_KEY_get0_public_key(key->ecdsa),
									POINT_CONVERSION_UNCOMPRESSED,
									buf, l, NULL)) == 0 ) {
			pamsshagentauth_logerror("key_to_blob: failed to deserialize point");
			return 0;
		}
		pamsshagentauth_buffer_put_string(&b, buf, l);
		bzero(buf, l);
		break;
	}
	case KEY_ED25519:
		pamsshagentauth_buffer_put_cstring(&b, key_ssh_name(key));
		pamsshagentauth_buffer_put_string(&b, key->ed25519->pk, sizeof(key->ed25519->pk));
		break;
	default:
		pamsshagentauth_logerror("key_to_blob: unsupported key type %d", key->type);
		pamsshagentauth_buffer_free(&b);
		return 0;
	}
	len = pamsshagentauth_buffer_len(&b);
	if (lenp != NULL)
		*lenp = len;
	if (blobp != NULL) {
		*blobp = pamsshagentauth_xmalloc(len);
		memcpy(*blobp, pamsshagentauth_buffer_ptr(&b), len);
	}
	memset(pamsshagentauth_buffer_ptr(&b), 0, len);
	pamsshagentauth_buffer_free(&b);
	return len;
}

int
pamsshagentauth_key_sign(
    const Key *key,
    u_char **sigp, u_int *lenp,
    const u_char *data, u_int datalen)
{
	switch (key->type) {
	case KEY_DSA:
		return ssh_dss_sign(key, sigp, lenp, data, datalen);
	case KEY_RSA:
		return ssh_rsa_sign(key, sigp, lenp, data, datalen);
	case KEY_ECDSA:
		return ssh_ecdsa_sign(key, sigp, lenp, data, datalen);
	case KEY_ED25519:
		return ssh_ed25519_sign(key, sigp, lenp, data, datalen);
	default:
		pamsshagentauth_logerror("key_sign: invalid key type %d", key->type);
		return -1;
	}
}

/*
 * key_verify returns 1 for a correct signature, 0 for an incorrect signature
 * and -1 on error.
 */
int
pamsshagentauth_key_verify(
    const Key *key,
    const u_char *signature, u_int signaturelen,
    const u_char *data, u_int datalen)
{
	if (signaturelen == 0)
		return -1;

	switch (key->type) {
	case KEY_DSA:
		return ssh_dss_verify(key, signature, signaturelen, data, datalen);
	case KEY_RSA:
		return ssh_rsa_verify(key, signature, signaturelen, data, datalen);
	case KEY_ECDSA:
		return ssh_ecdsa_verify(key, signature, signaturelen, data, datalen);
	case KEY_ED25519:
		return ssh_ed25519_verify(key, signature, signaturelen, data, datalen);
	default:
		pamsshagentauth_logerror("key_verify: invalid key type %d", key->type);
		return -1;
	}
}

/* Converts a private to a public key */
Key *
pamsshagentauth_key_demote(const Key *k)
{
	Key *pk;

	pk = pamsshagentauth_xcalloc(1, sizeof(*pk));
	pk->type = k->type;
	pk->flags = k->flags;
	pk->dsa = NULL;
	pk->rsa = NULL;
	pk->ecdsa = NULL;

	switch (k->type) {
	case KEY_RSA1:
	case KEY_RSA:
		if ((pk->rsa = RSA_new()) == NULL)
			pamsshagentauth_fatal("key_demote: RSA_new failed");
#if OPENSSL_VERSION_NUMBER < 0x10100005L || defined(LIBRESSL_VERSION_NUMBER)
		if ((pk->rsa->e = BN_dup(k->rsa->e)) == NULL)
			pamsshagentauth_fatal("key_demote: BN_dup failed");
		if ((pk->rsa->n = BN_dup(k->rsa->n)) == NULL)
			pamsshagentauth_fatal("key_demote: BN_dup failed");
#else
		if (RSA_set0_key(pk->rsa, BN_dup(RSA_get0_n(k->rsa)), BN_dup(RSA_get0_e(k->rsa)), NULL) != 1)
			pamsshagentauth_fatal("key_demote: RSA_set0_key failed");
#endif
		break;
	case KEY_DSA:
		if ((pk->dsa = DSA_new()) == NULL)
			pamsshagentauth_fatal("key_demote: DSA_new failed");
#if OPENSSL_VERSION_NUMBER < 0x10100005L || defined(LIBRESSL_VERSION_NUMBER)
		if ((pk->dsa->p = BN_dup(k->dsa->p)) == NULL)
			pamsshagentauth_fatal("key_demote: BN_dup failed");
		if ((pk->dsa->q = BN_dup(k->dsa->q)) == NULL)
			pamsshagentauth_fatal("key_demote: BN_dup failed");
		if ((pk->dsa->g = BN_dup(k->dsa->g)) == NULL)
			pamsshagentauth_fatal("key_demote: BN_dup failed");
		if ((pk->dsa->pub_key = BN_dup(k->dsa->pub_key)) == NULL)
			pamsshagentauth_fatal("key_demote: BN_dup failed");
#else
		if (DSA_set0_pqg(pk->dsa, BN_dup(DSA_get0_p(k->dsa)), BN_dup(DSA_get0_q(k->dsa)), BN_dup(DSA_get0_g(k->dsa))) != 1)
			pamsshagentauth_fatal("key_demote: DSA_set0_pqg failed");
		if (DSA_set0_key(pk->dsa, BN_dup(DSA_get0_pub_key(k->dsa)), NULL) != 1)
			pamsshagentauth_fatal("key_demote: DSA_set0_key failed");
#endif
		break;
	case KEY_ECDSA:
		pamsshagentauth_fatal("key_demote: implement me");
		break;
	case KEY_ED25519:
		ed25519_publickey(k->ed25519->sk, k->ed25519->pk);
		break;
	default:
		pamsshagentauth_fatal("key_free: bad key type %d", k->type);
		break;
	}

	return (pk);
}
