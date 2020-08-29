/* $OpenBSD: ssh-dss.c,v 1.24 2006/11/06 21:25:28 markus Exp $ */
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

#include "includes.h"

#include <sys/types.h>

#include <openssl/bn.h>
#include <openssl/evp.h>

#include <stdarg.h>
#include <string.h>

#include "xmalloc.h"
#include "buffer.h"
#include "compat.h"
#include "log.h"
#include "key.h"

#define INTBLOB_LEN	20
#define SIGBLOB_LEN	(2*INTBLOB_LEN)

int
ssh_dss_sign(const Key *key, u_char **sigp, u_int *lenp,
    const u_char *data, u_int datalen)
{
	DSA_SIG *sig;
	const EVP_MD *evp_md = EVP_sha1();
	EVP_MD_CTX *md;
	u_char digest[EVP_MAX_MD_SIZE], sigblob[SIGBLOB_LEN];
	u_int rlen, slen, len, dlen;
	Buffer b;
#if OPENSSL_VERSION_NUMBER >= 0x10100005L && !defined(LIBRESSL_VERSION_NUMBER)
	const BIGNUM *r, *s;
#endif

	if (key == NULL || key->type != KEY_DSA || key->dsa == NULL) {
		pamsshagentauth_logerror("ssh_dss_sign: no DSA key");
		return -1;
	}
	md = EVP_MD_CTX_create();
	EVP_DigestInit(md, evp_md);
	EVP_DigestUpdate(md, data, datalen);
	EVP_DigestFinal(md, digest, &dlen);

	sig = DSA_do_sign(digest, dlen, key->dsa);
	memset(digest, 'd', sizeof(digest));
	EVP_MD_CTX_destroy(md);

	if (sig == NULL) {
		pamsshagentauth_logerror("ssh_dss_sign: sign failed");
		return -1;
	}

#if OPENSSL_VERSION_NUMBER < 0x10100005L || defined(LIBRESSL_VERSION_NUMBER)
	rlen = BN_num_bytes(sig->r);
	slen = BN_num_bytes(sig->s);
#else
	DSA_SIG_get0((const DSA_SIG *)sig, (const BIGNUM **)r, (const BIGNUM **)s);
	rlen = BN_num_bytes(r);
	slen = BN_num_bytes(s);
#endif
	if (rlen > INTBLOB_LEN || slen > INTBLOB_LEN) {
		pamsshagentauth_logerror("bad sig size %u %u", rlen, slen);
		DSA_SIG_free(sig);
		return -1;
	}
	memset(sigblob, 0, SIGBLOB_LEN);
#if OPENSSL_VERSION_NUMBER < 0x10100005L || defined(LIBRESSL_VERSION_NUMBER)
	BN_bn2bin(sig->r, sigblob+ SIGBLOB_LEN - INTBLOB_LEN - rlen);
	BN_bn2bin(sig->s, sigblob+ SIGBLOB_LEN - slen);
#else
	BN_bn2bin(r, sigblob+ SIGBLOB_LEN - INTBLOB_LEN - rlen);
	BN_bn2bin(s, sigblob+ SIGBLOB_LEN - slen);
#endif
	DSA_SIG_free(sig);

	if (datafellows & SSH_BUG_SIGBLOB) {
		if (lenp != NULL)
			*lenp = SIGBLOB_LEN;
		if (sigp != NULL) {
			*sigp = pamsshagentauth_xmalloc(SIGBLOB_LEN);
			memcpy(*sigp, sigblob, SIGBLOB_LEN);
		}
	} else {
		/* ietf-drafts */
		pamsshagentauth_buffer_init(&b);
		pamsshagentauth_buffer_put_cstring(&b, "ssh-dss");
		pamsshagentauth_buffer_put_string(&b, sigblob, SIGBLOB_LEN);
		len = pamsshagentauth_buffer_len(&b);
		if (lenp != NULL)
			*lenp = len;
		if (sigp != NULL) {
			*sigp = pamsshagentauth_xmalloc(len);
			memcpy(*sigp, pamsshagentauth_buffer_ptr(&b), len);
		}
		pamsshagentauth_buffer_free(&b);
	}
	return 0;
}
int
ssh_dss_verify(const Key *key, const u_char *signature, u_int signaturelen,
    const u_char *data, u_int datalen)
{
	DSA_SIG *sig;
	const EVP_MD *evp_md = EVP_sha1();
	EVP_MD_CTX *md;
	u_char digest[EVP_MAX_MD_SIZE], *sigblob;
	u_int len, dlen;
	int rlen, ret;
	Buffer b;
#if OPENSSL_VERSION_NUMBER >= 0x10100005L && !defined(LIBRESSL_VERSION_NUMBER)
	BIGNUM *r, *s;
#endif

	if (key == NULL || key->type != KEY_DSA || key->dsa == NULL) {
		pamsshagentauth_logerror("ssh_dss_verify: no DSA key");
		return -1;
	}

	/* fetch signature */
	if (datafellows & SSH_BUG_SIGBLOB) {
		sigblob = pamsshagentauth_xmalloc(signaturelen);
		memcpy(sigblob, signature, signaturelen);
		len = signaturelen;
	} else {
		/* ietf-drafts */
		char *ktype;
		pamsshagentauth_buffer_init(&b);
		pamsshagentauth_buffer_append(&b, signature, signaturelen);
		ktype = pamsshagentauth_buffer_get_string(&b, NULL);
		if (strcmp("ssh-dss", ktype) != 0) {
			pamsshagentauth_logerror("ssh_dss_verify: cannot handle type %s", ktype);
			pamsshagentauth_buffer_free(&b);
			pamsshagentauth_xfree(ktype);
			return -1;
		}
		pamsshagentauth_xfree(ktype);
		sigblob = pamsshagentauth_buffer_get_string(&b, &len);
		rlen = pamsshagentauth_buffer_len(&b);
		pamsshagentauth_buffer_free(&b);
		if (rlen != 0) {
			pamsshagentauth_logerror("ssh_dss_verify: "
			    "remaining bytes in signature %d", rlen);
			pamsshagentauth_xfree(sigblob);
			return -1;
		}
	}

	if (len != SIGBLOB_LEN) {
		pamsshagentauth_fatal("bad sigbloblen %u != SIGBLOB_LEN", len);
	}

	/* parse signature */
	if ((sig = DSA_SIG_new()) == NULL)
		pamsshagentauth_fatal("ssh_dss_verify: DSA_SIG_new failed");
#if OPENSSL_VERSION_NUMBER < 0x10100005L || defined(LIBRESSL_VERSION_NUMBER)
	if ((sig->r = BN_new()) == NULL)
		pamsshagentauth_fatal("ssh_dss_verify: BN_new failed");
	if ((sig->s = BN_new()) == NULL)
		pamsshagentauth_fatal("ssh_dss_verify: BN_new failed");
	if ((BN_bin2bn(sigblob, INTBLOB_LEN, sig->r) == NULL) ||
	    (BN_bin2bn(sigblob+ INTBLOB_LEN, INTBLOB_LEN, sig->s) == NULL))
		pamsshagentauth_fatal("ssh_dss_verify: BN_bin2bn failed");
#else
	if ((r = BN_new()) == NULL)
		pamsshagentauth_fatal("ssh_dss_verify: BN_new failed");
	if ((s = BN_new()) == NULL)
		pamsshagentauth_fatal("ssh_dss_verify: BN_new failed");
	if (DSA_SIG_set0(sig, r, s) != 1)
		pamsshagentauth_fatal("ssh_dss_verify: DSA_SIG_set0 failed");
	if ((BN_bin2bn(sigblob, INTBLOB_LEN, r) == NULL) ||
	    (BN_bin2bn(sigblob+ INTBLOB_LEN, INTBLOB_LEN, s) == NULL))
		pamsshagentauth_fatal("ssh_dss_verify: BN_bin2bn failed");
	if (DSA_SIG_set0(sig, r, s) != 1)
		pamsshagentauth_fatal("ssh_dss_verify: DSA_SIG_set0 failed");
#endif

	/* clean up */
	memset(sigblob, 0, len);
	pamsshagentauth_xfree(sigblob);

	/* sha1 the data */
	md = EVP_MD_CTX_create();
	EVP_DigestInit(md, evp_md);
	EVP_DigestUpdate(md, data, datalen);
	EVP_DigestFinal(md, digest, &dlen);

	ret = DSA_do_verify(digest, dlen, sig, key->dsa);
	memset(digest, 'd', sizeof(digest));
	EVP_MD_CTX_destroy(md);

	DSA_SIG_free(sig);

	pamsshagentauth_verbose("ssh_dss_verify: signature %s",
	    ret == 1 ? "correct" : ret == 0 ? "incorrect" : "error");
	return ret;
}
