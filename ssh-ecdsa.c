#include "includes.h"

#include <sys/types.h>

#include <openssl/bn.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>

#include <stdarg.h>
#include <string.h>

#include "xmalloc.h"
#include "buffer.h"
#include "compat.h"
#include "log.h"
#include "key.h"

const EVP_MD *
evp_from_key(const Key *key)
{
	switch (key->type) {
	case KEY_ECDSA:
	{
		int nid = EC_GROUP_get_curve_name(EC_KEY_get0_group(key->ecdsa));
		switch (nid) {
		case NID_X9_62_prime256v1:
			return EVP_sha256();
		case NID_secp384r1:
			return EVP_sha384();
		case NID_secp521r1:
			return EVP_sha512();
		}
	}
	}
	return NULL;
}

int
ssh_ecdsa_sign(const Key *key, u_char **sigp, u_int *lenp,
    const u_char *data, u_int datalen)
{
	ECDSA_SIG *sig;
	const EVP_MD *evp_md = evp_from_key(key);
	EVP_MD_CTX md;
	u_char digest[EVP_MAX_MD_SIZE];
	u_int len, dlen;
	Buffer b, bb;

	if (key == NULL || key->type != KEY_ECDSA || key->ecdsa == NULL) {
		pamsshagentauth_logerror("ssh_ecdsa_sign: no ECDSA key");
		return -1;
	}

	EVP_DigestInit(&md, evp_md);
	EVP_DigestUpdate(&md, data, datalen);
	EVP_DigestFinal(&md, digest, &dlen);

	sig = ECDSA_do_sign(digest, dlen, key->ecdsa);
	memset(digest, 'd', sizeof(digest));

	if (sig == NULL) {
		pamsshagentauth_logerror("ssh_ecdsa_sign: sign failed");
		return -1;
	}

	pamsshagentauth_buffer_init(&bb);
	if (pamsshagentauth_buffer_get_bignum2_ret(&bb, sig->r) == -1 ||
		pamsshagentauth_buffer_get_bignum2_ret(&bb, sig->s) == -1) {
		pamsshagentauth_logerror("couldn't serialize signature");
		ECDSA_SIG_free(sig);
		return -1;
	}

	pamsshagentauth_buffer_init(&b);
	pamsshagentauth_buffer_put_cstring(&b, key_ssh_name(key));
	pamsshagentauth_buffer_put_string(&b, pamsshagentauth_buffer_ptr(&bb),
		pamsshagentauth_buffer_len(&bb));

	len = pamsshagentauth_buffer_len(&b);
	if (lenp != NULL)
		*lenp = len;
	if (sigp != NULL) {
		*sigp = pamsshagentauth_xmalloc(len);
		memcpy(*sigp, pamsshagentauth_buffer_ptr(&b), len);
	}
	pamsshagentauth_buffer_free(&b);
	return 0;
}


int
ssh_ecdsa_verify(const Key *key, const u_char *signature, u_int signaturelen,
    const u_char *data, u_int datalen)
{
	ECDSA_SIG *sig;
	const EVP_MD *evp_md = evp_from_key(key);
	EVP_MD_CTX md;
	u_char digest[EVP_MAX_MD_SIZE], *sigblob;
	u_int len, dlen;
	int rlen, ret;
	Buffer b;

	if (key == NULL || key->type != KEY_ECDSA || key->ecdsa == NULL) {
		pamsshagentauth_logerror("ssh_ecdsa_sign: no ECDSA key");
		return -1;
	}

	{
		char *ktype;
		pamsshagentauth_buffer_init(&b);
		pamsshagentauth_buffer_append(&b, signature, signaturelen);

		ktype = pamsshagentauth_buffer_get_string(&b, NULL);
		pamsshagentauth_xfree(ktype);
		sigblob = pamsshagentauth_buffer_get_string(&b, &len);
		rlen = pamsshagentauth_buffer_len(&b);
		pamsshagentauth_buffer_free(&b);
		if (rlen != 0) {
			pamsshagentauth_logerror("ssh_ecdsa_verify: "
			    "remaining bytes in signature %d", rlen);
			pamsshagentauth_xfree(sigblob);
			return -1;
		}
	}

	/* parse signature */
	if ((sig = ECDSA_SIG_new()) == NULL)
		pamsshagentauth_fatal("ssh_ecdsa_verify: DSA_SIG_new failed");

	pamsshagentauth_buffer_init(&b);
	pamsshagentauth_buffer_append(&b, sigblob, len);
	if ((pamsshagentauth_buffer_get_bignum2_ret(&b, sig->r) == -1) ||
	    (pamsshagentauth_buffer_get_bignum2_ret(&b, sig->s) == -1))
		pamsshagentauth_fatal("ssh_ecdsa_verify:"
			"pamsshagentauth_buffer_get_bignum2_ret failed");

	/* clean up */
	memset(sigblob, 0, len);
	pamsshagentauth_xfree(sigblob);

	/* sha256 the data */
	EVP_DigestInit(&md, evp_md);
	EVP_DigestUpdate(&md, data, datalen);
	EVP_DigestFinal(&md, digest, &dlen);

	ret = ECDSA_do_verify(digest, dlen, sig, key->ecdsa);
	memset(digest, 'd', sizeof(digest));

	ECDSA_SIG_free(sig);

	pamsshagentauth_verbose("ssh_ecdsa_verify: signature %s",
	    ret == 1 ? "correct" : ret == 0 ? "incorrect" : "error");
	return ret;
}