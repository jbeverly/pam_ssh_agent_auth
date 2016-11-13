#include "includes.h"

#include <sys/types.h>

#include "ed25519-donna/ed25519.h"

#include <stdarg.h>
#include <string.h>

#include "xmalloc.h"
#include "buffer.h"
#include "compat.h"
#include "log.h"
#include "key.h"

int
ssh_ed25519_sign(const Key *key, u_char **sigp, u_int *lenp,
    const u_char *data, u_int datalen)
{
    ed25519_signature sig;
    u_int len;
    Buffer b;

    if (key == NULL || key->type != KEY_ED25519 || key->ed25519 == NULL) {
        pamsshagentauth_logerror("ssh_ed25519_sign: no ED25519 key");
        return -1;
    }
    ed25519_sign(data, datalen, key->ed25519->sk, key->ed25519->pk, sig);

    pamsshagentauth_buffer_init(&b);
    pamsshagentauth_buffer_put_cstring(&b, key_ssh_name(key));
    pamsshagentauth_buffer_put_string(&b, sig, sizeof(sig));

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
ssh_ed25519_verify(const Key *key, const u_char *signature, u_int signaturelen,
    const u_char *data, u_int datalen)
{
    ed25519_signature sig;
    u_int len;
    int rlen, ret;
    Buffer b;
    u_char *sigblob;

    if (key == NULL || key->type != KEY_ED25519 || key->ed25519 == NULL) {
        pamsshagentauth_logerror("ssh_ed25519_verify: no ED25519 key");
        return -1;
    }

   	pamsshagentauth_buffer_init(&b);
    pamsshagentauth_buffer_append(&b, signature, signaturelen);

    char *ktype = pamsshagentauth_buffer_get_string(&b, NULL);
    pamsshagentauth_xfree(ktype);

    sigblob = pamsshagentauth_buffer_get_string(&b, &len);
    rlen = pamsshagentauth_buffer_len(&b);
    pamsshagentauth_buffer_free(&b);
    if (rlen != 0) {
        pamsshagentauth_logerror("ssh_ed25519_verify: "
            "remaining bytes in signature %d", rlen);
        pamsshagentauth_xfree(sigblob);
        return -1;
    }
    memcpy(sig, sigblob, sizeof(sig));
    pamsshagentauth_xfree(sigblob);

	ret = (ed25519_sign_open(data, datalen, key->ed25519->pk, sig) == 0);

    pamsshagentauth_verbose("ssh_ed25519_verify: signature %s",
        ret == 1 ? "correct" : ret == 0 ? "incorrect" : "error");
	return ret;
}