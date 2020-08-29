/* $OpenBSD: authfd.c,v 1.80 2006/08/03 03:34:41 deraadt Exp $ */
/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 * Functions for connecting the local authentication agent.
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 *
 * SSH2 implementation,
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
 * All additions/modifications of this file by Jamie Beverly are released under the same license
 * as the original version as found in openssh; which is a BSD style license 
 * */

#include "includes.h"

#include <sys/types.h>
#include <sys/un.h>
#include <sys/socket.h>

#include <openssl/evp.h>

#include <openssl/crypto.h>
#include <fcntl.h>
#include <stdlib.h>
#include <signal.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <pwd.h>
#include <errno.h>

#include "xmalloc.h"
#include "ssh.h"
#include "rsa.h"
#include "buffer.h"
#include "key.h"
#include "authfd.h"
#include "cipher.h"
#include "kex.h"
#include "compat.h"
#include "log.h"
#include "atomicio.h"
#include "misc.h"

static int agent_present = 0;

/* helper */
int	pamsshagentauth_decode_reply(int type);

/* macro to check for "agent failure" message */
#define agent_failed(x) \
    ((x == SSH_AGENT_FAILURE) || (x == SSH_COM_AGENT2_FAILURE) || \
    (x == SSH2_AGENT_FAILURE))

int
ssh_agent_present(void)
{
	if (agent_present)
		return 1;
	return 0;
}

/* Returns the number of the authentication fd, or -1 if there is none. */

/* 
 * Added by Jamie Beverly, ensure socket fd points to a socket owned by the user 
 * A cursory check is done, but to avoid race conditions, it is necessary 
 * to drop effective UID when connecting to the socket. 
 *
 * If the cause of error is EACCES, because we verified we would not have that 
 * problem initially, we can safely assume that somebody is attempting to find a 
 * race condition; so a more "direct" log message is generated.
 */

int
ssh_get_authentication_socket(uid_t uid)
{
	const char *authsocket;
	int sock;
	struct sockaddr_un sunaddr;
    struct stat sock_st;

	authsocket = getenv(SSH_AUTHSOCKET_ENV_NAME);
	if (!authsocket)
		return -1;

    /* Advisory only; seteuid ensures no race condition; but will only log if we see EACCES */
    if( stat(authsocket,&sock_st) == 0) {
        if(uid != 0 && sock_st.st_uid != uid) {
            pamsshagentauth_fatal("uid %lu attempted to open an agent socket owned by uid %lu", (unsigned long) uid, (unsigned long) sock_st.st_uid);
            return -1;
        }
    }

    /* 
     * Ensures that the EACCES tested for below can _only_ happen if somebody 
     * is attempting to race the stat above to bypass authentication.
     */
    if( (sock_st.st_mode & S_IWUSR) != S_IWUSR || (sock_st.st_mode & S_IRUSR) != S_IRUSR) {
        pamsshagentauth_logerror("ssh-agent socket has incorrect permissions for owner");
        return -1;
    }

	sunaddr.sun_family = AF_UNIX;
	pamsshagentauth_strlcpy(sunaddr.sun_path, authsocket, sizeof(sunaddr.sun_path));

	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock < 0)
		return -1;

	/* close on exec */
	if (fcntl(sock, F_SETFD, 1) == -1) {
		close(sock);
		return -1;
	}

    errno = 0; 
    /* To ensure a race condition is not used to circumvent the stat
       above, we will temporarily drop UID to the caller */
    if (seteuid(uid) < 0)
        return -1;

	if (connect(sock, (struct sockaddr *)&sunaddr, sizeof sunaddr) < 0) {
		close(sock);
        if(errno == EACCES)
            pamsshagentauth_fatal("MAJOR SECURITY WARNING: uid %lu made a deliberate and malicious attempt to open an agent socket owned by another user", (unsigned long) uid);
		return -1;
	}

    /* we now continue the regularly scheduled programming */
    if (seteuid(0) < 0)
        return -1;

	agent_present = 1;
	return sock;
}

static int
ssh_request_reply(AuthenticationConnection *auth, Buffer *request, Buffer *reply)
{
	u_int l, len;
	char buf[1024];

	/* Get the length of the message, and format it in the buffer. */
	len = pamsshagentauth_buffer_len(request);
	pamsshagentauth_put_u32(buf, len);

	/* Send the length and then the packet to the agent. */
	if (pamsshagentauth_atomicio(vwrite, auth->fd, buf, 4) != 4 ||
	    pamsshagentauth_atomicio(vwrite, auth->fd, pamsshagentauth_buffer_ptr(request),
	    pamsshagentauth_buffer_len(request)) != pamsshagentauth_buffer_len(request)) {
		pamsshagentauth_logerror("Error writing to authentication socket.");
		return 0;
	}
	/*
	 * Wait for response from the agent.  First read the length of the
	 * response packet.
	 */
	if (pamsshagentauth_atomicio(read, auth->fd, buf, 4) != 4) {
	    pamsshagentauth_logerror("Error reading response length from authentication socket.");
	    return 0;
	}

	/* Extract the length, and check it for sanity. */
	len = pamsshagentauth_get_u32(buf);
	if (len > 256 * 1024)
		pamsshagentauth_fatal("Authentication response too long: %u", len);

	/* Read the rest of the response in to the buffer. */
	pamsshagentauth_buffer_clear(reply);
	while (len > 0) {
		l = len;
		if (l > sizeof(buf))
			l = sizeof(buf);
		if (pamsshagentauth_atomicio(read, auth->fd, buf, l) != l) {
			pamsshagentauth_logerror("Error reading response from authentication socket.");
			return 0;
		}
		pamsshagentauth_buffer_append(reply, buf, l);
		len -= l;
	}
	return 1;
}

/*
 * Closes the agent socket if it should be closed (depends on how it was
 * obtained).  The argument must have been returned by
 * ssh_get_authentication_socket().
 */

void
ssh_close_authentication_socket(int sock)
{
	if (getenv(SSH_AUTHSOCKET_ENV_NAME))
		close(sock);
}

/*
 * Opens and connects a private socket for communication with the
 * authentication agent.  Returns the file descriptor (which must be
 * shut down and closed by the caller when no longer needed).
 * Returns NULL if an error occurred and the connection could not be
 * opened.
 */

AuthenticationConnection *
ssh_get_authentication_connection(uid_t uid)
{
	AuthenticationConnection *auth;
	int sock;

	sock = ssh_get_authentication_socket(uid);

	/*
	 * Fail if we couldn't obtain a connection.  This happens if we
	 * exited due to a timeout.
	 */
	if (sock < 0)
		return NULL;

	auth = pamsshagentauth_xmalloc(sizeof(*auth));
	auth->fd = sock;
	pamsshagentauth_buffer_init(&auth->identities);
	auth->howmany = 0;

	return auth;
}

/*
 * Closes the connection to the authentication agent and frees any associated
 * memory.
 */

void
ssh_close_authentication_connection(AuthenticationConnection *auth)
{
	pamsshagentauth_buffer_free(&auth->identities);
	close(auth->fd);
	pamsshagentauth_xfree(auth);
}

/* Lock/unlock agent */
int
ssh_lock_agent(AuthenticationConnection *auth, int lock, const char *password)
{
	int type;
	Buffer msg;

	pamsshagentauth_buffer_init(&msg);
	pamsshagentauth_buffer_put_char(&msg, lock ? SSH_AGENTC_LOCK : SSH_AGENTC_UNLOCK);
	pamsshagentauth_buffer_put_cstring(&msg, password);

	if (ssh_request_reply(auth, &msg, &msg) == 0) {
		pamsshagentauth_buffer_free(&msg);
		return 0;
	}
	type = pamsshagentauth_buffer_get_char(&msg);
	pamsshagentauth_buffer_free(&msg);
	return pamsshagentauth_decode_reply(type);
}

/*
 * Returns the first authentication identity held by the agent.
 */

int
ssh_get_num_identities(AuthenticationConnection *auth, int version)
{
	int type, code1 = 0, code2 = 0;
	Buffer request;

	switch (version) {
	case 1:
		code1 = SSH_AGENTC_REQUEST_RSA_IDENTITIES;
		code2 = SSH_AGENT_RSA_IDENTITIES_ANSWER;
		break;
	case 2:
		code1 = SSH2_AGENTC_REQUEST_IDENTITIES;
		code2 = SSH2_AGENT_IDENTITIES_ANSWER;
		break;
	default:
		return 0;
	}

	/*
	 * Send a message to the agent requesting for a list of the
	 * identities it can represent.
	 */
	pamsshagentauth_buffer_init(&request);
	pamsshagentauth_buffer_put_char(&request, code1);

	pamsshagentauth_buffer_clear(&auth->identities);
	if (ssh_request_reply(auth, &request, &auth->identities) == 0) {
		pamsshagentauth_buffer_free(&request);
		return 0;
	}
	pamsshagentauth_buffer_free(&request);

	/* Get message type, and verify that we got a proper answer. */
	type = pamsshagentauth_buffer_get_char(&auth->identities);
	if (agent_failed(type)) {
		return 0;
	} else if (type != code2) {
		pamsshagentauth_fatal("Bad authentication reply message type: %d", type);
	}

	/* Get the number of entries in the response and check it for sanity. */
	auth->howmany = pamsshagentauth_buffer_get_int(&auth->identities);
	if ((u_int)auth->howmany > 1024)
		pamsshagentauth_fatal("Too many identities in authentication reply: %d",
		    auth->howmany);

	return auth->howmany;
}

Key *
ssh_get_first_identity(AuthenticationConnection *auth, char **comment, int version)
{
	/* get number of identities and return the first entry (if any). */
	if (ssh_get_num_identities(auth, version) > 0)
		return ssh_get_next_identity(auth, comment, version);
	return NULL;
}

Key *
ssh_get_next_identity(AuthenticationConnection *auth, char **comment, int version)
{
	int keybits;
	u_int bits;
	u_char *blob;
	u_int blen;
	Key *key = NULL;

	/* Return failure if no more entries. */
	if (auth->howmany <= 0)
		return NULL;

	/*
	 * Get the next entry from the packet.  These will abort with a fatal
	 * error if the packet is too short or contains corrupt data.
	 */
	switch (version) {
	case 1:
		key = pamsshagentauth_key_new(KEY_RSA1);
		bits = pamsshagentauth_buffer_get_int(&auth->identities);
#if OPENSSL_VERSION_NUMBER < 0x10100005L || defined(LIBRESSL_VERSION_NUMBER)
		pamsshagentauth_buffer_get_bignum(&auth->identities, key->rsa->e);
		pamsshagentauth_buffer_get_bignum(&auth->identities, key->rsa->n);
		*comment = pamsshagentauth_buffer_get_string(&auth->identities, NULL);
		keybits = BN_num_bits(key->rsa->n);
		if (keybits < 0 || bits != (u_int)keybits)
			pamsshagentauth_logit("Warning: identity keysize mismatch: actual %d, announced %u",
			    BN_num_bits(key->rsa->n), bits);
#else
		pamsshagentauth_buffer_get_bignum(&auth->identities, RSA_get0_e(key->rsa));
		pamsshagentauth_buffer_get_bignum(&auth->identities, RSA_get0_n(key->rsa));
		*comment = pamsshagentauth_buffer_get_string(&auth->identities, NULL);
		keybits = BN_num_bits(RSA_get0_n(key->rsa));
		if (keybits < 0 || bits != (u_int)keybits)
			pamsshagentauth_logit("Warning: identity keysize mismatch: actual %d, announced %u",
			    BN_num_bits(RSA_get0_n(key->rsa)), bits);
#endif
		break;
	case 2:
		blob = pamsshagentauth_buffer_get_string(&auth->identities, &blen);
		*comment = pamsshagentauth_buffer_get_string(&auth->identities, NULL);
		key = pamsshagentauth_key_from_blob(blob, blen);
		pamsshagentauth_xfree(blob);
		break;
	default:
		return NULL;
	}
	/* Decrement the number of remaining entries. */
	auth->howmany--;
	return key;
}

/*
 * Generates a random challenge, sends it to the agent, and waits for
 * response from the agent.  Returns true (non-zero) if the agent gave the
 * correct answer, zero otherwise.  Response type selects the style of
 * response desired, with 0 corresponding to protocol version 1.0 (no longer
 * supported) and 1 corresponding to protocol version 1.1.
 */

int
ssh_decrypt_challenge(AuthenticationConnection *auth,
    Key* key, BIGNUM *challenge,
    u_char session_id[16],
    u_int response_type,
    u_char response[16])
{
	Buffer buffer;
	int success = 0;
	int i;
	int type;

	if (key->type != KEY_RSA1)
		return 0;
	if (response_type == 0) {
		pamsshagentauth_logit("Compatibility with ssh protocol version 1.0 no longer supported.");
		return 0;
	}
	pamsshagentauth_buffer_init(&buffer);
	pamsshagentauth_buffer_put_char(&buffer, SSH_AGENTC_RSA_CHALLENGE);
#if OPENSSL_VERSION_NUMBER < 0x10100005L || defined(LIBRESSL_VERSION_NUMBER)
	pamsshagentauth_buffer_put_int(&buffer, BN_num_bits(key->rsa->n));
	pamsshagentauth_buffer_put_bignum(&buffer, key->rsa->e);
	pamsshagentauth_buffer_put_bignum(&buffer, key->rsa->n);
#else
	pamsshagentauth_buffer_put_int(&buffer, BN_num_bits(RSA_get0_n(key->rsa)));
	pamsshagentauth_buffer_put_bignum(&buffer, RSA_get0_e(key->rsa));
	pamsshagentauth_buffer_put_bignum(&buffer, RSA_get0_n(key->rsa));
#endif
	pamsshagentauth_buffer_put_bignum(&buffer, challenge);
	pamsshagentauth_buffer_append(&buffer, session_id, 16);
	pamsshagentauth_buffer_put_int(&buffer, response_type);

	if (ssh_request_reply(auth, &buffer, &buffer) == 0) {
		pamsshagentauth_buffer_free(&buffer);
		return 0;
	}
	type = pamsshagentauth_buffer_get_char(&buffer);

	if (agent_failed(type)) {
		pamsshagentauth_logit("Agent admitted failure to authenticate using the key.");
	} else if (type != SSH_AGENT_RSA_RESPONSE) {
		pamsshagentauth_fatal("Bad authentication response: %d", type);
	} else {
		success = 1;
		/*
		 * Get the response from the packet.  This will abort with a
		 * fatal error if the packet is corrupt.
		 */
		for (i = 0; i < 16; i++)
			response[i] = (u_char)pamsshagentauth_buffer_get_char(&buffer);
	}
	pamsshagentauth_buffer_free(&buffer);
	return success;
}

/* ask agent to sign data, returns -1 on error, 0 on success */
int
ssh_agent_sign(AuthenticationConnection *auth,
    Key *key,
    u_char **sigp, u_int *lenp,
    u_char *data, u_int datalen)
{
	extern int datafellows;
	Buffer msg;
	u_char *blob;
	u_int blen;
	int type, flags = 0;
	int ret = -1;

	if (pamsshagentauth_key_to_blob(key, &blob, &blen) == 0)
		return -1;

	if (datafellows & SSH_BUG_SIGBLOB)
		flags = SSH_AGENT_OLD_SIGNATURE;

	pamsshagentauth_buffer_init(&msg);
	pamsshagentauth_buffer_put_char(&msg, SSH2_AGENTC_SIGN_REQUEST);
	pamsshagentauth_buffer_put_string(&msg, blob, blen);
	pamsshagentauth_buffer_put_string(&msg, data, datalen);
	pamsshagentauth_buffer_put_int(&msg, flags);
	pamsshagentauth_xfree(blob);

	if (ssh_request_reply(auth, &msg, &msg) == 0) {
		pamsshagentauth_buffer_free(&msg);
		return -1;
	}
	type = pamsshagentauth_buffer_get_char(&msg);
	if (agent_failed(type)) {
		pamsshagentauth_logit("Agent admitted failure to sign using the key.");
	} else if (type != SSH2_AGENT_SIGN_RESPONSE) {
		pamsshagentauth_fatal("Bad authentication response: %d", type);
	} else {
		ret = 0;
		*sigp = pamsshagentauth_buffer_get_string(&msg, lenp);
	}
	pamsshagentauth_buffer_free(&msg);
	return ret;
}

/* Encode key for a message to the agent. */

static void
ssh_encode_identity_rsa1(Buffer *b, RSA *key, const char *comment)
{
#if OPENSSL_VERSION_NUMBER < 0x10100005L || defined(LIBRESSL_VERSION_NUMBER)
	pamsshagentauth_buffer_put_int(b, BN_num_bits(key->n));
	pamsshagentauth_buffer_put_bignum(b, key->n);
	pamsshagentauth_buffer_put_bignum(b, key->e);
	pamsshagentauth_buffer_put_bignum(b, key->d);
	/* To keep within the protocol: p < q for ssh. in SSL p > q */
	pamsshagentauth_buffer_put_bignum(b, key->iqmp);	/* ssh key->u */
	pamsshagentauth_buffer_put_bignum(b, key->q);	/* ssh key->p, SSL key->q */
	pamsshagentauth_buffer_put_bignum(b, key->p);	/* ssh key->q, SSL key->p */
#else
	pamsshagentauth_buffer_put_int(b, BN_num_bits(RSA_get0_n(key)));
	pamsshagentauth_buffer_put_bignum(b, RSA_get0_n(key));
	pamsshagentauth_buffer_put_bignum(b, RSA_get0_e(key));
	pamsshagentauth_buffer_put_bignum(b, RSA_get0_d(key));
	/* To keep within the protocol: p < q for ssh. in SSL p > q */
	pamsshagentauth_buffer_put_bignum(b, RSA_get0_iqmp(key));	/* ssh key->u */
	pamsshagentauth_buffer_put_bignum(b, RSA_get0_q(key));	/* ssh key->p, SSL key->q */
	pamsshagentauth_buffer_put_bignum(b, RSA_get0_p(key));	/* ssh key->q, SSL key->p */
#endif
	pamsshagentauth_buffer_put_cstring(b, comment);
}

static void
ssh_encode_identity_ssh2(Buffer *b, Key *key, const char *comment)
{
	pamsshagentauth_buffer_put_cstring(b, key_ssh_name(key));
	switch (key->type) {
	case KEY_RSA:
#if OPENSSL_VERSION_NUMBER < 0x10100005L || defined(LIBRESSL_VERSION_NUMBER)
		pamsshagentauth_buffer_put_bignum2(b, key->rsa->n);
		pamsshagentauth_buffer_put_bignum2(b, key->rsa->e);
		pamsshagentauth_buffer_put_bignum2(b, key->rsa->d);
		pamsshagentauth_buffer_put_bignum2(b, key->rsa->iqmp);
		pamsshagentauth_buffer_put_bignum2(b, key->rsa->p);
		pamsshagentauth_buffer_put_bignum2(b, key->rsa->q);
#else
		pamsshagentauth_buffer_put_bignum2(b, RSA_get0_n(key->rsa));
		pamsshagentauth_buffer_put_bignum2(b, RSA_get0_e(key->rsa));
		pamsshagentauth_buffer_put_bignum2(b, RSA_get0_d(key->rsa));
		pamsshagentauth_buffer_put_bignum2(b, RSA_get0_iqmp(key->rsa));
		pamsshagentauth_buffer_put_bignum2(b, RSA_get0_p(key->rsa));
		pamsshagentauth_buffer_put_bignum2(b, RSA_get0_q(key->rsa));
#endif
		break;
	case KEY_DSA:
#if OPENSSL_VERSION_NUMBER < 0x10100005L || defined(LIBRESSL_VERSION_NUMBER)
		pamsshagentauth_buffer_put_bignum2(b, key->dsa->p);
		pamsshagentauth_buffer_put_bignum2(b, key->dsa->q);
		pamsshagentauth_buffer_put_bignum2(b, key->dsa->g);
		pamsshagentauth_buffer_put_bignum2(b, key->dsa->pub_key);
		pamsshagentauth_buffer_put_bignum2(b, key->dsa->priv_key);
#else
		pamsshagentauth_buffer_put_bignum2(b, DSA_get0_p(key->dsa));
		pamsshagentauth_buffer_put_bignum2(b, DSA_get0_q(key->dsa));
		pamsshagentauth_buffer_put_bignum2(b, DSA_get0_g(key->dsa));
		pamsshagentauth_buffer_put_bignum2(b, DSA_get0_pub_key(key->dsa));
		pamsshagentauth_buffer_put_bignum2(b, DSA_get0_priv_key(key->dsa));
#endif
		break;
	}
	pamsshagentauth_buffer_put_cstring(b, comment);
}

/*
 * Adds an identity to the authentication server.  This call is not meant to
 * be used by normal applications.
 */

int
ssh_add_identity_constrained(AuthenticationConnection *auth, Key *key,
    const char *comment, u_int life, u_int confirm)
{
	Buffer msg;
	int type, constrained = (life || confirm);

	pamsshagentauth_buffer_init(&msg);

	switch (key->type) {
	case KEY_RSA1:
		type = constrained ?
		    SSH_AGENTC_ADD_RSA_ID_CONSTRAINED :
		    SSH_AGENTC_ADD_RSA_IDENTITY;
		pamsshagentauth_buffer_put_char(&msg, type);
		ssh_encode_identity_rsa1(&msg, key->rsa, comment);
		break;
	case KEY_RSA:
	case KEY_DSA:
		type = constrained ?
		    SSH2_AGENTC_ADD_ID_CONSTRAINED :
		    SSH2_AGENTC_ADD_IDENTITY;
		pamsshagentauth_buffer_put_char(&msg, type);
		ssh_encode_identity_ssh2(&msg, key, comment);
		break;
	default:
		pamsshagentauth_buffer_free(&msg);
		return 0;
	}
	if (constrained) {
		if (life != 0) {
			pamsshagentauth_buffer_put_char(&msg, SSH_AGENT_CONSTRAIN_LIFETIME);
			pamsshagentauth_buffer_put_int(&msg, life);
		}
		if (confirm != 0)
			pamsshagentauth_buffer_put_char(&msg, SSH_AGENT_CONSTRAIN_CONFIRM);
	}
	if (ssh_request_reply(auth, &msg, &msg) == 0) {
		pamsshagentauth_buffer_free(&msg);
		return 0;
	}
	type = pamsshagentauth_buffer_get_char(&msg);
	pamsshagentauth_buffer_free(&msg);
	return pamsshagentauth_decode_reply(type);
}

int
ssh_add_identity(AuthenticationConnection *auth, Key *key, const char *comment)
{
	return ssh_add_identity_constrained(auth, key, comment, 0, 0);
}

/*
 * Removes an identity from the authentication server.  This call is not
 * meant to be used by normal applications.
 */

int
ssh_remove_identity(AuthenticationConnection *auth, Key *key)
{
	Buffer msg;
	int type;
	u_char *blob;
	u_int blen;

	pamsshagentauth_buffer_init(&msg);

	if (key->type == KEY_RSA1) {
		pamsshagentauth_buffer_put_char(&msg, SSH_AGENTC_REMOVE_RSA_IDENTITY);
#if OPENSSL_VERSION_NUMBER < 0x10100005L || defined(LIBRESSL_VERSION_NUMBER)
		pamsshagentauth_buffer_put_int(&msg, BN_num_bits(key->rsa->n));
		pamsshagentauth_buffer_put_bignum(&msg, key->rsa->e);
		pamsshagentauth_buffer_put_bignum(&msg, key->rsa->n);
#else
		pamsshagentauth_buffer_put_int(&msg, BN_num_bits(RSA_get0_n(key->rsa)));
		pamsshagentauth_buffer_put_bignum(&msg, RSA_get0_e(key->rsa));
		pamsshagentauth_buffer_put_bignum(&msg, RSA_get0_n(key->rsa));
#endif
	} else if (key->type == KEY_DSA || key->type == KEY_RSA) {
		pamsshagentauth_key_to_blob(key, &blob, &blen);
		pamsshagentauth_buffer_put_char(&msg, SSH2_AGENTC_REMOVE_IDENTITY);
		pamsshagentauth_buffer_put_string(&msg, blob, blen);
		pamsshagentauth_xfree(blob);
	} else {
		pamsshagentauth_buffer_free(&msg);
		return 0;
	}
	if (ssh_request_reply(auth, &msg, &msg) == 0) {
		pamsshagentauth_buffer_free(&msg);
		return 0;
	}
	type = pamsshagentauth_buffer_get_char(&msg);
	pamsshagentauth_buffer_free(&msg);
	return pamsshagentauth_decode_reply(type);
}

int
ssh_update_card(AuthenticationConnection *auth, int add,
    const char *reader_id, const char *pin, u_int life, u_int confirm)
{
	Buffer msg;
	int type, constrained = (life || confirm);

	if (add) {
		type = constrained ?
		    SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED :
		    SSH_AGENTC_ADD_SMARTCARD_KEY;
	} else
		type = SSH_AGENTC_REMOVE_SMARTCARD_KEY;

	pamsshagentauth_buffer_init(&msg);
	pamsshagentauth_buffer_put_char(&msg, type);
	pamsshagentauth_buffer_put_cstring(&msg, reader_id);
	pamsshagentauth_buffer_put_cstring(&msg, pin);

	if (constrained) {
		if (life != 0) {
			pamsshagentauth_buffer_put_char(&msg, SSH_AGENT_CONSTRAIN_LIFETIME);
			pamsshagentauth_buffer_put_int(&msg, life);
		}
		if (confirm != 0)
			pamsshagentauth_buffer_put_char(&msg, SSH_AGENT_CONSTRAIN_CONFIRM);
	}

	if (ssh_request_reply(auth, &msg, &msg) == 0) {
		pamsshagentauth_buffer_free(&msg);
		return 0;
	}
	type = pamsshagentauth_buffer_get_char(&msg);
	pamsshagentauth_buffer_free(&msg);
	return pamsshagentauth_decode_reply(type);
}

/*
 * Removes all identities from the agent.  This call is not meant to be used
 * by normal applications.
 */

int
ssh_remove_all_identities(AuthenticationConnection *auth, int version)
{
	Buffer msg;
	int type;
	int code = (version==1) ?
		SSH_AGENTC_REMOVE_ALL_RSA_IDENTITIES :
		SSH2_AGENTC_REMOVE_ALL_IDENTITIES;

	pamsshagentauth_buffer_init(&msg);
	pamsshagentauth_buffer_put_char(&msg, code);

	if (ssh_request_reply(auth, &msg, &msg) == 0) {
		pamsshagentauth_buffer_free(&msg);
		return 0;
	}
	type = pamsshagentauth_buffer_get_char(&msg);
	pamsshagentauth_buffer_free(&msg);
	return pamsshagentauth_decode_reply(type);
}

int
pamsshagentauth_decode_reply(int type)
{
	switch (type) {
	case SSH_AGENT_FAILURE:
	case SSH_COM_AGENT2_FAILURE:
	case SSH2_AGENT_FAILURE:
		pamsshagentauth_logit("SSH_AGENT_FAILURE");
		return 0;
	case SSH_AGENT_SUCCESS:
		return 1;
	default:
		pamsshagentauth_fatal("Bad response from authentication agent: %d", type);
	}
	/* NOTREACHED */
	return 0;
}
