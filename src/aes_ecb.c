/*
 * Copyright IBM Corp. 2021
 *
 * libzpc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <stdbool.h>

#include "zpc/aes_ecb.h"
#include "zpc/error.h"

#include "aes_ecb_local.h"
#include "aes_key_local.h"
#include "cpacf.h"
#include "globals.h"
#include "misc.h"
#include "debug.h"
#include "zkey/pkey.h"

#include <assert.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static int __aes_ecb_crypt(struct zpc_aes_ecb *, u8 *, const u8 *, size_t,
    unsigned long, size_t *);
static void __aes_ecb_reset(struct zpc_aes_ecb *);

int
zpc_aes_ecb_alloc(struct zpc_aes_ecb **aes_ecb)
{
	struct zpc_aes_ecb *new_aes_ecb = NULL;
	int rc;

	if (pkeyfd < 0) {
		rc = ZPC_ERROR_DEVPKEY;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}
	if (!hwcaps.aes_ecb) {
		rc = ZPC_ERROR_HWCAPS;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}
	if (aes_ecb == NULL) {
		rc = ZPC_ERROR_ARG1NULL;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}

	new_aes_ecb = calloc(1, sizeof(*new_aes_ecb));
	if (new_aes_ecb == NULL) {
		rc = ZPC_ERROR_MALLOC;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}

	DEBUG("aes-ecb context at %p: allocated", new_aes_ecb);
	*aes_ecb = new_aes_ecb;
	rc = 0;
	DEBUG("return %d (%s)", rc, zpc_error_string(rc));
	return rc;
}

int
zpc_aes_ecb_set_key(struct zpc_aes_ecb *aes_ecb, struct zpc_aes_key *aes_key)
{
	int rc, rv;

	UNUSED(rv);

	if (pkeyfd < 0) {
		rc = ZPC_ERROR_DEVPKEY;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}
	if (!hwcaps.aes_ecb) {
		rc = ZPC_ERROR_HWCAPS;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}
	if (aes_ecb == NULL) {
		rc = ZPC_ERROR_ARG1NULL;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}

	if (aes_key == NULL) {
		/* If another key is already set, unset it and decrease
		 * refcount. */
		DEBUG("aes-ecb context at %p: key unset", aes_ecb);
		__aes_ecb_reset(aes_ecb);
		rc = 0;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}

	rv = pthread_mutex_lock(&aes_key->lock);
	assert(rv == 0);

	rc = aes_key_check(aes_key);
	if (rc)
		goto ret;

	if (aes_ecb->aes_key == aes_key) {
		DEBUG("aes-ecb context at %p: key at %p already set", aes_ecb, aes_key);
		rc = 0; /* nothing to do */
		goto ret;
	}

	aes_key->refcount++;
	DEBUG("aes key at %p: refcount %llu", aes_key, aes_key->refcount);

	if (aes_ecb->key_set) {
		/* If another key is already set, unset it and decrease
		 * refcount. */
		DEBUG("aes-ecb context at %p: key unset", aes_ecb);
		__aes_ecb_reset(aes_ecb);
	}

	/* Set new key. */
	assert(!aes_ecb->key_set);

	DEBUG("aes-ecb context at %p: key at %p set", aes_ecb, aes_key);

	memcpy(aes_ecb->param.protkey, aes_key->prot.protkey,
	    sizeof(aes_ecb->param.protkey));

	aes_ecb->fc = CPACF_KM_ENCRYPTED_AES_128 + (aes_key->keysize - 128) / 64;

	aes_ecb->aes_key = aes_key;
	aes_ecb->key_set = 1;

	rc = 0;
ret:
	rv = pthread_mutex_unlock(&aes_key->lock);
	assert(rv == 0);
	DEBUG("return %d (%s)", rc, zpc_error_string(rc));
	return rc;
}

int
zpc_aes_ecb_encrypt(struct zpc_aes_ecb *aes_ecb, u8 * c, const u8 * m,
    size_t mlen)
{
	struct cpacf_km_aes_param *param;
	struct pkey_protkey *protkey;
	unsigned long flags = 0;
	int rc, rv, i;
	const u8 *in_pos = m;
	u8 *out_pos = c;
	size_t bytes_processed = 0, len = mlen;

	UNUSED(rv);

	if (pkeyfd < 0) {
		rc = ZPC_ERROR_DEVPKEY;
		goto ret;
	}
	if (!hwcaps.aes_ecb) {
		rc = ZPC_ERROR_HWCAPS;
		goto ret;
	}
	if (aes_ecb == NULL) {
		rc = ZPC_ERROR_ARG1NULL;
		goto ret;
	}

	if ((mlen > 0 || m != NULL) && c == NULL) {
		rc = ZPC_ERROR_ARG2NULL;
		goto ret;
	}
	if ((mlen > 0 || c != NULL) && m == NULL) {
		rc = ZPC_ERROR_ARG3NULL;
		goto ret;
	}
	if (mlen % 16 != 0) {
		rc = ZPC_ERROR_MLEN;
		goto ret;
	}

	if (!aes_ecb->key_set) {
		rc = ZPC_ERROR_KEYNOTSET;
		goto ret;
	}

	rc = -1;
	for (i = 0; i < 2 && rc != 0; i++) {
		assert(i == AES_KEY_SEC_CUR || i == AES_KEY_SEC_OLD);

		protkey = &aes_ecb->aes_key->prot;
		param = &aes_ecb->param;

		for (;;) {
			rc = __aes_ecb_crypt(aes_ecb, out_pos, in_pos, len, flags, &bytes_processed);
			if (rc == 0) {
				break;
			} else {
				if (aes_ecb->aes_key->rand_protk) {
					rc = ZPC_ERROR_PROTKEYONLY;
					goto ret;
				}
				if (rc == ZPC_ERROR_WKVPMISMATCH) {
					rv = pthread_mutex_lock(&aes_ecb->aes_key->lock);
					assert(rv == 0);

					DEBUG
					    ("aes-ecb context at %p: re-derive protected key from %s secure key from aes key at %p",
					    aes_ecb, i == 0 ? "current" : "old", aes_ecb->aes_key);
					rc = aes_key_sec2prot(aes_ecb->aes_key, i);
					memcpy(param->protkey, protkey->protkey, sizeof(param->protkey));

					rv = pthread_mutex_unlock(&aes_ecb->aes_key->lock);
					assert(rv == 0);

					in_pos += bytes_processed;
					out_pos += bytes_processed;
					len -= bytes_processed;
				}
				if (rc)
					break;
			}
		}
	}

ret:
	DEBUG("return %d (%s)", rc, zpc_error_string(rc));
	return rc;
}

int
zpc_aes_ecb_decrypt(struct zpc_aes_ecb *aes_ecb, u8 * m, const u8 * c,
    size_t clen)
{
	struct cpacf_km_aes_param *param;
	struct pkey_protkey *protkey;
	unsigned long flags = CPACF_M;  /* decrypt */
	int rc, rv, i;
	const u8 *in_pos = c;
	u8 *out_pos = m;
	size_t bytes_processed = 0, len = clen;

	UNUSED(rv);

	if (pkeyfd < 0) {
		rc = ZPC_ERROR_DEVPKEY;
		goto ret;
	}
	if (!hwcaps.aes_ecb) {
		rc = ZPC_ERROR_HWCAPS;
		goto ret;
	}
	if (aes_ecb == NULL) {
		rc = ZPC_ERROR_ARG1NULL;
		goto ret;
	}

	if ((clen > 0 || c != NULL) && m == NULL) {
		rc = ZPC_ERROR_ARG2NULL;
		goto ret;
	}
	if ((clen > 0 || m != NULL) && c == NULL) {
		rc = ZPC_ERROR_ARG3NULL;
		goto ret;
	}
	if (clen % 16 != 0) {
		rc = ZPC_ERROR_CLEN;
		goto ret;
	}

	if (!aes_ecb->key_set) {
		rc = ZPC_ERROR_KEYNOTSET;
		goto ret;
	}

	rc = -1;
	for (i = 0; i < 2 && rc != 0; i++) {
		assert(i == AES_KEY_SEC_CUR || i == AES_KEY_SEC_OLD);

		protkey = &aes_ecb->aes_key->prot;
		param = &aes_ecb->param;

		for (;;) {
			rc = __aes_ecb_crypt(aes_ecb, out_pos, in_pos, len, flags, &bytes_processed);
			if (rc == 0) {
				break;
			} else {
				if (aes_ecb->aes_key->rand_protk) {
					rc = ZPC_ERROR_PROTKEYONLY;
					goto ret;
				}
				if (rc == ZPC_ERROR_WKVPMISMATCH) {
					rv = pthread_mutex_lock(&aes_ecb->aes_key->lock);
					assert(rv == 0);

					DEBUG
					    ("aes-ecb context at %p: re-derive protected key from %s secure key from aes key at %p",
					    aes_ecb, i == 0 ? "current" : "old", aes_ecb->aes_key);
					rc = aes_key_sec2prot(aes_ecb->aes_key, i);
					memcpy(param->protkey, protkey->protkey, sizeof(param->protkey));

					rv = pthread_mutex_unlock(&aes_ecb->aes_key->lock);
					assert(rv == 0);

					in_pos += bytes_processed;
					out_pos += bytes_processed;
					len -= bytes_processed;
				}
				if (rc)
					break;
			}
		}
	}

ret:
	DEBUG("return %d (%s)", rc, zpc_error_string(rc));
	return rc;
}

void
zpc_aes_ecb_free(struct zpc_aes_ecb **aes_ecb)
{
	if (aes_ecb == NULL)
		return;
	if (*aes_ecb == NULL)
		return;

	if ((*aes_ecb)->key_set) {
		/* Decrease aes_key's refcount. */
		zpc_aes_key_free(&(*aes_ecb)->aes_key);
		(*aes_ecb)->key_set = 0;
	}

	__aes_ecb_reset(*aes_ecb);

	free(*aes_ecb);
	*aes_ecb = NULL;
	DEBUG("return");
}

static int
__aes_ecb_crypt(struct zpc_aes_ecb *aes_ecb, u8 * out, const u8 * in,
    size_t inlen, unsigned long flags, size_t *bytes_processed)
{
	struct cpacf_km_aes_param *param;
	int rc, cc;

	param = &aes_ecb->param;

	cc = cpacf_km(aes_ecb->fc | flags, param, out, in, inlen, bytes_processed);
	assert(cc == 0 || cc == 1 || cc == 2);
	if (cc == 1) {
		rc = ZPC_ERROR_WKVPMISMATCH;
		goto err;
	}

	rc = 0;
err:
	return rc;
}

static void
__aes_ecb_reset(struct zpc_aes_ecb *aes_ecb)
{
	assert(aes_ecb != NULL);

	memset(&aes_ecb->param, 0, sizeof(aes_ecb->param));

	if (aes_ecb->aes_key != NULL)
		zpc_aes_key_free(&aes_ecb->aes_key);
	aes_ecb->key_set = 0;

	aes_ecb->fc = 0;
}
