/*
 * Copyright IBM Corp. 2021
 *
 * libzpc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <stdbool.h>

#include "zpc/aes_cmac.h"
#include "zpc/error.h"

#include "aes_cmac_local.h"
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

static int __aes_cmac_crypt(struct zpc_aes_cmac *, u8 *, size_t, const u8 *,
    size_t, unsigned long);
static void __aes_cmac_reset(struct zpc_aes_cmac *);
static void __aes_cmac_reset_state(struct zpc_aes_cmac *);

int
zpc_aes_cmac_alloc(struct zpc_aes_cmac **aes_cmac)
{
	struct zpc_aes_cmac *new_aes_cmac = NULL;
	int rc;

	if (pkeyfd < 0) {
		rc = ZPC_ERROR_DEVPKEY;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}
	if (!hwcaps.aes_cmac) {
		rc = ZPC_ERROR_HWCAPS;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}
	if (aes_cmac == NULL) {
		rc = ZPC_ERROR_ARG1NULL;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}

	new_aes_cmac = calloc(1, sizeof(*new_aes_cmac));
	if (new_aes_cmac == NULL) {
		rc = ZPC_ERROR_MALLOC;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}

	DEBUG("aes-cmac context at %p: allocated", new_aes_cmac);
	*aes_cmac = new_aes_cmac;
	rc = 0;
	DEBUG("return %d (%s)", rc, zpc_error_string(rc));
	return rc;
}

int
zpc_aes_cmac_set_key(struct zpc_aes_cmac *aes_cmac, struct zpc_aes_key *aes_key)
{
	int rc, rv;

	UNUSED(rv);

	if (pkeyfd < 0) {
		rc = ZPC_ERROR_DEVPKEY;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}
	if (!hwcaps.aes_cmac) {
		rc = ZPC_ERROR_HWCAPS;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}
	if (aes_cmac == NULL) {
		rc = ZPC_ERROR_ARG1NULL;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}

	if (aes_key == NULL) {
		/* If another key is already set, unset it and decrease
		 * refcount. */
		DEBUG("aes-cmac context at %p: key unset", aes_cmac);
		__aes_cmac_reset(aes_cmac);
		rc = 0;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}

	rv = pthread_mutex_lock(&aes_key->lock);
	assert(rv == 0);

	rc = aes_key_check(aes_key);
	if (rc)
		goto ret;

	if (aes_cmac->aes_key == aes_key) {
		__aes_cmac_reset_state(aes_cmac);
		DEBUG("aes-cmac context at %p: key at %p already set", aes_cmac, aes_key);
		rc = 0;
		goto ret;
	}

	aes_key->refcount++;
	DEBUG("aes key at %p: refcount %llu", aes_key, aes_key->refcount);

	if (aes_cmac->key_set) {
		/* If another key is already set, unset it and decrease
		 * refcount. */
		DEBUG("aes-cmac context at %p: key unset", aes_cmac);
		__aes_cmac_reset(aes_cmac);
	}

	/* Set new key. */
	assert(!aes_cmac->key_set);

	DEBUG("aes-cmac context at %p: key at %p set, iv unset", aes_cmac, aes_key);

	memset(&aes_cmac->param_kmac, 0, sizeof(aes_cmac->param_kmac));
	memset(&aes_cmac->param_pcc, 0, sizeof(aes_cmac->param_pcc));
	memcpy(aes_cmac->param_kmac.protkey, aes_key->prot.protkey,
	    sizeof(aes_cmac->param_kmac.protkey));
	memcpy(aes_cmac->param_pcc.protkey, aes_key->prot.protkey,
	    sizeof(aes_cmac->param_pcc.protkey));

	aes_cmac->fc = CPACF_KMAC_ENCRYPTED_AES_128 + (aes_key->keysize - 128) / 64;

	aes_cmac->aes_key = aes_key;
	aes_cmac->key_set = 1;

	rc = 0;
ret:
	rv = pthread_mutex_unlock(&aes_key->lock);
	assert(rv == 0);
	DEBUG("return %d (%s)", rc, zpc_error_string(rc));
	return rc;
}

int
zpc_aes_cmac_sign(struct zpc_aes_cmac *aes_cmac, u8 * tag, size_t taglen,
    const u8 * m, size_t mlen)
{
	struct cpacf_kmac_aes_param *param_kmac;
	struct cpacf_pcc_cmac_aes_param *param_pcc;
	struct pkey_protkey *protkey;
	unsigned long flags = 0;
	int rc, rv, i;

	UNUSED(rv);

	if (pkeyfd < 0) {
		rc = ZPC_ERROR_DEVPKEY;
		goto ret;
	}
	if (!hwcaps.aes_cmac) {
		rc = ZPC_ERROR_HWCAPS;
		goto ret;
	}
	if (aes_cmac == NULL) {
		rc = ZPC_ERROR_ARG1NULL;
		goto ret;
	}

	/* Valid tag byte-lengths: >= 8, <= 16. */
	if (taglen > 0 && tag == NULL) {
		rc = ZPC_ERROR_ARG2NULL;
		goto ret;
	}
	if (tag != NULL && (taglen > 16 || taglen < 8)) {
		rc = ZPC_ERROR_TAGSIZE;
		goto ret;
	}

	if (mlen > 0 && mlen % 16 != 0 && tag == NULL) {
		rc = ZPC_ERROR_ARG5RANGE;
		goto ret;
	}

	if (!aes_cmac->key_set) {
		rc = ZPC_ERROR_KEYNOTSET;
		goto ret;
	}

	rc = -1;
	for (i = 0; i < 2 && rc != 0; i++) {
		assert(i == AES_KEY_SEC_CUR || i == AES_KEY_SEC_OLD);

		protkey = &aes_cmac->aes_key->prot;
		param_kmac = &aes_cmac->param_kmac;
		param_pcc = &aes_cmac->param_pcc;

		for (;;) {
			rc = __aes_cmac_crypt(aes_cmac, tag, taglen, m, mlen, flags);
			if (rc == 0) {
				break;
			} else {
				if (aes_cmac->aes_key->rand_protk) {
					rc = ZPC_ERROR_PROTKEYONLY;
					goto ret;
				}
				if (rc == ZPC_ERROR_WKVPMISMATCH) {
					rv = pthread_mutex_lock(&aes_cmac->aes_key->lock);
					assert(rv == 0);

					DEBUG
					    ("aes-cmac context at %p: re-derive protected key from %s secure key from aes key at %p",
					    aes_cmac, i == 0 ? "current" : "old", aes_cmac->aes_key);
					rc = aes_key_sec2prot(aes_cmac->aes_key, i);
					memcpy(param_kmac->protkey, protkey->protkey, sizeof(param_kmac->protkey));
					memcpy(param_pcc->protkey, protkey->protkey, sizeof(param_pcc->protkey));

					rv = pthread_mutex_unlock(&aes_cmac->aes_key->lock);
					assert(rv == 0);
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
zpc_aes_cmac_verify(struct zpc_aes_cmac *aes_cmac, const u8 * tag,
    size_t taglen, const u8 * m, size_t mlen)
{
	struct cpacf_kmac_aes_param *param_kmac;
	struct cpacf_pcc_cmac_aes_param *param_pcc;
	struct pkey_protkey *protkey;
	unsigned long flags = 0;
	int rc, rv, i;
	u8 tmp[16];

	UNUSED(rv);

	if (pkeyfd < 0) {
		rc = ZPC_ERROR_DEVPKEY;
		goto ret;
	}
	if (!hwcaps.aes_cmac) {
		rc = ZPC_ERROR_HWCAPS;
		goto ret;
	}
	if (aes_cmac == NULL) {
		rc = ZPC_ERROR_ARG1NULL;
		goto ret;
	}

	/* Valid tag byte-lengths: >= 8, <= 16. */
	if (taglen > 0 && tag == NULL) {
		rc = ZPC_ERROR_ARG2NULL;
		goto ret;
	}
	if (tag != NULL && (taglen > 16 || taglen < 8)) {
		rc = ZPC_ERROR_TAGSIZE;
		goto ret;
	}

	if (mlen > 0 && mlen % 16 != 0 && tag == NULL) {
		rc = ZPC_ERROR_ARG5RANGE;
		goto ret;
	}

	if (!aes_cmac->key_set) {
		rc = ZPC_ERROR_KEYNOTSET;
		goto ret;
	}

	rc = -1;
	for (i = 0; i < 2 && (rc != 0 && rc != ZPC_ERROR_TAGMISMATCH); i++) {
		assert(i == AES_KEY_SEC_CUR || i == AES_KEY_SEC_OLD);

		protkey = &aes_cmac->aes_key->prot;
		param_kmac = &aes_cmac->param_kmac;
		param_pcc = &aes_cmac->param_pcc;

		for (;;) {
			rc = __aes_cmac_crypt(aes_cmac,
			    tag == NULL ? NULL : tmp,
			    tag == NULL ? 0 : sizeof(tmp), m, mlen, flags);
			if (rc == 0) {
				if (tag != NULL) {
					rc = memcmp_consttime(tmp, tag, taglen);
					if (rc != 0)
						rc = ZPC_ERROR_TAGMISMATCH;
				}
				break;
			} else {
				if (aes_cmac->aes_key->rand_protk) {
					rc = ZPC_ERROR_PROTKEYONLY;
					goto ret;
				}
				if (rc == ZPC_ERROR_WKVPMISMATCH) {
					rv = pthread_mutex_lock(&aes_cmac->aes_key->lock);
					assert(rv == 0);

					DEBUG
					    ("aes-cmac context at %p: re-derive protected key from %s secure key from aes key at %p",
					    aes_cmac, i == 0 ? "current" : "old", aes_cmac->aes_key);
					rc = aes_key_sec2prot(aes_cmac->aes_key, i);
					memcpy(param_kmac->protkey, protkey->protkey, sizeof(param_kmac->protkey));
					memcpy(param_pcc->protkey, protkey->protkey, sizeof(param_pcc->protkey));

					rv = pthread_mutex_unlock(&aes_cmac->aes_key->lock);
					assert(rv == 0);
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
zpc_aes_cmac_free(struct zpc_aes_cmac **aes_cmac)
{
	if (aes_cmac == NULL)
		return;
	if (*aes_cmac == NULL)
		return;

	if ((*aes_cmac)->key_set) {
		/* Decrease aes_key's refcount. */
		zpc_aes_key_free(&(*aes_cmac)->aes_key);
		(*aes_cmac)->key_set = 0;
	}

	__aes_cmac_reset(*aes_cmac);

	free(*aes_cmac);
	*aes_cmac = NULL;
	DEBUG("return");
}

static int
__aes_cmac_crypt(struct zpc_aes_cmac *aes_cmac, u8 * tag, size_t taglen,
    const u8 * in, size_t inlen, unsigned long flags)
{
	size_t rem;
	int rc, cc;

	assert(aes_cmac != NULL);
	assert((tag != NULL) || (tag == NULL && inlen % 16 == 0));
	assert((tag == NULL) || (8 <= taglen && taglen <= 16));

	rem = inlen & 0xf;
	inlen &= ~(size_t)0xf;
	if (tag != NULL && rem == 0 && inlen >= 16) {
		inlen -= 16;
		rem += 16;
	}
	if (inlen) {
		cc = cpacf_kmac(aes_cmac->fc | flags, &aes_cmac->param_kmac, in, inlen);
		assert(cc == 0 || cc == 1);
		if (cc == 1) {
			rc = ZPC_ERROR_WKVPMISMATCH;
			goto err;
		}
		in += inlen;
	}
	if (tag != NULL) {
		aes_cmac->param_pcc.ml = rem * 8;
		memset(aes_cmac->param_pcc.message, 0,
		    sizeof(aes_cmac->param_pcc.message));
		memcpy(aes_cmac->param_pcc.message, in, rem);
		memcpy(aes_cmac->param_pcc.icv, aes_cmac->param_kmac.icv,
		    sizeof(aes_cmac->param_pcc.icv));

		cc = cpacf_pcc(aes_cmac->fc | flags, &aes_cmac->param_pcc);
		assert(cc == 0 || cc == 1);
		if (cc == 1) {
			rc = ZPC_ERROR_WKVPMISMATCH;
			goto err;
		}
		memcpy(tag, aes_cmac->param_pcc.icv, taglen);

		__aes_cmac_reset_state(aes_cmac);
	}
	rc = 0;
err:
	return rc;
}

static void
__aes_cmac_reset(struct zpc_aes_cmac *aes_cmac)
{
	assert(aes_cmac != NULL);

	__aes_cmac_reset_state(aes_cmac);
	memset(&aes_cmac->param_kmac, 0, sizeof(aes_cmac->param_kmac));
	memset(&aes_cmac->param_pcc, 0, sizeof(aes_cmac->param_pcc));

	if (aes_cmac->aes_key != NULL)
		zpc_aes_key_free(&aes_cmac->aes_key);
	aes_cmac->key_set = 0;

	aes_cmac->fc = 0;
}

static void
__aes_cmac_reset_state(struct zpc_aes_cmac *aes_cmac)
{
	assert(aes_cmac != NULL);

	memset(aes_cmac->param_kmac.icv, 0, sizeof(aes_cmac->param_kmac.icv));
	memset(&aes_cmac->param_pcc.icv, 0, sizeof(aes_cmac->param_pcc.icv));
	memset(&aes_cmac->param_pcc.message, 0, sizeof(aes_cmac->param_pcc.message));
	aes_cmac->param_pcc.ml = 0;
}
