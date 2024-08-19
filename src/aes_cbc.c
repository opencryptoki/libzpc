/*
 * Copyright IBM Corp. 2021
 *
 * libzpc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <stdbool.h>

#include "zpc/aes_cbc.h"
#include "zpc/error.h"

#include "aes_cbc_local.h"
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

static void __aes_cbc_set_iv(struct zpc_aes_cbc *, const u8 iv[16]);
static int __aes_cbc_crypt(struct zpc_aes_cbc *, u8 *, const u8 *, size_t,
    unsigned long, size_t *);
static void __aes_cbc_reset(struct zpc_aes_cbc *);
static void __aes_cbc_reset_iv(struct zpc_aes_cbc *);

int
zpc_aes_cbc_alloc(struct zpc_aes_cbc **aes_cbc)
{
	struct zpc_aes_cbc *new_aes_cbc = NULL;
	int rc;

	if (pkeyfd < 0) {
		rc = ZPC_ERROR_DEVPKEY;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}
	if (!hwcaps.aes_cbc) {
		rc = ZPC_ERROR_HWCAPS;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}
	if (aes_cbc == NULL) {
		rc = ZPC_ERROR_ARG1NULL;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}

	new_aes_cbc = calloc(1, sizeof(*new_aes_cbc));
	if (new_aes_cbc == NULL) {
		rc = ZPC_ERROR_MALLOC;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}

	DEBUG("aes-cbc context at %p: allocated", new_aes_cbc);
	*aes_cbc = new_aes_cbc;
	rc = 0;
	DEBUG("return %d (%s)", rc, zpc_error_string(rc));
	return rc;
}

int
zpc_aes_cbc_set_key(struct zpc_aes_cbc *aes_cbc, struct zpc_aes_key *aes_key)
{
	int rc, rv;

	UNUSED(rv);

	if (pkeyfd < 0) {
		rc = ZPC_ERROR_DEVPKEY;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}
	if (!hwcaps.aes_cbc) {
		rc = ZPC_ERROR_HWCAPS;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}
	if (aes_cbc == NULL) {
		rc = ZPC_ERROR_ARG1NULL;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}

	if (aes_key == NULL) {
		/* If another key is already set, unset it and decrease
		 * refcount. */
		DEBUG("aes-cbc context at %p: key unset", aes_cbc);
		__aes_cbc_reset(aes_cbc);
		rc = 0;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}

	rv = pthread_mutex_lock(&aes_key->lock);
	assert(rv == 0);

	rc = aes_key_check(aes_key);
	if (rc)
		goto ret;

	if (aes_cbc->aes_key == aes_key) {
		DEBUG("aes-cbc context at %p: key at %p already set", aes_cbc, aes_key);
		rc = 0; /* nothing to do */
		goto ret;
	}

	aes_key->refcount++;
	DEBUG("aes key at %p: refcount %llu", aes_key, aes_key->refcount);

	if (aes_cbc->key_set) {
		/* If another key is already set, unset it and decrease
		 * refcount. */
		DEBUG("aes-cbc context at %p: key unset", aes_cbc);
		__aes_cbc_reset(aes_cbc);
	}

	/* Set new key. */
	assert(!aes_cbc->key_set);

	DEBUG("aes-cbc context at %p: key at %p set", aes_cbc, aes_key);

	memcpy(aes_cbc->param.protkey, aes_key->prot.protkey, sizeof(aes_cbc->param.protkey));

	aes_cbc->fc = CPACF_KMC_ENCRYPTED_AES_128 + (aes_key->keysize - 128) / 64;

	aes_cbc->aes_key = aes_key;
	aes_cbc->key_set = 1;

	rc = 0;
ret:
	rv = pthread_mutex_unlock(&aes_key->lock);
	assert(rv == 0);
	DEBUG("return %d (%s)", rc, zpc_error_string(rc));
	return rc;
}

int
zpc_aes_cbc_set_iv(struct zpc_aes_cbc *aes_cbc, const u8 * iv)
{
	int rc, rv;

	UNUSED(rv);

	if (pkeyfd < 0) {
		rc = ZPC_ERROR_DEVPKEY;
		goto ret;
	}
	if (!hwcaps.aes_cbc) {
		rc = ZPC_ERROR_HWCAPS;
		goto ret;
	}
	if (aes_cbc == NULL) {
		rc = ZPC_ERROR_ARG1NULL;
		goto ret;
	}
	if (iv == NULL) {
		/* Unset iv */
		DEBUG("aes-cbc context at %p: iv unset", aes_cbc);
		__aes_cbc_reset_iv(aes_cbc);
		aes_cbc->iv_set = 0;
		rc = 0;
		goto ret;
	}

	if (aes_cbc->key_set != 1) {
		rc = ZPC_ERROR_KEYNOTSET;
		goto ret;
	}

	__aes_cbc_set_iv(aes_cbc, iv);
	DEBUG("aes-cbc context at %p: iv set", aes_cbc);
	aes_cbc->iv_set = 1;
	rc = 0;
ret:
	DEBUG("return %d (%s)", rc, zpc_error_string(rc));
	return rc;
}

int
zpc_aes_cbc_get_intermediate_iv(struct zpc_aes_cbc *aes_cbc, unsigned char iv[16])
{
	int rc;

	if (pkeyfd < 0) {
		rc = ZPC_ERROR_DEVPKEY;
		goto ret;
	}
	if (!hwcaps.aes_cbc) {
		rc = ZPC_ERROR_HWCAPS;
		goto ret;
	}
	if (aes_cbc == NULL) {
		rc = ZPC_ERROR_ARG1NULL;
		goto ret;
	}

	if (iv == NULL) {
		rc = ZPC_ERROR_ARG2NULL;
		goto ret;
	}

	if (aes_cbc->iv_set != 1) {
		rc = ZPC_ERROR_IVNOTSET;
		goto ret;
	}

	memcpy(iv, aes_cbc->param.cv, 16);
	rc = 0;

ret:
	DEBUG("return %d (%s)", rc, zpc_error_string(rc));
	return rc;
}

int
zpc_aes_cbc_set_intermediate_iv(struct zpc_aes_cbc *aes_cbc, const unsigned char iv[16])
{
	int rc;

	if (pkeyfd < 0) {
		rc = ZPC_ERROR_DEVPKEY;
		goto ret;
	}
	if (!hwcaps.aes_cbc) {
		rc = ZPC_ERROR_HWCAPS;
		goto ret;
	}
	if (aes_cbc == NULL) {
		rc = ZPC_ERROR_ARG1NULL;
		goto ret;
	}
	if (iv == NULL) {
		rc = ZPC_ERROR_ARG2NULL;
		goto ret;
	}

	if (aes_cbc->key_set != 1) {
		rc = ZPC_ERROR_KEYNOTSET;
		goto ret;
	}

	if (aes_cbc->iv_set != 1) {
		rc = ZPC_ERROR_IVNOTSET;
		goto ret;
	}

	__aes_cbc_set_iv(aes_cbc, iv);
	DEBUG("aes-cbc context at %p: intermediate iv set", aes_cbc);
	aes_cbc->iv_set = 1;
	rc = 0;
ret:
	DEBUG("return %d (%s)", rc, zpc_error_string(rc));
	return rc;
}

int
zpc_aes_cbc_encrypt(struct zpc_aes_cbc *aes_cbc, u8 * c, const u8 * m,
    size_t mlen)
{
	struct cpacf_kmc_aes_param *param;
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
	if (!hwcaps.aes_cbc) {
		rc = ZPC_ERROR_HWCAPS;
		goto ret;
	}
	if (aes_cbc == NULL) {
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

	if (!aes_cbc->key_set) {
		rc = ZPC_ERROR_KEYNOTSET;
		goto ret;
	}
	if (!aes_cbc->iv_set) {
		rc = ZPC_ERROR_IVNOTSET;
		goto ret;
	}

	rc = -1;
	for (i = 0; i < 2 && rc != 0; i++) {
		assert(i == AES_KEY_SEC_CUR || i == AES_KEY_SEC_OLD);

		protkey = &aes_cbc->aes_key->prot;
		param = &aes_cbc->param;

		for (;;) {
			rc = __aes_cbc_crypt(aes_cbc, out_pos, in_pos, len, flags, &bytes_processed);
			if (rc == 0) {
				break;
			} else {
				if (aes_cbc->aes_key->rand_protk) {
					rc = ZPC_ERROR_PROTKEYONLY;
					goto ret;
				}
				if (rc == ZPC_ERROR_WKVPMISMATCH) {
					rv = pthread_mutex_lock(&aes_cbc->aes_key->lock);
					assert(rv == 0);

					DEBUG
					    ("aes-cbc context at %p: re-derive protected key from %s secure key from aes key at %p",
					    aes_cbc, i == 0 ? "current" : "old", aes_cbc->aes_key);
					rc = aes_key_sec2prot(aes_cbc->aes_key, i);
					memcpy(param->protkey, protkey->protkey, sizeof(param->protkey));

					rv = pthread_mutex_unlock(&aes_cbc->aes_key->lock);
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
zpc_aes_cbc_decrypt(struct zpc_aes_cbc *aes_cbc, u8 * m, const u8 * c,
    size_t clen)
{
	struct cpacf_kmc_aes_param *param;
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
	if (!hwcaps.aes_cbc) {
		rc = ZPC_ERROR_HWCAPS;
		goto ret;
	}
	if (aes_cbc == NULL) {
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

	if (!aes_cbc->key_set) {
		rc = ZPC_ERROR_KEYNOTSET;
		goto ret;
	}
	if (!aes_cbc->iv_set) {
		rc = ZPC_ERROR_IVNOTSET;
		goto ret;
	}

	rc = -1;
	for (i = 0; i < 2 && rc != 0; i++) {
		assert(i == AES_KEY_SEC_CUR || i == AES_KEY_SEC_OLD);

		protkey = &aes_cbc->aes_key->prot;
		param = &aes_cbc->param;

		for (;;) {
			rc = __aes_cbc_crypt(aes_cbc, out_pos, in_pos, len, flags, &bytes_processed);
			if (rc == 0) {
				break;
			} else {
				if (aes_cbc->aes_key->rand_protk) {
					rc = ZPC_ERROR_PROTKEYONLY;
					goto ret;
				}
				if (rc == ZPC_ERROR_WKVPMISMATCH) {
					rv = pthread_mutex_lock(&aes_cbc->aes_key->lock);
					assert(rv == 0);

					DEBUG
					    ("aes-cbc context at %p: re-derive protected key from %s secure key from aes key at %p",
					    aes_cbc, i == 0 ? "current" : "old", aes_cbc->aes_key);
					rc = aes_key_sec2prot(aes_cbc->aes_key, i);
					memcpy(param->protkey, protkey->protkey, sizeof(param->protkey));

					rv = pthread_mutex_unlock(&aes_cbc->aes_key->lock);
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
zpc_aes_cbc_free(struct zpc_aes_cbc **aes_cbc)
{
	if (aes_cbc == NULL)
		return;
	if (*aes_cbc == NULL)
		return;

	if ((*aes_cbc)->key_set) {
		/* Decrease aes_key's refcount. */
		zpc_aes_key_free(&(*aes_cbc)->aes_key);
		(*aes_cbc)->key_set = 0;
		__aes_cbc_reset_iv(*aes_cbc);
		(*aes_cbc)->iv_set = 0;
	}

	__aes_cbc_reset(*aes_cbc);

	free(*aes_cbc);
	*aes_cbc = NULL;
	DEBUG("return");
}

static void
__aes_cbc_set_iv(struct zpc_aes_cbc *aes_cbc, const u8 iv[16])
{
	assert(aes_cbc != NULL);
	assert(iv != NULL);

	memcpy(aes_cbc->param.cv, iv, 16);
}

static int
__aes_cbc_crypt(struct zpc_aes_cbc *aes_cbc, u8 * out, const u8 * in,
    size_t inlen, unsigned long flags, size_t *bytes_processed)
{
	struct cpacf_kmc_aes_param *param;
	int rc, cc;

	param = &aes_cbc->param;

	cc = cpacf_kmc(aes_cbc->fc | flags, param, out, in, inlen, bytes_processed);
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
__aes_cbc_reset(struct zpc_aes_cbc *aes_cbc)
{
	assert(aes_cbc != NULL);

	memset(&aes_cbc->param, 0, sizeof(aes_cbc->param));

	__aes_cbc_reset_iv(aes_cbc);
	aes_cbc->iv_set = 0;

	if (aes_cbc->aes_key != NULL)
		zpc_aes_key_free(&aes_cbc->aes_key);
	aes_cbc->key_set = 0;

	aes_cbc->fc = 0;
}

static void
__aes_cbc_reset_iv(struct zpc_aes_cbc *aes_cbc)
{
	assert(aes_cbc != NULL);

	memset(aes_cbc->param.cv, 0, sizeof(aes_cbc->param.cv));
	aes_cbc->iv_set = 0;
}
