/*
 * Copyright IBM Corp. 2021
 *
 * libzpc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <stdbool.h>

#include "zpc/aes_gcm.h"
#include "zpc/error.h"

#include "aes_gcm_local.h"
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

static int __aes_gcm_set_iv(struct zpc_aes_gcm *, const u8 *, size_t);
static int __aes_gcm_crypt(struct zpc_aes_gcm *, u8 *, u8 *, size_t, const u8 *,
    size_t, const u8 *, size_t, unsigned long);
static void __aes_gcm_reset(struct zpc_aes_gcm *);
static void __aes_gcm_reset_iv(struct zpc_aes_gcm *);

int
zpc_aes_gcm_alloc(struct zpc_aes_gcm **aes_gcm)
{
	struct zpc_aes_gcm *new_aes_gcm = NULL;
	int rc;

	if (pkeyfd < 0) {
		rc = ZPC_ERROR_DEVPKEY;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}
	if (!hwcaps.aes_gcm) {
		rc = ZPC_ERROR_HWCAPS;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}
	if (aes_gcm == NULL) {
		rc = ZPC_ERROR_ARG1NULL;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}

	new_aes_gcm = calloc(1, sizeof(*new_aes_gcm));
	if (new_aes_gcm == NULL) {
		rc = ZPC_ERROR_MALLOC;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}

	DEBUG("aes-gcm context at %p: allocated", new_aes_gcm);
	*aes_gcm = new_aes_gcm;
	rc = 0;
	DEBUG("return %d (%s)", rc, zpc_error_string(rc));
	return rc;
}

int
zpc_aes_gcm_set_key(struct zpc_aes_gcm *aes_gcm, struct zpc_aes_key *aes_key)
{
	int rc, rv;

	UNUSED(rv);

	if (pkeyfd < 0) {
		rc = ZPC_ERROR_DEVPKEY;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}
	if (!hwcaps.aes_gcm) {
		rc = ZPC_ERROR_HWCAPS;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}
	if (aes_gcm == NULL) {
		rc = ZPC_ERROR_ARG1NULL;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}

	if (aes_key == NULL) {
		/* If another key is already set, unset it and decrease
		 * refcount. */
		DEBUG("aes-gcm context at %p: key unset", aes_gcm);
		__aes_gcm_reset(aes_gcm);
		rc = 0;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}

	rv = pthread_mutex_lock(&aes_key->lock);
	assert(rv == 0);

	rc = aes_key_check(aes_key);
	if (rc)
		goto ret;

	if (aes_gcm->aes_key == aes_key) {
		DEBUG("aes-gcm context at %p: key at %p already set", aes_gcm,
		    aes_key);
		rc = 0; /* nothing to do */
		goto ret;
	}

	aes_key->refcount++;
	DEBUG("aes key at %p: refcount %llu", aes_key, aes_key->refcount);

	if (aes_gcm->key_set) {
		/* If another key is already set, unset it and decrease
		 * refcount. */
		DEBUG("aes-gcm context at %p: key unset", aes_gcm);
		__aes_gcm_reset(aes_gcm);
	}

	/* Set new key. */
	assert(!aes_gcm->key_set);

	DEBUG("aes-gcm context at %p: key at %p set, iv unset", aes_gcm,
	    aes_key);

	memcpy(aes_gcm->param.protkey, aes_key->prot.protkey,
	    sizeof(aes_gcm->param.protkey));

	aes_gcm->fc =
	    CPACF_KMA_GCM_ENCRYPTED_AES_128 + (aes_key->keysize - 128) / 64;

	aes_gcm->aes_key = aes_key;
	aes_gcm->key_set = 1;

	__aes_gcm_reset_iv(aes_gcm);
	aes_gcm->iv_set = 0;

	rc = 0;
ret:
	rv = pthread_mutex_unlock(&aes_key->lock);
	assert(rv == 0);
	DEBUG("return %d (%s)", rc, zpc_error_string(rc));
	return rc;
}

int
zpc_aes_gcm_set_iv(struct zpc_aes_gcm *aes_gcm, const u8 * iv, size_t ivlen)
{
	struct cpacf_kma_gcm_aes_param *param;
	struct pkey_protkey *protkey;
	int rc, rv, i;

	UNUSED(rv);

	if (pkeyfd < 0) {
		rc = ZPC_ERROR_DEVPKEY;
		goto ret;
	}
	if (!hwcaps.aes_gcm) {
		rc = ZPC_ERROR_HWCAPS;
		goto ret;
	}
	if (aes_gcm == NULL) {
		rc = ZPC_ERROR_ARG1NULL;
		goto ret;
	}
	if (iv == NULL) {
		/* Unset iv */
		DEBUG("aes-gcm context at %p: iv unset", aes_gcm);
		__aes_gcm_reset_iv(aes_gcm);
		aes_gcm->iv_set = 0;
		rc = 0;
		goto ret;
	}
	/* 1 <= iv bit-length <= 2^64 - 1, iv bit-length % 8 == 0 */
	if (ivlen < 1 || ivlen > SIZE_MAX - 16) {
		rc = ZPC_ERROR_IVSIZE;
		goto ret;
	}

	if (aes_gcm->key_set != 1) {
		rc = ZPC_ERROR_KEYNOTSET;
		goto ret;
	}

	rc = -1;
	for (i = 0; i < 2 && rc != 0; i++) {
		assert(i == AES_KEY_SEC_CUR || i == AES_KEY_SEC_OLD);

		protkey = &aes_gcm->aes_key->prot;
		param = &aes_gcm->param;

		for (;;) {
			rc = __aes_gcm_set_iv(aes_gcm, iv, ivlen);
			if (rc == 0) {
				break;
			} else {
				if (aes_gcm->aes_key->rand_protk) {
					rc = ZPC_ERROR_PROTKEYONLY;
					goto ret;
				}
				if (rc == ZPC_ERROR_WKVPMISMATCH) {
					rv = pthread_mutex_lock(&aes_gcm->
					    aes_key->lock);
					assert(rv == 0);

					DEBUG
					    ("aes-gcm context at %p: re-derive protected key from %s secure key from aes key at %p",
					    aes_gcm, i == 0 ? "current" : "old",
					    aes_gcm->aes_key);
					rc = aes_key_sec2prot(aes_gcm->aes_key,
					    i);

					memcpy(param->protkey, protkey->protkey,
					    sizeof(param->protkey));

					rv = pthread_mutex_unlock(&aes_gcm->
					    aes_key->lock);
					assert(rv == 0);
				}
				if (rc)
					break;
			}
		}
	}
	if (rc)
		goto ret;

	DEBUG("aes-gcm context at %p: iv set", aes_gcm);
	aes_gcm->iv_set = 1;
ret:
	DEBUG("return %d (%s)", rc, zpc_error_string(rc));
	return rc;
}

int
zpc_aes_gcm_encrypt(struct zpc_aes_gcm *aes_gcm, u8 * c, u8 * tag,
    size_t taglen, const u8 * aad, size_t aadlen, const u8 * m, size_t mlen)
{
	struct cpacf_kma_gcm_aes_param *param;
	struct pkey_protkey *protkey;
	unsigned long flags = 0;
	int rc, rv, i;

	UNUSED(rv);

	if (pkeyfd < 0) {
		rc = ZPC_ERROR_DEVPKEY;
		goto ret;
	}
	if (!hwcaps.aes_gcm) {
		rc = ZPC_ERROR_HWCAPS;
		goto ret;
	}
	if (aes_gcm == NULL) {
		rc = ZPC_ERROR_ARG1NULL;
		goto ret;
	}

	if ((mlen > 0 || m != NULL) && c == NULL) {
		rc = ZPC_ERROR_ARG2NULL;
		goto ret;
	}
	/* Valid tag bit-lengths: 128, 120, 112, 104, 96, 64, 32. */
	if (taglen > 0 && tag == NULL) {
		rc = ZPC_ERROR_ARG3NULL;
		goto ret;
	}
	if (taglen > 16 || (taglen > 0 && taglen < 12 && taglen != 8
	    && taglen != 4)) {
		rc = ZPC_ERROR_TAGSIZE;
		goto ret;
	}
	/* aad bit-length <= 2^64 - 1, aad bit-length % 8 == 0 */
	if (aadlen > 0 && aad == NULL) {
		rc = ZPC_ERROR_ARG5NULL;
		goto ret;
	}
	if (aadlen > (2ULL << 61) - 1) {
		rc = ZPC_ERROR_AADLEN;
		goto ret;
	}
	if (aadlen > 0 && aadlen % 16 != 0 && m == NULL && tag == NULL) {
		rc = ZPC_ERROR_ARG6RANGE;
		goto ret;
	}
	/* m bit-length <= 2^39 - 256, m bit-length % 8 == 0 */
	if ((mlen > 0 || c != NULL) && m == NULL) {
		rc = ZPC_ERROR_ARG7NULL;
		goto ret;
	}
	if (mlen > (2ULL << 36) - 256) {
		rc = ZPC_ERROR_MLEN;
		goto ret;
	}
	if (mlen > 0 && mlen % 16 != 0 && tag == NULL) {
		rc = ZPC_ERROR_ARG8RANGE;
		goto ret;
	}

	if (!aes_gcm->key_set) {
		rc = ZPC_ERROR_KEYNOTSET;
		goto ret;
	}
	if (!aes_gcm->iv_set) {
		rc = ZPC_ERROR_IVNOTSET;
		goto ret;
	}

	if ((m != NULL && c != NULL) || tag != NULL) {
		flags |= CPACF_KMA_LAAD;
		if (tag != NULL)
			flags |= CPACF_KMA_LPC;
	}
	aes_gcm->param.taadl += (aadlen * 8);
	aes_gcm->param.tpcl += (mlen * 8);

	rc = -1;
	for (i = 0; i < 2 && rc != 0; i++) {
		assert(i == AES_KEY_SEC_CUR || i == AES_KEY_SEC_OLD);

		protkey = &aes_gcm->aes_key->prot;
		param = &aes_gcm->param;

		for (;;) {
			rc = __aes_gcm_crypt(aes_gcm, c, tag, taglen, aad,
			    aadlen, m, mlen, flags);
			if (rc == 0) {
				break;
			} else {
				if (aes_gcm->aes_key->rand_protk) {
					rc = ZPC_ERROR_PROTKEYONLY;
					goto ret;
				}
				if (rc == ZPC_ERROR_WKVPMISMATCH) {
					rv = pthread_mutex_lock(&aes_gcm->
					    aes_key->lock);
					assert(rv == 0);

					DEBUG
					    ("aes-gcm context at %p: re-derive protected key from %s secure key from aes key at %p",
					    aes_gcm, i == 0 ? "current" : "old",
					    aes_gcm->aes_key);
					rc = aes_key_sec2prot(aes_gcm->aes_key,
					    i);
					memcpy(param->protkey, protkey->protkey,
					    sizeof(param->protkey));

					rv = pthread_mutex_unlock(&aes_gcm->
					    aes_key->lock);
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
zpc_aes_gcm_decrypt(struct zpc_aes_gcm *aes_gcm, u8 * m, const u8 * tag,
    size_t taglen, const u8 * aad, size_t aadlen, const u8 * c, size_t clen)
{
	struct cpacf_kma_gcm_aes_param *param;
	struct pkey_protkey *protkey;
	unsigned long flags = CPACF_M;  /* decrypt */
	int rc, rv, i;
	u8 tmp[16];

	UNUSED(rv);

	if (pkeyfd < 0) {
		rc = ZPC_ERROR_DEVPKEY;
		goto ret;
	}
	if (!hwcaps.aes_gcm) {
		rc = ZPC_ERROR_HWCAPS;
		goto ret;
	}
	if (aes_gcm == NULL) {
		rc = ZPC_ERROR_ARG1NULL;
		goto ret;
	}

	if ((clen > 0 || c != NULL) && m == NULL) {
		rc = ZPC_ERROR_ARG2NULL;
		goto ret;
	}
	/* Valid tag bit-lengths: 128, 120, 112, 104, 96, 64, 32. */
	if (taglen > 0 && tag == NULL) {
		rc = ZPC_ERROR_ARG3NULL;
		goto ret;
	}
	if (taglen > 16 || (taglen > 0 && taglen < 12 && taglen != 8
	    && taglen != 4)) {
		rc = ZPC_ERROR_TAGSIZE;
		goto ret;
	}
	/* aad bit-length <= 2^64 - 1, aad bit-length % 8 == 0 */
	if (aadlen > 0 && aad == NULL) {
		rc = ZPC_ERROR_ARG5NULL;
		goto ret;
	}
	if (aadlen > (2ULL << 61) - 1) {
		rc = ZPC_ERROR_AADLEN;
		goto ret;
	}
	if (aadlen > 0 && aadlen % 16 != 0 && c == NULL && tag == NULL) {
		rc = ZPC_ERROR_ARG6RANGE;
		goto ret;
	}
	/* c bit-length <= 2^39 - 256, c bit-length % 8 == 0 */
	if ((clen > 0 || m != NULL) && c == NULL) {
		rc = ZPC_ERROR_ARG7NULL;
		goto ret;
	}
	if (clen > (2ULL << 36) - 256) {
		rc = ZPC_ERROR_CLEN;
		goto ret;
	}
	if (clen > 0 && clen % 16 != 0 && tag == NULL) {
		rc = ZPC_ERROR_ARG8RANGE;
		goto ret;
	}

	if (!aes_gcm->key_set) {
		rc = ZPC_ERROR_KEYNOTSET;
		goto ret;
	}
	if (!aes_gcm->iv_set) {
		rc = ZPC_ERROR_IVNOTSET;
		goto ret;
	}

	if ((m != NULL && c != NULL) || tag != NULL) {
		flags |= CPACF_KMA_LAAD;
		if (tag != NULL)
			flags |= CPACF_KMA_LPC;
	}
	aes_gcm->param.taadl += (aadlen * 8);
	aes_gcm->param.tpcl += (clen * 8);

	rc = -1;
	for (i = 0; i < 2 && (rc != 0 && rc != ZPC_ERROR_TAGMISMATCH); i++) {
		assert(i == AES_KEY_SEC_CUR || i == AES_KEY_SEC_OLD);

		protkey = &aes_gcm->aes_key->prot;
		param = &aes_gcm->param;

		for (;;) {
			rc = __aes_gcm_crypt(aes_gcm, m, tmp, sizeof(tmp), aad,
			    aadlen, c, clen, flags);
			if (rc == 0) {
				rc = memcmp_consttime(tmp, tag, taglen);
				if (rc)
					rc = ZPC_ERROR_TAGMISMATCH;
				break;
			} else {
				if (aes_gcm->aes_key->rand_protk) {
					rc = ZPC_ERROR_PROTKEYONLY;
					goto ret;
				}
				if (rc == ZPC_ERROR_WKVPMISMATCH) {
					rv = pthread_mutex_lock(&aes_gcm->
					    aes_key->lock);
					assert(rv == 0);

					DEBUG
					    ("aes-gcm context at %p: re-derive protected key from %s secure key from aes key at %p",
					    aes_gcm, i == 0 ? "current" : "old",
					    aes_gcm->aes_key);
					rc = aes_key_sec2prot(aes_gcm->aes_key,
					    i);
					memcpy(param->protkey, protkey->protkey,
					    sizeof(param->protkey));

					rv = pthread_mutex_unlock(&aes_gcm->
					    aes_key->lock);
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
zpc_aes_gcm_free(struct zpc_aes_gcm **aes_gcm)
{
	if (aes_gcm == NULL)
		return;
	if (*aes_gcm == NULL)
		return;

	if ((*aes_gcm)->key_set) {
		/* Decrease aes_key's refcount. */
		zpc_aes_key_free(&(*aes_gcm)->aes_key);
		(*aes_gcm)->key_set = 0;
		__aes_gcm_reset_iv(*aes_gcm);
		(*aes_gcm)->iv_set = 0;
	}

	__aes_gcm_reset(*aes_gcm);

	free(*aes_gcm);
	*aes_gcm = NULL;
	DEBUG("return");
}

static int
__aes_gcm_set_iv(struct zpc_aes_gcm *aes_gcm, const u8 * iv, size_t ivlen)
{
	struct cpacf_kma_gcm_aes_param *param;
	size_t ivpadlen;
	u64 *ivpad = NULL;
	int rc, cc;

	assert(aes_gcm != NULL);
	assert(iv != NULL);
	assert(ivlen <= SIZE_MAX - 16);

	param = &aes_gcm->param;

	memset(param->reserved, 0, sizeof(param->reserved));
	memset(param->t, 0, sizeof(param->t));
	param->taadl = 0;
	param->tpcl = 0;

	if (ivlen == 12) {
		memcpy(param->j0, iv, ivlen);
		param->j0[12] = 0;
		param->j0[13] = 0;
		param->j0[14] = 0;
		param->j0[15] = 1;

		param->cv = 1;
	} else {
		ivpadlen = (ivlen + 15) / 16 * 16 + 16;

		ivpad = calloc(1, ivpadlen);
		if (ivpad == NULL)
			return ZPC_ERROR_MALLOC;

		memcpy(ivpad, iv, ivlen);
		ivpad[ivpadlen / 8 - 1] = ivlen * 8;

		memset(param->j0, 0, sizeof(param->j0));

		cc = cpacf_kma(aes_gcm->fc, param, NULL, (u8 *) ivpad, ivpadlen,
		    NULL, 0);
		/* Either incomplete processing or WKaVP mismatch. */
		assert(cc == 2 || cc == 1);
		if (cc == 1) {
			rc = ZPC_ERROR_WKVPMISMATCH;
			goto ret;
		}
		aes_gcm->fc |= CPACF_KMA_HS;

		memcpy(&param->cv, param->t + 12, sizeof(param->cv));
		memcpy(param->j0, param->t, sizeof(param->j0));
		memset(param->t, 0, sizeof(param->t));
	}

	rc = 0;
ret:
	free(ivpad);
	return rc;
}

static int
__aes_gcm_crypt(struct zpc_aes_gcm *aes_gcm, u8 * out, u8 * tag, size_t taglen,
    const u8 * aad, size_t aadlen, const u8 * in, size_t inlen,
    unsigned long flags)
{
	struct cpacf_kma_gcm_aes_param *param;
	int rc, cc;

	param = &aes_gcm->param;

	cc = cpacf_kma(aes_gcm->fc | flags, param, out, aad, aadlen, in, inlen);
	assert(cc == 0 || cc == 1 || cc == 2);
	if (cc == 1) {
		rc = ZPC_ERROR_WKVPMISMATCH;
		goto err;
	}
	aes_gcm->fc |= CPACF_KMA_HS;

	memcpy(tag, param->t, taglen);
	rc = 0;
err:
	return rc;
}

static void
__aes_gcm_reset(struct zpc_aes_gcm *aes_gcm)
{
	assert(aes_gcm != NULL);

	memset(&aes_gcm->param, 0, sizeof(aes_gcm->param));

	__aes_gcm_reset_iv(aes_gcm);
	aes_gcm->iv_set = 0;

	if (aes_gcm->aes_key != NULL)
		zpc_aes_key_free(&aes_gcm->aes_key);
	aes_gcm->key_set = 0;

	aes_gcm->fc = 0;
}

static void
__aes_gcm_reset_iv(struct zpc_aes_gcm *aes_gcm)
{
	assert(aes_gcm != NULL);

	memset(aes_gcm->param.reserved, 0, sizeof(aes_gcm->param.reserved));
	memset(aes_gcm->param.t, 0, sizeof(aes_gcm->param.t));
	memset(aes_gcm->param.j0, 0, sizeof(aes_gcm->param.j0));
	aes_gcm->param.cv = 0;
	aes_gcm->param.taadl = 0;
	aes_gcm->param.tpcl = 0;

	aes_gcm->fc &= ~(CPACF_KMA_LAAD | CPACF_KMA_LPC);
	aes_gcm->iv_set = 0;
}
