/*
 * Copyright IBM Corp. 2021
 *
 * libzpc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <stdbool.h>

#include "zpc/aes_xts.h"
#include "zpc/error.h"

#include "aes_xts_local.h"
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

static int __aes_xts_set_iv(struct zpc_aes_xts *, const u8 *);
static int __aes_xts_set_intermediate_iv(struct zpc_aes_xts *, const u8 iv[16]);
static int __aes_xts_crypt(struct zpc_aes_xts *, u8 *, const u8 *, size_t,
    unsigned long, size_t *);
static void __aes_xts_reset(struct zpc_aes_xts *);
static void __aes_xts_reset_iv(struct zpc_aes_xts *);

int
zpc_aes_xts_alloc(struct zpc_aes_xts **aes_xts)
{
	struct zpc_aes_xts *new_aes_xts = NULL;
	int rc;

	if (pkeyfd < 0) {
		rc = ZPC_ERROR_DEVPKEY;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}
	if (!hwcaps.aes_xts) {
		rc = ZPC_ERROR_HWCAPS;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}
	if (aes_xts == NULL) {
		rc = ZPC_ERROR_ARG1NULL;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}

	new_aes_xts = calloc(1, sizeof(*new_aes_xts));
	if (new_aes_xts == NULL) {
		rc = ZPC_ERROR_MALLOC;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}

	DEBUG("aes-xts context at %p: allocated", new_aes_xts);
	*aes_xts = new_aes_xts;
	rc = 0;
	DEBUG("return %d (%s)", rc, zpc_error_string(rc));
	return rc;
}

int
zpc_aes_xts_set_key(struct zpc_aes_xts *aes_xts, struct zpc_aes_key *aes_key1,
    struct zpc_aes_key *aes_key2)
{
	int rc, rv;

	UNUSED(rv);

	if (pkeyfd < 0) {
		rc = ZPC_ERROR_DEVPKEY;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}
	if (!hwcaps.aes_xts) {
		rc = ZPC_ERROR_HWCAPS;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}
	if (aes_xts == NULL) {
		rc = ZPC_ERROR_ARG1NULL;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}

	if (aes_key1 == NULL || aes_key2 == NULL) {
		/* If another key is already set, unset it and decrease
		 * refcount. */
		DEBUG("aes-xts context at %p: key unset", aes_xts);
		__aes_xts_reset(aes_xts);
		rc = 0;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}

	if (aes_key1 == aes_key2) {
		rc = ZPC_ERROR_KEYSEQUAL;
		goto ret;
	}

	rv = pthread_mutex_lock(&aes_key1->lock);
	assert(rv == 0);
	rv = pthread_mutex_lock(&aes_key2->lock);
	assert(rv == 0);

	rc = aes_key_check(aes_key1);
	if (rc)
		goto ret;
	rc = aes_key_check(aes_key2);
	if (rc)
		goto ret;
	if (aes_key1->keysize != aes_key2->keysize) {
		rc = ZPC_ERROR_KEYSIZE;
		goto ret;
	}
	if (aes_key1->keysize != 128 && aes_key1->keysize != 256) {
		rc = ZPC_ERROR_KEYSIZE;
		goto ret;
	}

	if (aes_xts->aes_key1 == aes_key1 && aes_xts->aes_key2 == aes_key2) {
		DEBUG("aes-xts context at %p: keys at %p and %p already set",
		    aes_xts, aes_key1, aes_key2);
		rc = 0; /* nothing to do */
		goto ret;
	}

	aes_key1->refcount++;
	DEBUG("aes key at %p: refcount %llu", aes_key1, aes_key1->refcount);
	aes_key2->refcount++;
	DEBUG("aes key at %p: refcount %llu", aes_key2, aes_key2->refcount);

	if (aes_xts->key_set) {
		/* If another key is already set, unset it and decrease
		 * refcount. */
		DEBUG("aes-xts context at %p: key unset", aes_xts);
		__aes_xts_reset(aes_xts);
	}

	/* Set new key. */
	assert(!aes_xts->key_set);

	DEBUG("aes-xts context at %p: keys at %p and %p set", aes_xts, aes_key1,
	    aes_key2);

	memcpy(aes_xts->param_km, aes_key1->prot.protkey,
	    AES_XTS_PROTKEYLEN(aes_key1->keysize));
	memcpy(aes_xts->param_pcc, aes_key2->prot.protkey,
	    AES_XTS_PROTKEYLEN(aes_key2->keysize));

	/* PCC uses the same function codes for 128 resp. 256 bit keys. */
	aes_xts->fc = CPACF_KM_XTS_ENCRYPTED_AES_128 + (aes_key1->keysize - 128) / 64;

	aes_xts->aes_key1 = aes_key1;
	aes_xts->aes_key2 = aes_key2;
	aes_xts->key_set = 1;

	rc = 0;
ret:
	rv = pthread_mutex_unlock(&aes_key1->lock);
	assert(rv == 0);
	rv = pthread_mutex_unlock(&aes_key2->lock);
	assert(rv == 0);
	DEBUG("return %d (%s)", rc, zpc_error_string(rc));
	return rc;
}

int
zpc_aes_xts_set_iv(struct zpc_aes_xts *aes_xts, const u8 * iv)
{
	struct pkey_protkey *protkey;
	int rc, rv, i;
	u8 *param;

	UNUSED(rv);

	if (pkeyfd < 0) {
		rc = ZPC_ERROR_DEVPKEY;
		goto ret;
	}
	if (!hwcaps.aes_xts) {
		rc = ZPC_ERROR_HWCAPS;
		goto ret;
	}
	if (aes_xts == NULL) {
		rc = ZPC_ERROR_ARG1NULL;
		goto ret;
	}
	if (iv == NULL) {
		/* Unset iv */
		DEBUG("aes-xts context at %p: iv unset", aes_xts);
		__aes_xts_reset_iv(aes_xts);
		aes_xts->iv_set = 0;
		rc = 0;
		goto ret;
	}

	if (aes_xts->key_set != 1) {
		rc = ZPC_ERROR_KEYNOTSET;
		goto ret;
	}

	rc = -1;
	for (i = 0; i < 2 && rc != 0; i++) {
		assert(i == AES_KEY_SEC_CUR || i == AES_KEY_SEC_OLD);

		protkey = &aes_xts->aes_key2->prot;
		param = aes_xts->param_pcc;

		for (;;) {
			rc = __aes_xts_set_iv(aes_xts, iv);
			if (rc == 0) {
				break;
			} else {
				if (aes_xts->aes_key2->rand_protk) {
					rc = ZPC_ERROR_PROTKEYONLY;
					goto ret;
				}
				if (rc == ZPC_ERROR_WKVPMISMATCH) {
					rv = pthread_mutex_lock(&aes_xts->aes_key2->lock);
					assert(rv == 0);

					DEBUG
					    ("aes-xts context at %p: re-derive protected key from %s secure key from aes key at %p",
					    aes_xts, i == 0 ? "current" : "old", aes_xts->aes_key2);
					rc = aes_key_sec2prot(aes_xts->aes_key2, i);

					memcpy(param, protkey->protkey, AES_XTS_PROTKEYLEN(aes_xts->aes_key2->keysize));

					rv = pthread_mutex_unlock(&aes_xts->aes_key2->lock);
					assert(rv == 0);
				}
				if (rc)
					break;
			}
		}
	}
	if (rc)
		goto ret;

	DEBUG("aes-xts context at %p: iv set", aes_xts);
	aes_xts->iv_set = 1;
ret:
	DEBUG("return %d (%s)", rc, zpc_error_string(rc));
	return rc;
}

int
zpc_aes_xts_get_intermediate_iv(struct zpc_aes_xts *aes_xts, unsigned char iv[16])
{
	int rc, off1;

	if (pkeyfd < 0) {
		rc = ZPC_ERROR_DEVPKEY;
		goto ret;
	}
	if (!hwcaps.aes_xts) {
		rc = ZPC_ERROR_HWCAPS;
		goto ret;
	}
	if (aes_xts == NULL) {
		rc = ZPC_ERROR_ARG1NULL;
		goto ret;
	}

	if (iv == NULL) {
		rc = ZPC_ERROR_ARG2NULL;
		goto ret;
	}

	if (aes_xts->iv_set != 1) {
		rc = ZPC_ERROR_IVNOTSET;
		goto ret;
	}

	off1 = AES_XTS_KM_XTSPARAM(aes_xts->aes_key1->keysize);
	memcpy(iv, aes_xts->param_km + off1, 16);
	rc = 0;

ret:
	DEBUG("return %d (%s)", rc, zpc_error_string(rc));
	return rc;
}

int
zpc_aes_xts_set_intermediate_iv(struct zpc_aes_xts *aes_xts, const unsigned char iv[16])
{
	int rc;

	if (pkeyfd < 0) {
		rc = ZPC_ERROR_DEVPKEY;
		goto ret;
	}
	if (!hwcaps.aes_xts) {
		rc = ZPC_ERROR_HWCAPS;
		goto ret;
	}
	if (aes_xts == NULL) {
		rc = ZPC_ERROR_ARG1NULL;
		goto ret;
	}
	if (iv == NULL) {
		rc = ZPC_ERROR_ARG2NULL;
		goto ret;
	}

	if (aes_xts->key_set != 1) {
		rc = ZPC_ERROR_KEYNOTSET;
		goto ret;
	}

	if (aes_xts->iv_set != 1) {
		rc = ZPC_ERROR_IVNOTSET;
		goto ret;
	}

	rc = __aes_xts_set_intermediate_iv(aes_xts, iv);
	if (rc)
		goto ret;

	aes_xts->iv_set = 1;

	DEBUG("aes-xts context at %p: intermediate iv set", aes_xts);
ret:
	DEBUG("return %d (%s)", rc, zpc_error_string(rc));
	return rc;
}

int
zpc_aes_xts_encrypt(struct zpc_aes_xts *aes_xts, u8 * c, const u8 * m,
    size_t mlen)
{
	struct pkey_protkey *protkey;
	unsigned long flags = 0;
	u8 *param;
	int rc, rv, i;
	const u8 *in_pos = m;
	u8 *out_pos = c;
	size_t bytes_processed = 0, len = mlen;

	UNUSED(rv);

	if (pkeyfd < 0) {
		rc = ZPC_ERROR_DEVPKEY;
		goto ret;
	}
	if (!hwcaps.aes_xts) {
		rc = ZPC_ERROR_HWCAPS;
		goto ret;
	}
	if (aes_xts == NULL) {
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
	if (mlen < 16) {
		rc = ZPC_ERROR_MLEN;
		goto ret;
	}

	if (!aes_xts->key_set) {
		rc = ZPC_ERROR_KEYNOTSET;
		goto ret;
	}
	if (!aes_xts->iv_set) {
		rc = ZPC_ERROR_IVNOTSET;
		goto ret;
	}

	rc = -1;
	for (i = 0; i < 2 && rc != 0; i++) {
		assert(i == AES_KEY_SEC_CUR || i == AES_KEY_SEC_OLD);

		protkey = &aes_xts->aes_key1->prot;
		param = aes_xts->param_km;

		for (;;) {
			rc = __aes_xts_crypt(aes_xts, out_pos, in_pos, len, flags, &bytes_processed);
			if (rc == 0) {
				break;
			} else {
				if (aes_xts->aes_key1->rand_protk) {
					rc = ZPC_ERROR_PROTKEYONLY;
					goto ret;
				}
				if (rc == ZPC_ERROR_WKVPMISMATCH) {
					rv = pthread_mutex_lock(&aes_xts->aes_key1->lock);
					assert(rv == 0);

					DEBUG
					    ("aes-xts context at %p: re-derive protected key"
						" from %s secure key from aes key at %p",
					    aes_xts, i == 0 ? "current" : "old", aes_xts->aes_key1);
					rc = aes_key_sec2prot(aes_xts->aes_key1, i);
					memcpy(param, protkey->protkey, AES_XTS_PROTKEYLEN(aes_xts->aes_key1->keysize));

					rv = pthread_mutex_unlock(&aes_xts->aes_key1->lock);
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
zpc_aes_xts_decrypt(struct zpc_aes_xts *aes_xts, u8 * m, const u8 * c,
    size_t clen)
{
	struct pkey_protkey *protkey;
	unsigned long flags = CPACF_M;  /* decrypt */
	u8 *param;
	int rc, rv, i;
	const u8 *in_pos = c;
	u8 *out_pos = m;
	size_t bytes_processed = 0, len = clen;

	UNUSED(rv);

	if (pkeyfd < 0) {
		rc = ZPC_ERROR_DEVPKEY;
		goto ret;
	}
	if (!hwcaps.aes_xts) {
		rc = ZPC_ERROR_HWCAPS;
		goto ret;
	}
	if (aes_xts == NULL) {
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
	if (clen < 16) {
		rc = ZPC_ERROR_CLEN;
		goto ret;
	}

	if (!aes_xts->key_set) {
		rc = ZPC_ERROR_KEYNOTSET;
		goto ret;
	}
	if (!aes_xts->iv_set) {
		rc = ZPC_ERROR_IVNOTSET;
		goto ret;
	}

	rc = -1;
	for (i = 0; i < 2 && rc != 0; i++) {
		assert(i == AES_KEY_SEC_CUR || i == AES_KEY_SEC_OLD);

		protkey = &aes_xts->aes_key1->prot;
		param = aes_xts->param_km;

		for (;;) {
			rc = __aes_xts_crypt(aes_xts, out_pos, in_pos, len, flags, &bytes_processed);
			if (rc == 0) {
				break;
			} else {
				if (aes_xts->aes_key1->rand_protk) {
					rc = ZPC_ERROR_PROTKEYONLY;
					goto ret;
				}
				if (rc == ZPC_ERROR_WKVPMISMATCH) {
					rv = pthread_mutex_lock(&aes_xts->aes_key1->lock);
					assert(rv == 0);

					DEBUG
					    ("aes-xts context at %p: re-derive protected key"
					    " from %s secure key from aes key at %p",
					    aes_xts, i == 0 ? "current" : "old", aes_xts->aes_key1);
					rc = aes_key_sec2prot(aes_xts->aes_key1, i);
					memcpy(param, protkey->protkey, AES_XTS_PROTKEYLEN(aes_xts->aes_key1->keysize));

					rv = pthread_mutex_unlock(&aes_xts->aes_key1->lock);
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
zpc_aes_xts_free(struct zpc_aes_xts **aes_xts)
{
	if (aes_xts == NULL)
		return;
	if (*aes_xts == NULL)
		return;

	if ((*aes_xts)->key_set) {
		/* Decrease aes_key's refcount. */
		zpc_aes_key_free(&(*aes_xts)->aes_key1);
		zpc_aes_key_free(&(*aes_xts)->aes_key2);
		(*aes_xts)->key_set = 0;
		__aes_xts_reset_iv(*aes_xts);
		(*aes_xts)->iv_set = 0;
	}

	__aes_xts_reset(*aes_xts);

	free(*aes_xts);
	*aes_xts = NULL;
	DEBUG("return");
}

static int
__aes_xts_set_iv(struct zpc_aes_xts *aes_xts, const u8 * iv)
{
	int rc, cc, off1, off2;

	assert(aes_xts != NULL);
	assert(iv != NULL);
	assert(aes_xts->aes_key1 != NULL);
	assert(aes_xts->aes_key2 != NULL);
	assert(aes_xts->key_set == 1);

	/* set i */
	off1 = AES_XTS_PCC_I(aes_xts->aes_key2->keysize);
	memcpy(aes_xts->param_pcc + off1, iv, 16);
	/* zero j, t, xtsparam */
	off2 = AES_XTS_PCC_J(aes_xts->aes_key2->keysize);
	memset(aes_xts->param_pcc + off2, 0, 3 * 16);

	cc = cpacf_pcc(aes_xts->fc, aes_xts->param_pcc);
	/* Either incomplete processing or WKaVP mismatch. */
	assert(cc == 0 || cc == 2 || cc == 1);
	if (cc == 1) {
		rc = ZPC_ERROR_WKVPMISMATCH;
		goto ret;
	}

	off1 = AES_XTS_KM_XTSPARAM(aes_xts->aes_key1->keysize);
	off2 = AES_XTS_PCC_XTSPARAM(aes_xts->aes_key2->keysize);
	memcpy(aes_xts->param_km + off1, aes_xts->param_pcc + off2, 16);
	rc = 0;
ret:
	return rc;
}

static int
__aes_xts_set_intermediate_iv(struct zpc_aes_xts *aes_xts, const u8 iv[16])
{
	int rc, off1;

	assert(aes_xts != NULL);
	assert(iv != NULL);
	assert(aes_xts->aes_key1 != NULL);
	assert(aes_xts->aes_key2 != NULL);
	assert(aes_xts->key_set == 1);

	off1 = AES_XTS_KM_XTSPARAM(aes_xts->aes_key1->keysize);
	memcpy(aes_xts->param_km + off1, iv, 16);
	rc = 0;

	return rc;
}

static int
__aes_xts_crypt(struct zpc_aes_xts *aes_xts, u8 * out, const u8 * in,
    size_t inlen, unsigned long flags, size_t *bytes_processed)
{
	int rc, cc;
	size_t rem;
	u8 tmp[16];

	rem = inlen & 0xf;
	inlen &= ~(size_t)0xf;

	if (rem == 0) {
		cc = cpacf_km(aes_xts->fc | flags, aes_xts->param_km, out, in,
		    inlen, bytes_processed);
		assert(cc == 0 || cc == 2 || cc == 1);
		if (cc == 1) {
			rc = ZPC_ERROR_WKVPMISMATCH;
			goto ret;
		}
		rc = 0;
		goto ret;
	}

	inlen -= 16;

	if (!(flags & CPACF_M)) {
		/* ciphertext-stealing (encrypt) */
		cc = cpacf_km(aes_xts->fc | flags, aes_xts->param_km, out, in,
		    inlen + 16, bytes_processed);
		assert(cc == 0 || cc == 2 || cc == 1);
		if (cc == 1) {
			rc = ZPC_ERROR_WKVPMISMATCH;
			goto ret;
		}

		memcpy(tmp, in + inlen + 16, rem);
		memcpy(tmp + rem, out + inlen + rem, 16 - rem);
		memcpy(out + inlen + 16, out + inlen, rem);

		cc = cpacf_km(aes_xts->fc | flags, aes_xts->param_km,
		    out + inlen, tmp, 16, bytes_processed);
		assert(cc == 0 || cc == 2 || cc == 1);
		if (cc == 1) {
			rc = ZPC_ERROR_WKVPMISMATCH;
			goto ret;
		}
	} else if ((flags & CPACF_M)) {
		/* ciphertext-stealing (decrypt) */
		u8 xtsparam[16], buf[16];

		if (inlen) {
			cc = cpacf_km(aes_xts->fc | flags, aes_xts->param_km,
			    out, in, inlen, bytes_processed);
			assert(cc == 0 || cc == 2 || cc == 1);
			if (cc == 1) {
				rc = ZPC_ERROR_WKVPMISMATCH;
				goto ret;
			}
		}

		memcpy(xtsparam, aes_xts->param_km + AES_XTS_KM_XTSPARAM(aes_xts->aes_key1->keysize), 16);

		cc = cpacf_km(aes_xts->fc | flags, aes_xts->param_km, buf,
		    in + inlen, 16, bytes_processed);
		assert(cc == 0 || cc == 2 || cc == 1);
		if (cc == 1) {
			rc = ZPC_ERROR_WKVPMISMATCH;
			goto ret;
		}
		cc = cpacf_km(aes_xts->fc | flags, aes_xts->param_km,
		    out + inlen, in + inlen, 16, bytes_processed);
		assert(cc == 0 || cc == 2 || cc == 1);
		if (cc == 1) {
			rc = ZPC_ERROR_WKVPMISMATCH;
			goto ret;
		}

		memcpy(tmp, in + inlen + 16, rem);
		memcpy(tmp + rem, out + inlen + rem, 16 - rem);
		memcpy(out + inlen + 16, out + inlen, rem);

		memcpy(aes_xts->param_km + AES_XTS_KM_XTSPARAM(aes_xts->aes_key1->keysize), xtsparam, 16);

		cc = cpacf_km(aes_xts->fc | flags, aes_xts->param_km,
		    out + inlen, tmp, 16, bytes_processed);
		assert(cc == 0 || cc == 2 || cc == 1);
		if (cc == 1) {
			rc = ZPC_ERROR_WKVPMISMATCH;
			goto ret;
		}
	}

	rc = 0;
ret:
	return rc;
}

static void
__aes_xts_reset(struct zpc_aes_xts *aes_xts)
{
	assert(aes_xts != NULL);

	memset(aes_xts->param_km, 0, sizeof(aes_xts->param_km));
	memset(aes_xts->param_pcc, 0, sizeof(aes_xts->param_pcc));

	__aes_xts_reset_iv(aes_xts);
	aes_xts->iv_set = 0;

	if (aes_xts->aes_key1 != NULL)
		zpc_aes_key_free(&aes_xts->aes_key1);
	if (aes_xts->aes_key2 != NULL)
		zpc_aes_key_free(&aes_xts->aes_key2);
	aes_xts->key_set = 0;

	aes_xts->fc = 0;
}

static void
__aes_xts_reset_iv(struct zpc_aes_xts *aes_xts)
{
	assert(aes_xts != NULL);

	if (aes_xts->key_set == 1) {
		assert(aes_xts->aes_key1 != NULL);
		assert(aes_xts->aes_key2 != NULL);

		memset(aes_xts->param_km + AES_XTS_KM_XTSPARAM(aes_xts->aes_key1->keysize), 0, 1 * 16);
		/* zero i, j, t, xtsparam */
		memset(aes_xts->param_pcc + AES_XTS_PCC_I(aes_xts->aes_key2->keysize), 0, 4 * 16);
	}
	aes_xts->iv_set = 0;
}
