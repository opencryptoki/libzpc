/*
 * Copyright IBM Corp. 2025
 *
 * libzpc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <stdbool.h>

#include <assert.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "zpc/aes_xts_full.h"
#include "zpc/error.h"

#include "aes_xts_full_local.h"
#include "aes_xts_key_local.h"

#include "cpacf.h"
#include "globals.h"
#include "misc.h"
#include "debug.h"
#include "zkey/pkey.h"


static int __aes_xts_full_set_iv(struct zpc_aes_xts_full *, const u8 *);
static int __aes_xts_full_set_intermediate_state(struct zpc_aes_xts_full *, const u8 state[32]);
static int __aes_xts_full_crypt(struct zpc_aes_xts_full *, u8 *, const u8 *, size_t, unsigned long);
static void __aes_xts_full_reset(struct zpc_aes_xts_full *);
static void __aes_xts_full_reset_iv(struct zpc_aes_xts_full *);

int zpc_aes_xts_full_alloc(struct zpc_aes_xts_full **aes_xts)
{
	struct zpc_aes_xts_full *new_aes_xts = NULL;
	int rc;

	if (pkeyfd < 0) {
		rc = ZPC_ERROR_DEVPKEY;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}
	if (!hwcaps.aes_xts_full) {
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

	DEBUG("aes-xts-full context at %p: allocated", new_aes_xts);
	*aes_xts = new_aes_xts;
	rc = 0;
	DEBUG("return %d (%s)", rc, zpc_error_string(rc));
	return rc;
}

int zpc_aes_xts_full_set_key(struct zpc_aes_xts_full *aes_xts, struct zpc_aes_xts_key *xts_key)
{
	int rc, rv;

	UNUSED(rv);

	if (pkeyfd < 0) {
		rc = ZPC_ERROR_DEVPKEY;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}
	if (!hwcaps.aes_xts_full) {
		rc = ZPC_ERROR_HWCAPS;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}
	if (aes_xts == NULL) {
		rc = ZPC_ERROR_ARG1NULL;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}

	if (xts_key == NULL) {
		/* If another key is already set, unset it and decrease
		 * refcount. */
		DEBUG("aes-xts-full context at %p: key unset", aes_xts);
		__aes_xts_full_reset(aes_xts);
		rc = 0;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}

	rv = pthread_mutex_lock(&xts_key->lock);
	assert(rv == 0);

	rc = aes_xts_key_check(xts_key);
	if (rc)
		goto ret;

	if (aes_xts->xts_key == xts_key) {
		DEBUG("aes-xts-full context at %p: key at %p already set",
			aes_xts, xts_key);
		rc = 0; /* nothing to do */
		goto ret;
	}

	xts_key->refcount++;
	DEBUG("xts key at %p: refcount %llu", xts_key, xts_key->refcount);

	if (aes_xts->key_set) {
		/* If another key is already set, unset it and decrease refcount. */
		DEBUG("aes-xts-full context at %p: key unset", aes_xts);
		__aes_xts_full_reset(aes_xts);
	}

	/* Set new key. */
	assert(!aes_xts->key_set);

	DEBUG("aes-xts-full context at %p: xts-key at %p set", aes_xts, xts_key);

	aes_xts->fc = (xts_key->keysize == 128) ?
		CPACF_KM_FXTS_ENCRYPTED_AES_128 : CPACF_KM_FXTS_ENCRYPTED_AES_256;

	/*
	 * Currently, full-xts keys can only be pvsecret-type keys. These can
	 * only be imported via their secret ID and this import does not do any
	 * sec2prot conversion, i.e. the protkey value is not yet set in the key.
	 * Therefore do an explicit sec2prot here.
	 */
	if (xts_key->type == ZPC_AES_XTS_KEY_TYPE_PVSECRET) {
		rc = aes_xts_key_sec2prot(xts_key);
		if (rc != 0) {
			DEBUG("aes-xts-full context at %p: sec2prot failed with rc=%d",
				aes_xts, rc);
			goto ret;
		}
	}

	memcpy(aes_xts->param_km, &xts_key->prot.protkey, AES_FXTS_PROTKEYLEN(xts_key->keysize));
	memcpy(aes_xts->param_km + AES_FXTS_WKVP_OFFSET(xts_key->keysize),
		xts_key->prot.protkey + AES_FXTS_PROTKEYLEN(xts_key->keysize),
		32);
	memset(aes_xts->param_km + AES_FXTS_NAP_OFFSET(xts_key->keysize), 0x01, 1);

	aes_xts->xts_key = xts_key;
	aes_xts->key_set = 1;

	rc = 0;
ret:
	rv = pthread_mutex_unlock(&xts_key->lock);
	assert(rv == 0);
	DEBUG("return %d (%s)", rc, zpc_error_string(rc));
	return rc;
}

int
zpc_aes_xts_full_set_iv(struct zpc_aes_xts_full *aes_xts, const u8 * iv)
{
	int rc, rv;

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
		DEBUG("aes-xts-full context at %p: iv unset", aes_xts);
		__aes_xts_full_reset_iv(aes_xts);
		aes_xts->iv_set = 0;
		rc = 0;
		goto ret;
	}

	if (aes_xts->key_set != 1) {
		rc = ZPC_ERROR_KEYNOTSET;
		goto ret;
	}

	rc = __aes_xts_full_set_iv(aes_xts, iv);
	if (rc)
		goto ret;

	DEBUG("aes-xts-full context at %p: iv set", aes_xts);
	aes_xts->iv_set = 1;
ret:
	DEBUG("return %d (%s)", rc, zpc_error_string(rc));
	return rc;
}

int zpc_aes_xts_full_export(struct zpc_aes_xts_full *aes_xts, unsigned char state[32])
{
	int rc, off1, off2;

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

	if (state == NULL) {
		rc = ZPC_ERROR_ARG2NULL;
		goto ret;
	}

	if (aes_xts->iv_set != 1) {
		rc = ZPC_ERROR_IVNOTSET;
		goto ret;
	}

	off1 = AES_FXTS_TWEAK_OFFSET(aes_xts->xts_key->keysize);
	memcpy(state, aes_xts->param_km + off1, 16);
	off2 = AES_FXTS_NAP_OFFSET(aes_xts->xts_key->keysize);
	memcpy(state + 16, aes_xts->param_km + off2, 16);
	rc = 0;

ret:
	DEBUG("return %d (%s)", rc, zpc_error_string(rc));
	return rc;
}

int zpc_aes_xts_full_import(struct zpc_aes_xts_full *aes_xts, const unsigned char state[32])
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
	if (state == NULL) {
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

	rc = __aes_xts_full_set_intermediate_state(aes_xts, state);
	if (rc)
		goto ret;

	aes_xts->iv_set = 1;

	DEBUG("aes-xts-full context at %p: intermediate state set", aes_xts);
ret:
	DEBUG("return %d (%s)", rc, zpc_error_string(rc));
	return rc;
}

int zpc_aes_xts_full_encrypt(struct zpc_aes_xts_full *aes_xts, u8 * c,
		const u8 * m, size_t mlen)
{
	struct pkey_xts_full_protkey *protkey;
	unsigned long flags = 0;
	u8 *param;
	int rc, rv;

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
	protkey = &aes_xts->xts_key->prot;
	param = aes_xts->param_km;

	for (;;) {
		rc = __aes_xts_full_crypt(aes_xts, c, m, mlen, flags);
		if (rc == 0) {
			break;
		} else {
			if (aes_xts->xts_key->rand_protk) {
				rc = ZPC_ERROR_PROTKEYONLY;
				goto ret;
			}
			if (rc == ZPC_ERROR_WKVPMISMATCH) {
				rv = pthread_mutex_lock(&aes_xts->xts_key->lock);
				assert(rv == 0);

				DEBUG("aes-xts-full context at %p: re-derive protected key from xts key at %p",
					aes_xts, aes_xts->xts_key);
				rc = aes_xts_key_sec2prot(aes_xts->xts_key);
				memcpy(param, protkey->protkey, AES_FXTS_PROTKEYLEN(aes_xts->xts_key->keysize));
				memcpy(param + AES_FXTS_WKVP_OFFSET(aes_xts->xts_key->keysize),
					protkey->protkey + AES_FXTS_PROTKEYLEN(aes_xts->xts_key->keysize),
					32);

				rv = pthread_mutex_unlock(&aes_xts->xts_key->lock);
				assert(rv == 0);
			}
			if (rc)
				break;
		}
	}

ret:
	DEBUG("return %d (%s)", rc, zpc_error_string(rc));
	return rc;
}

int zpc_aes_xts_full_decrypt(struct zpc_aes_xts_full *aes_xts, u8 * m,
		const u8 * c, size_t clen)
{
	struct pkey_xts_full_protkey *protkey;
	unsigned long flags = CPACF_M;  /* decrypt */
	u8 *param;
	int rc, rv;

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
	protkey = &aes_xts->xts_key->prot;
	param = aes_xts->param_km;

	for (;;) {
		rc = __aes_xts_full_crypt(aes_xts, m, c, clen, flags);
		if (rc == 0) {
			break;
		} else {
			if (aes_xts->xts_key->rand_protk) {
				rc = ZPC_ERROR_PROTKEYONLY;
				goto ret;
			}
			if (rc == ZPC_ERROR_WKVPMISMATCH) {
				rv = pthread_mutex_lock(&aes_xts->xts_key->lock);
				assert(rv == 0);

				DEBUG("aes-xts-full context at %p: re-derive protected key from xts key at %p",
					aes_xts, aes_xts->xts_key);
				rc = aes_xts_key_sec2prot(aes_xts->xts_key);
				memcpy(param, protkey->protkey, AES_FXTS_PROTKEYLEN(aes_xts->xts_key->keysize));
				memcpy(param + AES_FXTS_WKVP_OFFSET(aes_xts->xts_key->keysize),
					protkey->protkey + AES_FXTS_PROTKEYLEN(aes_xts->xts_key->keysize),
					32);

				rv = pthread_mutex_unlock(&aes_xts->xts_key->lock);
				assert(rv == 0);
			}
			if (rc)
				break;
		}
	}

ret:
	DEBUG("return %d (%s)", rc, zpc_error_string(rc));
	return rc;
}

void zpc_aes_xts_full_free(struct zpc_aes_xts_full **aes_xts)
{
	if (aes_xts == NULL)
		return;
	if (*aes_xts == NULL)
		return;

	if ((*aes_xts)->key_set) {
		/* Decrease aes_key's refcount. */
		zpc_aes_xts_key_free(&(*aes_xts)->xts_key);
		(*aes_xts)->key_set = 0;
		__aes_xts_full_reset_iv(*aes_xts);
		(*aes_xts)->iv_set = 0;
	}

	__aes_xts_full_reset(*aes_xts);

	free(*aes_xts);
	*aes_xts = NULL;
	DEBUG("return");
}

static int __aes_xts_full_set_iv(struct zpc_aes_xts_full *aes_xts, const u8 * iv)
{
	int rc, off1, off2;

	assert(aes_xts != NULL);
	assert(iv != NULL);
	assert(aes_xts->xts_key != NULL);
	assert(aes_xts->key_set == 1);

	off1 = AES_FXTS_TWEAK_OFFSET(aes_xts->xts_key->keysize);
	off2 = AES_FXTS_NAP_OFFSET(aes_xts->xts_key->keysize);
	memcpy(aes_xts->param_km + off1, iv, 16);
	memset(aes_xts->param_km + off2, 0x01, 1);
	rc = 0;

	return rc;
}

static int __aes_xts_full_set_intermediate_state(struct zpc_aes_xts_full *aes_xts,
		const u8 iv[32])
{
	int rc, off1, off2;

	assert(aes_xts != NULL);
	assert(iv != NULL);
	assert(aes_xts->xts_key != NULL);
	assert(aes_xts->key_set == 1);

	off1 = AES_FXTS_TWEAK_OFFSET(aes_xts->xts_key->keysize);
	memcpy(aes_xts->param_km + off1, iv, 16);

	off2 = AES_FXTS_NAP_OFFSET(aes_xts->xts_key->keysize);
	memcpy(aes_xts->param_km + off2, iv + 16, 16);

	rc = 0;

	return rc;
}

static int __aes_xts_full_crypt(struct zpc_aes_xts_full *aes_xts, u8 * out,
		const u8 * in, size_t inlen, unsigned long flags)
{
	int rc, cc;
	size_t rem;
	u8 tmp[16];

	rem = inlen & 0xf;
	inlen &= ~(size_t)0xf;

	if (rem == 0) {
		cc = cpacf_km(aes_xts->fc | flags, aes_xts->param_km, out, in, inlen);
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
		cc = cpacf_km(aes_xts->fc | flags, aes_xts->param_km, out, in, inlen + 16);
		assert(cc == 0 || cc == 2 || cc == 1);
		if (cc == 1) {
			rc = ZPC_ERROR_WKVPMISMATCH;
			goto ret;
		}

		memcpy(tmp, in + inlen + 16, rem);
		memcpy(tmp + rem, out + inlen + rem, 16 - rem);
		memcpy(out + inlen + 16, out + inlen, rem);

		cc = cpacf_km(aes_xts->fc | flags, aes_xts->param_km, out + inlen, tmp, 16);
		assert(cc == 0 || cc == 2 || cc == 1);
		if (cc == 1) {
			rc = ZPC_ERROR_WKVPMISMATCH;
			goto ret;
		}
	} else if ((flags & CPACF_M)) {
		/* ciphertext-stealing (decrypt) */
		u8 xtsparam[16], buf[16];
		u8 nap_n1[16];

		if (inlen) {
			cc = cpacf_km(aes_xts->fc | flags, aes_xts->param_km, out, in, inlen);
			assert(cc == 0 || cc == 2 || cc == 1);
			if (cc == 1) {
				rc = ZPC_ERROR_WKVPMISMATCH;
				goto ret;
			}
		}

		memcpy(xtsparam, aes_xts->param_km + AES_FXTS_TWEAK_OFFSET(aes_xts->xts_key->keysize), 16);
		memcpy(nap_n1, aes_xts->param_km + AES_FXTS_NAP_OFFSET(aes_xts->xts_key->keysize), 16);

		cc = cpacf_km(aes_xts->fc | flags, aes_xts->param_km, buf, in + inlen, 16);
		assert(cc == 0 || cc == 2 || cc == 1);
		if (cc == 1) {
			rc = ZPC_ERROR_WKVPMISMATCH;
			goto ret;
		}
		cc = cpacf_km(aes_xts->fc | flags, aes_xts->param_km, out + inlen, in + inlen, 16);
		assert(cc == 0 || cc == 2 || cc == 1);
		if (cc == 1) {
			rc = ZPC_ERROR_WKVPMISMATCH;
			goto ret;
		}

		memcpy(tmp, in + inlen + 16, rem);
		memcpy(tmp + rem, out + inlen + rem, 16 - rem);
		memcpy(out + inlen + 16, out + inlen, rem);

		memcpy(aes_xts->param_km + AES_FXTS_TWEAK_OFFSET(aes_xts->xts_key->keysize), xtsparam, 16);
		memcpy(aes_xts->param_km + AES_FXTS_NAP_OFFSET(aes_xts->xts_key->keysize), nap_n1, 16);

		cc = cpacf_km(aes_xts->fc | flags, aes_xts->param_km, out + inlen, tmp, 16);
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

static void __aes_xts_full_reset(struct zpc_aes_xts_full *aes_xts)
{
	assert(aes_xts != NULL);

	memset(aes_xts->param_km, 0, sizeof(aes_xts->param_km));

	__aes_xts_full_reset_iv(aes_xts);
	aes_xts->iv_set = 0;

	if (aes_xts->xts_key != NULL)
		zpc_aes_xts_key_free(&aes_xts->xts_key);
	aes_xts->key_set = 0;

	aes_xts->fc = 0;
}

static void __aes_xts_full_reset_iv(struct zpc_aes_xts_full *aes_xts)
{
	assert(aes_xts != NULL);

	if (aes_xts->key_set == 1) {
		assert(aes_xts->xts_key != NULL);

		memset(aes_xts->param_km + AES_FXTS_TWEAK_OFFSET(aes_xts->xts_key->keysize), 0, 1 * 16);
	}
	aes_xts->iv_set = 0;
}
