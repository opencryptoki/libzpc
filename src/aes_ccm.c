/*
 * Copyright IBM Corp. 2021
 *
 * libzpc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <stdbool.h>

#include "zpc/aes_ccm.h"
#include "zpc/error.h"

#include "aes_ccm_local.h"
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

struct aes_ccm_flags {
	u8 reserved:1;
	u8 adata:1;
	u8 m:3;
	u8 l:3;
} __packed;

static void __aes_ccm_set_iv(struct zpc_aes_ccm *, const u8 *, size_t);
static int __aes_ccm_crypt(struct zpc_aes_ccm *, u8 *, u8 *, size_t, const u8 *,
    size_t, const u8 *, size_t, unsigned long, int);
static int __aes_ccm_cbcmac(struct zpc_aes_ccm *, const u8 *, size_t);
static int __aes_ccm_ctr(struct zpc_aes_ccm *, u8[16], u8 *, const u8 *,
    size_t, int);
static void __aes_ccm_reset(struct zpc_aes_ccm *);
static void __aes_ccm_reset_iv(struct zpc_aes_ccm *);

int
zpc_aes_ccm_alloc(struct zpc_aes_ccm **aes_ccm)
{
	struct zpc_aes_ccm *new_aes_ccm = NULL;
	int rc;

	if (pkeyfd < 0) {
		rc = ZPC_ERROR_DEVPKEY;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}
	if (!hwcaps.aes_ccm) {
		rc = ZPC_ERROR_HWCAPS;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}
	if (aes_ccm == NULL) {
		rc = ZPC_ERROR_ARG1NULL;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}

	new_aes_ccm = calloc(1, sizeof(*new_aes_ccm));
	if (new_aes_ccm == NULL) {
		rc = ZPC_ERROR_MALLOC;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}

	DEBUG("aes-ccm context at %p: allocated", new_aes_ccm);
	*aes_ccm = new_aes_ccm;
	rc = 0;
	DEBUG("return %d (%s)", rc, zpc_error_string(rc));
	return rc;
}

int
zpc_aes_ccm_set_key(struct zpc_aes_ccm *aes_ccm, struct zpc_aes_key *aes_key)
{
	int rc, rv;

	UNUSED(rv);

	if (pkeyfd < 0) {
		rc = ZPC_ERROR_DEVPKEY;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}
	if (!hwcaps.aes_ccm) {
		rc = ZPC_ERROR_HWCAPS;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}
	if (aes_ccm == NULL) {
		rc = ZPC_ERROR_ARG1NULL;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}

	if (aes_key == NULL) {
		/* If another key is already set, unset it and decrease
		 * refcount. */
		DEBUG("aes-ccm context at %p: key unset", aes_ccm);
		__aes_ccm_reset(aes_ccm);
		rc = 0;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}

	rv = pthread_mutex_lock(&aes_key->lock);
	assert(rv == 0);

	rc = aes_key_check(aes_key);
	if (rc)
		goto ret;

	if (aes_ccm->aes_key == aes_key) {
		DEBUG("aes-ccm context at %p: key at %p already set", aes_ccm, aes_key);
		rc = 0; /* nothing to do */
		goto ret;
	}

	aes_key->refcount++;
	DEBUG("aes key at %p: refcount %llu", aes_key, aes_key->refcount);

	if (aes_ccm->key_set) {
		/* If another key is already set, unset it and decrease
		 * refcount. */
		DEBUG("aes-ccm context at %p: key unset", aes_ccm);
		__aes_ccm_reset(aes_ccm);
	}

	/* Set new key. */
	assert(!aes_ccm->key_set);

	DEBUG("aes-ccm context at %p: key at %p set, iv unset", aes_ccm, aes_key);

	memcpy(aes_ccm->param_kma.protkey, aes_key->prot.protkey,
	    sizeof(aes_ccm->param_kma.protkey));
	memcpy(aes_ccm->param_kmac.protkey, aes_key->prot.protkey,
	    sizeof(aes_ccm->param_kmac.protkey));

	/* The corresponding KMAC function codes are the same as the KMA
	 * function codes. */
	aes_ccm->fc = CPACF_KMA_GCM_ENCRYPTED_AES_128 + (aes_key->keysize - 128) / 64;

	aes_ccm->aes_key = aes_key;
	aes_ccm->key_set = 1;

	__aes_ccm_reset_iv(aes_ccm);
	aes_ccm->iv_set = 0;

	rc = 0;
ret:
	rv = pthread_mutex_unlock(&aes_key->lock);
	assert(rv == 0);
	DEBUG("return %d (%s)", rc, zpc_error_string(rc));
	return rc;
}

int
zpc_aes_ccm_set_iv(struct zpc_aes_ccm *aes_ccm, const u8 * iv, size_t ivlen)
{
	int rc, rv;

	UNUSED(rv);

	if (pkeyfd < 0) {
		rc = ZPC_ERROR_DEVPKEY;
		goto ret;
	}
	if (!hwcaps.aes_ccm) {
		rc = ZPC_ERROR_HWCAPS;
		goto ret;
	}
	if (aes_ccm == NULL) {
		rc = ZPC_ERROR_ARG1NULL;
		goto ret;
	}
	if (iv == NULL) {
		/* Unset iv */
		DEBUG("aes-ccm context at %p: iv unset", aes_ccm);
		__aes_ccm_reset_iv(aes_ccm);
		aes_ccm->iv_set = 0;
		rc = 0;
		goto ret;
	}
	/* 15 - L byte nonce. 2 <= L <= 8. */
	if (ivlen < 15 - 8 || ivlen > 15 - 2) {
		rc = ZPC_ERROR_IVSIZE;
		goto ret;
	}

	if (aes_ccm->key_set != 1) {
		rc = ZPC_ERROR_KEYNOTSET;
		goto ret;
	}

	__aes_ccm_set_iv(aes_ccm, iv, ivlen);
	DEBUG("aes-ccm context at %p: iv set", aes_ccm);
	aes_ccm->iv_set = 1;
	rc = 0;
ret:
	DEBUG("return %d (%s)", rc, zpc_error_string(rc));
	return rc;
}

int
zpc_aes_ccm_encrypt(struct zpc_aes_ccm *aes_ccm, u8 * c, u8 * tag,
    size_t taglen, const u8 * aad, size_t aadlen, const u8 * m, size_t mlen)
{
	struct cpacf_kma_gcm_aes_param *param_kma;
	struct cpacf_kmac_aes_param *param_kmac;
	struct pkey_protkey *protkey;
	unsigned long flags = 0;
	int rc, rv, i;

	UNUSED(rv);

	if (pkeyfd < 0) {
		rc = ZPC_ERROR_DEVPKEY;
		goto ret;
	}
	if (!hwcaps.aes_ccm) {
		rc = ZPC_ERROR_HWCAPS;
		goto ret;
	}
	if (aes_ccm == NULL) {
		rc = ZPC_ERROR_ARG1NULL;
		goto ret;
	}

	if ((mlen > 0 || m != NULL) && c == NULL) {
		rc = ZPC_ERROR_ARG2NULL;
		goto ret;
	}
	/* Valid tag byte-lengths: 16, 14, 12, 10, 8, 6, 4. */
	if (taglen > 0 && tag == NULL) {
		rc = ZPC_ERROR_ARG3NULL;
		goto ret;
	}
	if (taglen % 2 != 0 || taglen > 16 || taglen < 4) {
		rc = ZPC_ERROR_TAGSIZE;
		goto ret;
	}
	/* 0 <= aad byte-length <= 2^64 - 1 */
	if (aadlen > 0 && aad == NULL) {
		rc = ZPC_ERROR_ARG5NULL;
		goto ret;
	}

	if (!aes_ccm->key_set) {
		rc = ZPC_ERROR_KEYNOTSET;
		goto ret;
	}
	if (!aes_ccm->iv_set) {
		rc = ZPC_ERROR_IVNOTSET;
		goto ret;
	}

	/* 0 <= m byte-length <= 2^(8L) - 1 */
	if ((mlen > 0 || c != NULL) && m == NULL) {
		rc = ZPC_ERROR_ARG7NULL;
		goto ret;
	}
	if (aes_ccm->ivlen > 7
	    && (u64) mlen > (1ULL << (8 * (15 - aes_ccm->ivlen))) - 1) {
		rc = ZPC_ERROR_MLEN;
		goto ret;
	}

	rc = -1;
	for (i = 0; i < 2 && rc != 0; i++) {
		assert(i == AES_KEY_SEC_CUR || i == AES_KEY_SEC_OLD);

		protkey = &aes_ccm->aes_key->prot;
		param_kma = &aes_ccm->param_kma;
		param_kmac = &aes_ccm->param_kmac;

		for (;;) {
			rc = __aes_ccm_crypt(aes_ccm, c, tag, taglen, aad,
			    aadlen, m, mlen, flags, i);
			if (rc == 0) {
				break;
			} else {
				if (aes_ccm->aes_key->rand_protk) {
					rc = ZPC_ERROR_PROTKEYONLY;
					goto ret;
				}
				if (rc == ZPC_ERROR_WKVPMISMATCH) {
					rv = pthread_mutex_lock(&aes_ccm->aes_key->lock);
					assert(rv == 0);

					DEBUG
					    ("aes-ccm context at %p: re-derive protected key from %s secure key from aes key at %p",
					    aes_ccm, i == 0 ? "current" : "old", aes_ccm->aes_key);
					rc = aes_key_sec2prot(aes_ccm->aes_key, i);
					memcpy(param_kma->protkey, protkey->protkey, sizeof(param_kma->protkey));
					memcpy(param_kmac->protkey, protkey->protkey, sizeof(param_kmac->protkey));

					rv = pthread_mutex_unlock(&aes_ccm->
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
zpc_aes_ccm_decrypt(struct zpc_aes_ccm *aes_ccm, u8 * m, const u8 * tag,
    size_t taglen, const u8 * aad, size_t aadlen, const u8 * c, size_t clen)
{
	struct cpacf_kma_gcm_aes_param *param_kma;
	struct cpacf_kmac_aes_param *param_kmac;
	struct pkey_protkey *protkey;
	unsigned long flags = CPACF_M;
	int rc, rv, i;
	u8 tmp[16];

	UNUSED(rv);

	if (pkeyfd < 0) {
		rc = ZPC_ERROR_DEVPKEY;
		goto ret;
	}
	if (!hwcaps.aes_ccm) {
		rc = ZPC_ERROR_HWCAPS;
		goto ret;
	}
	if (aes_ccm == NULL) {
		rc = ZPC_ERROR_ARG1NULL;
		goto ret;
	}

	if ((clen > 0 || c != NULL) && m == NULL) {
		rc = ZPC_ERROR_ARG2NULL;
		goto ret;
	}
	/* Valid tag byte-lengths: 16, 14, 12, 10, 8, 6, 4. */
	if (taglen > 0 && tag == NULL) {
		rc = ZPC_ERROR_ARG3NULL;
		goto ret;
	}
	if (taglen % 2 != 0 || taglen > 16 || taglen < 4) {
		rc = ZPC_ERROR_TAGSIZE;
		goto ret;
	}
	/* 0 <= aad byte-length <= 2^64 - 1 */
	if (aadlen > 0 && aad == NULL) {
		rc = ZPC_ERROR_ARG5NULL;
		goto ret;
	}

	if (!aes_ccm->key_set) {
		rc = ZPC_ERROR_KEYNOTSET;
		goto ret;
	}
	if (!aes_ccm->iv_set) {
		rc = ZPC_ERROR_IVNOTSET;
		goto ret;
	}

	/* 0 <= c byte-length <= 2^(8L) - 1 */
	if ((clen > 0 || m != NULL) && c == NULL) {
		rc = ZPC_ERROR_ARG7NULL;
		goto ret;
	}
	if (aes_ccm->ivlen > 7
	    && (u64) clen > (1ULL << (8 * (15 - aes_ccm->ivlen))) - 1) {
		rc = ZPC_ERROR_CLEN;
		goto ret;
	}

	rc = -1;
	for (i = 0; i < 2 && rc != 0 && (rc != ZPC_ERROR_TAGMISMATCH); i++) {
		assert(i == AES_KEY_SEC_CUR || i == AES_KEY_SEC_OLD);

		protkey = &aes_ccm->aes_key->prot;
		param_kma = &aes_ccm->param_kma;
		param_kmac = &aes_ccm->param_kmac;

		for (;;) {
			memcpy(tmp, tag, taglen);
			rc = __aes_ccm_crypt(aes_ccm, m, tmp, taglen, aad,
			    aadlen, c, clen, flags, i);
			if (rc == 0 || rc == ZPC_ERROR_TAGMISMATCH) {
				break;
			} else {
				if (aes_ccm->aes_key->rand_protk) {
					rc = ZPC_ERROR_PROTKEYONLY;
					goto ret;
				}
				if (rc == ZPC_ERROR_WKVPMISMATCH) {
					rv = pthread_mutex_lock(&aes_ccm->aes_key->lock);
					assert(rv == 0);

					DEBUG
					    ("aes-ccm context at %p: re-derive protected key from %s secure key from aes key at %p",
					    aes_ccm, i == 0 ? "current" : "old", aes_ccm->aes_key);
					rc = aes_key_sec2prot(aes_ccm->aes_key, i);
					memcpy(param_kma->protkey, protkey->protkey, sizeof(param_kma->protkey));
					memcpy(param_kmac->protkey, protkey->protkey, sizeof(param_kmac->protkey));

					rv = pthread_mutex_unlock(&aes_ccm->aes_key->lock);
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
zpc_aes_ccm_free(struct zpc_aes_ccm **aes_ccm)
{
	if (aes_ccm == NULL)
		return;
	if (*aes_ccm == NULL)
		return;

	if ((*aes_ccm)->key_set) {
		/* Decrease aes_key's refcount. */
		zpc_aes_key_free(&(*aes_ccm)->aes_key);
		(*aes_ccm)->key_set = 0;
		__aes_ccm_reset_iv(*aes_ccm);
		(*aes_ccm)->iv_set = 0;
	}

	__aes_ccm_reset(*aes_ccm);

	free(*aes_ccm);
	*aes_ccm = NULL;
	DEBUG("return");
}

static void
__aes_ccm_set_iv(struct zpc_aes_ccm *aes_ccm, const u8 * iv, size_t ivlen)
{
	assert(aes_ccm != NULL);
	assert(iv != NULL);

	memset(aes_ccm->param_kma.reserved, 0,
	    sizeof(aes_ccm->param_kma.reserved));
	memset(aes_ccm->param_kma.t, 0, sizeof(aes_ccm->param_kma.t));
	memset(aes_ccm->param_kma.h, 0, sizeof(aes_ccm->param_kma.h));
	memset(aes_ccm->param_kma.j0, 0, sizeof(aes_ccm->param_kma.j0));
	aes_ccm->param_kma.cv = 0;
	aes_ccm->param_kma.taadl = 0;
	aes_ccm->param_kma.tpcl = 0;
	memset(aes_ccm->param_kmac.icv, 0, sizeof(aes_ccm->param_kmac.icv));

	memset(aes_ccm->iv, 0, sizeof(aes_ccm->iv));
	aes_ccm->ivlen = ivlen;
	memcpy(aes_ccm->iv, iv, ivlen);
}

static int
__aes_ccm_crypt(struct zpc_aes_ccm *aes_ccm, u8 * out, u8 * tag, size_t taglen,
    const u8 * aad, size_t aadlen, const u8 * in, size_t inlen,
    unsigned long flags, int key_sec)
{
	struct aes_ccm_flags b0flags;
	u8 b01[32], tmp[16];
	int rc, cc;
	size_t rem, i;

	assert(aes_ccm != NULL);
	assert(aes_ccm->key_set == 1);
	assert(aes_ccm->iv_set == 1);

	memset(&b0flags, 0, sizeof(b0flags));
	memset(b01, 0, sizeof(b01));

	if (aadlen)
		b0flags.adata = 1;
	b0flags.m = taglen / 2 - 1;
	assert(b0flags.m != 0);
	b0flags.l = (15 - aes_ccm->ivlen) - 1;
	assert(b0flags.l != 0);

	memcpy(b01, &b0flags, 1);
	memcpy(b01 + 1, aes_ccm->iv, aes_ccm->ivlen);
	for (i = 0; i < 16 - 1 - aes_ccm->ivlen; i++)
		b01[15 - i] = ((u8 *) & inlen)[sizeof(inlen) - 1 - i];

	if (b0flags.adata == 1) {
		if (aadlen < (1ULL << 16) - (1ULL << 8)) {
			*(u16 *) (&(b01[16])) = aadlen;
			i = 16 + 2;
		} else if (aadlen <= 1ULL << 32) {
			*(u16 *) (&(b01[16])) = 0xfffe;
			*(u32 *) (&(b01[16])) = aadlen;
			i = 16 + 6;
		} else {
			*(u16 *) (&(b01[16])) = 0xffff;
			*(u64 *) (&(b01[16])) = aadlen;
			i = 16 + 10;
		}
		while (i < 32 && aadlen) {
			b01[i] = *aad;
			aad++;
			aadlen--;
			i++;
		}
		while (i < 32) {
			b01[i] = 0;
			i++;
		}
	}

	memset(aes_ccm->param_kmac.icv, 0, sizeof(aes_ccm->param_kmac.icv));

	cc = cpacf_kmac(aes_ccm->fc, &aes_ccm->param_kmac, b01,
	    b0flags.adata == 1 ? 32 : 16);
	/* Either incomplete processing or WKaVP mismatch. */
	assert(cc == 0 || cc == 2 || cc == 1);
	if (cc == 1) {
		rc = ZPC_ERROR_WKVPMISMATCH;
		goto ret;
	}

	rem = aadlen & 0xf;
	aadlen &= ~(size_t)0xf;
	if (aadlen) {
		cc = cpacf_kmac(aes_ccm->fc, &aes_ccm->param_kmac, aad, aadlen);
		/* Either incomplete processing or WKaVP mismatch. */
		assert(cc == 0 || cc == 2 || cc == 1);
		if (cc == 1) {
			rc = ZPC_ERROR_WKVPMISMATCH;
			goto ret;
		}
		aad += aadlen;
	}
	if (rem) {
		for (i = 0; i < rem; i++)
			tmp[i] = aad[i];
		for (; i < 16; i++)
			tmp[i] = 0;

		cc = cpacf_kmac(aes_ccm->fc, &aes_ccm->param_kmac, tmp, 16);
		/* Either incomplete processing or WKaVP mismatch. */
		assert(cc == 0 || cc == 2 || cc == 1);
		if (cc == 1) {
			rc = ZPC_ERROR_WKVPMISMATCH;
			goto ret;
		}
	}

	memset(tmp, 0, 16);

	if (!(flags & CPACF_M)) {
		/* mac-then-encrypt */
		rc = __aes_ccm_cbcmac(aes_ccm, in, inlen);
		if (rc)
			goto ret;
		rc = __aes_ccm_ctr(aes_ccm, tmp, out, in, inlen, key_sec);
		if (rc)
			goto ret;
		for (i = 0; i < 16; i++)
			tmp[i] ^= aes_ccm->param_kmac.icv[i];
		memcpy(tag, tmp, taglen);
	} else {
		/* decrypt-then-mac */
		rc = __aes_ccm_ctr(aes_ccm, tmp, out, in, inlen, key_sec);
		if (rc)
			goto ret;
		rc = __aes_ccm_cbcmac(aes_ccm, out, inlen);
		if (rc)
			goto ret;
		for (i = 0; i < taglen; i++)
			tmp[i] ^= tag[i];
		rc = memcmp_consttime(tmp, aes_ccm->param_kmac.icv, taglen);
		if (rc) {
			rc = ZPC_ERROR_TAGMISMATCH;
			goto ret;
		}
	}

	rc = 0;
ret:
	if (rc == ZPC_ERROR_TAGMISMATCH) {
		memset(out, 0, inlen);
	}
	return rc;
}

static int
__aes_ccm_cbcmac(struct zpc_aes_ccm *aes_ccm, const u8 * in, size_t inlen)
{
	struct aes_ccm_flags aflags;
	u8 a[16], tmp[16];
	int rc, cc;
	size_t rem, i;

	memset(&aflags, 0, sizeof(aflags));
	memset(a, 0, sizeof(a));

	rem = inlen & 0xf;
	inlen &= ~(size_t)0xf;
	if (inlen) {
		cc = cpacf_kmac(aes_ccm->fc, &aes_ccm->param_kmac, in, inlen);
		/* Either incomplete processing or WKaVP mismatch. */
		assert(cc == 0 || cc == 2 || cc == 1);
		if (cc == 1) {
			rc = ZPC_ERROR_WKVPMISMATCH;
			goto ret;
		}
	}
	if (rem) {
		for (i = 0; i < rem; i++)
			tmp[i] = in[inlen + i];
		for (; i < 16; i++)
			tmp[i] = 0;

		cc = cpacf_kmac(aes_ccm->fc, &aes_ccm->param_kmac, tmp, 16);
		/* Either incomplete processing or WKaVP mismatch. */
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

static int
__aes_ccm_ctr(struct zpc_aes_ccm *aes_ccm, u8 tagkey[16], u8 * out,
    const u8 * in, size_t inlen, int key_sec)
{
	struct aes_ccm_flags aflags;
	unsigned int flags;
	u8 a[16];
	int rc, cc;
	u32 ctr;
	u8 *in_pos = (u8 *)in;
	u8 *out_pos = out;
	size_t len = inlen;
	size_t bytes_processed, dummy;
	struct cpacf_kma_gcm_aes_param *param_kma;
	struct cpacf_kmac_aes_param *param_kmac;
	struct pkey_protkey *protkey;
	int rv;

	flags = CPACF_KMA_LAAD | CPACF_KMA_HS;

	memset(&aflags, 0, sizeof(aflags));
	memset(a, 0, sizeof(a));

	aflags.l = (15 - aes_ccm->ivlen) - 1;
	assert(aflags.l != 0);

	memcpy(a, &aflags, 1);
	memcpy(a + 1, aes_ccm->iv, aes_ccm->ivlen);

	memcpy(&ctr, a + 16 - 4, 4);
	ctr--;  /* KMA pre-inc */
	memcpy(a + 16 - 4, &ctr, 4);

	memset(aes_ccm->param_kma.reserved, 0,
	    sizeof(aes_ccm->param_kma.reserved));
	aes_ccm->param_kma.cv = ctr;
	memcpy(aes_ccm->param_kma.j0, a, 16);

	memset(tagkey, 0, 16);

	cc = cpacf_kma(aes_ccm->fc | flags, &aes_ccm->param_kma, tagkey, NULL,
	    0, tagkey, 16, &dummy);
	/* Either incomplete processing or WKaVP mismatch. */
	assert(cc == 0 || cc == 2 || cc == 1);
	if (cc == 1) {
		rc = ZPC_ERROR_WKVPMISMATCH;
		goto ret;
	}

	for (;;) {
		flags = len > 16 ? flags : flags | CPACF_KMA_LPC;

		cc = cpacf_kma(aes_ccm->fc | flags, &aes_ccm->param_kma,
			out_pos, NULL, 0, in_pos, len, &bytes_processed);

		/* Either incomplete processing or WKaVP mismatch. */
		assert(cc == 0 || cc == 2 || cc == 1);
		switch (cc) {
		case 0:
		case 2:
			/* No wkvp mismatch, but some rest may be left over because lpc not yet set */
			if (bytes_processed == len) {
				rc = 0;
				goto ret;
			}
			in_pos += bytes_processed;
			out_pos += bytes_processed;
			len -= bytes_processed;
			break;
		case 1:
			/* wkvp mismatch, rederive protkey and continue */
			if (aes_ccm->aes_key->rand_protk) {
				rc = ZPC_ERROR_PROTKEYONLY;
				goto ret;
			}

			rv = pthread_mutex_lock(&aes_ccm->aes_key->lock);
			assert(rv == 0);
			DEBUG
				("aes-ccm context at %p: re-derive protected key from %s secure key from aes key at %p",
				aes_ccm, key_sec == 0 ? "current" : "old",
				aes_ccm->aes_key);
			rc = aes_key_sec2prot(aes_ccm->aes_key, key_sec);
			param_kma = &aes_ccm->param_kma;
			param_kmac = &aes_ccm->param_kmac;
			protkey = &aes_ccm->aes_key->prot;
			memcpy(param_kma->protkey, protkey->protkey, sizeof(param_kma->protkey));
			memcpy(param_kmac->protkey, protkey->protkey, sizeof(param_kmac->protkey));
			rv = pthread_mutex_unlock(&aes_ccm->aes_key->lock);
			assert(rv == 0);

			in_pos += bytes_processed;
			out_pos += bytes_processed;
			inlen -= bytes_processed;
			len = inlen;
			break;
		default:
			/* Cannot occur */
			break;
		}
	}

	rc = 0;
ret:
	return rc;
}

static void
__aes_ccm_reset(struct zpc_aes_ccm *aes_ccm)
{
	assert(aes_ccm != NULL);

	memset(&aes_ccm->param_kma, 0, sizeof(aes_ccm->param_kma));
	memset(&aes_ccm->param_kmac, 0, sizeof(aes_ccm->param_kmac));

	__aes_ccm_reset_iv(aes_ccm);
	aes_ccm->iv_set = 0;

	if (aes_ccm->aes_key != NULL)
		zpc_aes_key_free(&aes_ccm->aes_key);
	aes_ccm->key_set = 0;

	aes_ccm->fc = 0;
}

static void
__aes_ccm_reset_iv(struct zpc_aes_ccm *aes_ccm)
{
	assert(aes_ccm != NULL);

	memset(aes_ccm->param_kma.reserved, 0,
	    sizeof(aes_ccm->param_kma.reserved));
	memset(aes_ccm->param_kma.t, 0, sizeof(aes_ccm->param_kma.t));
	memset(aes_ccm->param_kma.h, 0, sizeof(aes_ccm->param_kma.h));
	memset(aes_ccm->param_kma.j0, 0, sizeof(aes_ccm->param_kma.j0));
	aes_ccm->param_kma.cv = 0;
	aes_ccm->param_kma.taadl = 0;
	aes_ccm->param_kma.tpcl = 0;
	memset(aes_ccm->param_kmac.icv, 0, sizeof(aes_ccm->param_kmac.icv));

	memset(aes_ccm->iv, 0, sizeof(aes_ccm->iv));
	aes_ccm->ivlen = 0;

	aes_ccm->iv_set = 0;
}
