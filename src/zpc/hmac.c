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

#include "zpc/hmac.h"
#include "zpc/error.h"

#include "hmac_local.h"
#include "hmac_key_local.h"

#include "cpacf.h"
#include "globals.h"
#include "misc.h"
#include "debug.h"
#include "zkey/pkey.h"


static void __hmac_init(struct zpc_hmac *hmac);
static void __hmac_update_protkey(struct zpc_hmac *, u8 *);
static int __hmac_kmac_crypt(struct zpc_hmac *, u8 *, size_t, const u8 *, size_t);
static void __hmac_reset(struct zpc_hmac *);
static void __hmac_reset_state(struct zpc_hmac *);

const int hfunc2fc[] = {
	CPACF_KMAC_ENCRYPTED_SHA_224,
	CPACF_KMAC_ENCRYPTED_SHA_256,
	CPACF_KMAC_ENCRYPTED_SHA_384,
	CPACF_KMAC_ENCRYPTED_SHA_512,
};

extern const size_t hfunc2blksize[];

int zpc_hmac_alloc(struct zpc_hmac **hmac)
{
	struct zpc_hmac *new_hmac = NULL;
	int rc;

	if (pkeyfd < 0) {
		rc = ZPC_ERROR_DEVPKEY;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}
	if (!hwcaps.hmac_kmac) {
		rc = ZPC_ERROR_HWCAPS;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}
	if (hmac == NULL) {
		rc = ZPC_ERROR_ARG1NULL;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}

	new_hmac = calloc(1, sizeof(*new_hmac));
	if (new_hmac == NULL) {
		rc = ZPC_ERROR_MALLOC;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}

	DEBUG("hmac context at %p: allocated", new_hmac);
	*hmac = new_hmac;
	rc = 0;
	DEBUG("return %d (%s)", rc, zpc_error_string(rc));
	return rc;
}

int zpc_hmac_set_key(struct zpc_hmac *hmac, struct zpc_hmac_key *hmac_key)
{
	int rc, rv;

	UNUSED(rv);

	if (pkeyfd < 0) {
		rc = ZPC_ERROR_DEVPKEY;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}
	if (!hwcaps.hmac_kmac) {
		rc = ZPC_ERROR_HWCAPS;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}
	if (hmac == NULL) {
		rc = ZPC_ERROR_ARG1NULL;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}

	if (hmac_key == NULL) {
		/* If another key is already set, unset it and decrease
		 * refcount. */
		DEBUG("hmac context at %p: key unset", hmac);
		__hmac_reset(hmac);
		rc = 0;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}

	rv = pthread_mutex_lock(&hmac_key->lock);
	assert(rv == 0);

	rc = hmac_key_check(hmac_key);
	if (rc)
		goto ret;

	if (hmac->hmac_key == hmac_key) {
		__hmac_reset_state(hmac);
		DEBUG("hmac context at %p: key at %p already set", hmac, hmac_key);
		rc = 0;
		goto ret;
	}

	hmac_key->refcount++;
	DEBUG("hmac key at %p: refcount %llu", hmac_key, hmac_key->refcount);

	if (hmac->key_set) {
		/* If another key is already set, unset it and decrease  refcount. */
		DEBUG("hmac context at %p: key unset", hmac);
		__hmac_reset(hmac);
	}

	/* Set new key. */
	assert(!hmac->key_set);

	DEBUG("hmac context at %p: key at %p set, uninitialized", hmac, hmac_key);

	hmac->initialized = 0;
	hmac->hmac_key = hmac_key;
	hmac->key_set = 1;

	rc = 0;
ret:
	rv = pthread_mutex_unlock(&hmac_key->lock);
	assert(rv == 0);
	DEBUG("return %d (%s)", rc, zpc_error_string(rc));
	return rc;
}

/*
 * Valid tag lengths according to:
 * https://csrc.nist.gov/CSRC/media/Projects/
 * Cryptographic-Algorithm-Validation-Program/documents/mac/HMACVS.pdf
 */
static int is_valid_taglen(struct zpc_hmac *hmac, size_t taglen)
{
	switch (hmac->hmac_key->hfunc) {
	case ZPC_HMAC_HASHFUNC_SHA_224:
		switch (taglen) {
		case 14:
		case 16:
		case 20:
		case 24:
		case 28:
			return 1;
		}
		break;
	case ZPC_HMAC_HASHFUNC_SHA_256:
		switch (taglen) {
		case 16:
		case 24:
		case 32:
			return 1;
		}
		break;
	case ZPC_HMAC_HASHFUNC_SHA_384:
		switch (taglen) {
		case 24:
		case 32:
		case 40:
		case 48:
			return 1;
		}
		break;
	case ZPC_HMAC_HASHFUNC_SHA_512:
		switch (taglen) {
		case 32:
		case 40:
		case 48:
		case 56:
		case 64:
			return 1;
		}
		break;
	default:
		break;
	}

	return 0;
}

int zpc_hmac_sign(struct zpc_hmac *hmac, u8 * tag, size_t taglen,
		const u8 * m, size_t mlen)
{
	struct hmac_protkey *protkey;
	int rc, rv;

	UNUSED(rv);

	if (pkeyfd < 0) {
		rc = ZPC_ERROR_DEVPKEY;
		goto ret;
	}
	if (!hwcaps.hmac_kmac) {
		rc = ZPC_ERROR_HWCAPS;
		goto ret;
	}
	if (hmac == NULL) {
		rc = ZPC_ERROR_ARG1NULL;
		goto ret;
	}
	if (taglen > 0 && tag == NULL) {
		rc = ZPC_ERROR_ARG2NULL;
		goto ret;
	}
	if (!hmac->key_set) {
		rc = ZPC_ERROR_KEYNOTSET;
		goto ret;
	}
	if (tag != NULL && !is_valid_taglen(hmac, taglen)) {
		rc = ZPC_ERROR_TAGSIZE;
		goto ret;
	}

	if (!hmac->initialized) {
		__hmac_init(hmac);
	}

	if (mlen > 0 && mlen % hmac->blksize != 0 && tag == NULL) {
		rc = ZPC_ERROR_ARG5RANGE;
		goto ret;
	}

	rc = -1;

	protkey = &hmac->hmac_key->prot;

	for (;;) {

		rc = __hmac_kmac_crypt(hmac, tag, taglen, m, mlen);
		if (rc == 0) {
			break;
		} else {
			if (hmac->hmac_key->rand_protk) {
				rc = ZPC_ERROR_PROTKEYONLY;
				goto ret;
			}
			if (rc == ZPC_ERROR_WKVPMISMATCH) {
				rv = pthread_mutex_lock(&hmac->hmac_key->lock);
				assert(rv == 0);
				DEBUG
					("hmac context at %p: re-derive protected key from pvsecret ID from hmac key at %p",
					hmac, hmac->hmac_key);
				rc = hmac_key_sec2prot(hmac->hmac_key);
				__hmac_update_protkey(hmac, protkey->protkey);
				rv = pthread_mutex_unlock(&hmac->hmac_key->lock);
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

int zpc_hmac_verify(struct zpc_hmac *hmac, const u8 * tag, size_t taglen,
		const u8 * m, size_t mlen)
{
	struct hmac_protkey *protkey;
	int rc, rv;
	u8 tmp[64];

	UNUSED(rv);

	if (pkeyfd < 0) {
		rc = ZPC_ERROR_DEVPKEY;
		goto ret;
	}
	if (!hwcaps.hmac_kmac) {
		rc = ZPC_ERROR_HWCAPS;
		goto ret;
	}
	if (hmac == NULL) {
		rc = ZPC_ERROR_ARG1NULL;
		goto ret;
	}
	if (taglen > 0 && tag == NULL) {
		rc = ZPC_ERROR_ARG2NULL;
		goto ret;
	}
	if (!hmac->key_set) {
		rc = ZPC_ERROR_KEYNOTSET;
		goto ret;
	}
	if (tag != NULL && !is_valid_taglen(hmac, taglen)) {
		rc = ZPC_ERROR_TAGSIZE;
		goto ret;
	}

	if (!hmac->initialized) {
		__hmac_init(hmac);
	}

	if (mlen > 0 && mlen % hmac->blksize != 0 && tag == NULL) {
		rc = ZPC_ERROR_ARG5RANGE;
		goto ret;
	}

	rc = -1;

	protkey = &hmac->hmac_key->prot;

	for (;;) {

		rc = __hmac_kmac_crypt(hmac, tag == NULL ? NULL : tmp,
					tag == NULL ? 0 : sizeof(tmp), m, mlen);
		if (rc == 0) {
			if (tag != NULL) {
				rc = memcmp_consttime(tmp, tag, taglen);
				if (rc != 0)
					rc = ZPC_ERROR_TAGMISMATCH;
			}
			break;
		} else {
			if (hmac->hmac_key->rand_protk) {
				rc = ZPC_ERROR_PROTKEYONLY;
				goto ret;
			}
			if (rc == ZPC_ERROR_WKVPMISMATCH) {
				rv = pthread_mutex_lock(&hmac->hmac_key->lock);
				assert(rv == 0);
				DEBUG
					("hmac context at %p: re-derive protected key from pvsecret ID from hmac key at %p",
					hmac, hmac->hmac_key);
				rc = hmac_key_sec2prot(hmac->hmac_key);
				__hmac_update_protkey(hmac, protkey->protkey);
				rv = pthread_mutex_unlock(&hmac->hmac_key->lock);
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

void zpc_hmac_free(struct zpc_hmac **hmac)
{
	if (hmac == NULL)
		return;
	if (*hmac == NULL)
		return;

	if ((*hmac)->key_set) {
		/* Decrease hmac_key's refcount. */
		zpc_hmac_key_free(&(*hmac)->hmac_key);
		(*hmac)->key_set = 0;
	}

	__hmac_reset(*hmac);

	free(*hmac);
	*hmac = NULL;
	DEBUG("return");
}

static void __hmac_update_imbl(struct zpc_hmac *hmac, long bitlen)
{
	switch (hmac->hmac_key->hfunc) {
	case ZPC_HMAC_HASHFUNC_SHA_224:
	case ZPC_HMAC_HASHFUNC_SHA_256:
		hmac->param_kmac.hmac_224_256.imbl += bitlen;
		break;
	case ZPC_HMAC_HASHFUNC_SHA_384:
	case ZPC_HMAC_HASHFUNC_SHA_512:
		hmac->param_kmac.hmac_384_512.imbl += bitlen;
		break;
	default:
		break;
	}
}

static void __hmac_update_protkey(struct zpc_hmac *hmac, u8 *protkey)
{
	switch (hmac->hmac_key->hfunc) {
	case ZPC_HMAC_HASHFUNC_SHA_224:
	case ZPC_HMAC_HASHFUNC_SHA_256:
		memcpy(&hmac->param_kmac.hmac_224_256.protkey, protkey,
			sizeof(hmac->param_kmac.hmac_224_256.protkey));
		break;
	case ZPC_HMAC_HASHFUNC_SHA_384:
	case ZPC_HMAC_HASHFUNC_SHA_512:
		memcpy(&hmac->param_kmac.hmac_384_512.protkey, protkey,
			sizeof(hmac->param_kmac.hmac_384_512.protkey));
		break;
	default:
		break;
	}
}

/*
 * Initialize the CPACF parmblock for the KMAC instruction. Note that the
 * SHA ICV values (H0 ... H7) are initialized with zeroes. The KMAC
 * instruction sets the related ICV values internally.
 */
static void __hmac_init(struct zpc_hmac *hmac)
{
	memset(&hmac->param_kmac, 0, sizeof(hmac->param_kmac));

	__hmac_update_protkey(hmac, hmac->hmac_key->prot.protkey);

	hmac->blksize = hfunc2blksize[hmac->hmac_key->hfunc];
	hmac->fc = hfunc2fc[hmac->hmac_key->hfunc];
	hmac->initialized = 1;
}

static int __hmac_kmac_crypt(struct zpc_hmac *hmac, u8 * tag, size_t taglen,
		const u8 * in, size_t inlen)
{
	int rc, cc;
	unsigned int flags = 0;

	assert(hmac != NULL);
	assert((tag != NULL) || (tag == NULL && inlen % hmac->blksize == 0));

	if (tag == NULL)
		flags |= CPACF_KMAC_IIMP;
	if (hmac->ikp)
		flags |= CPACF_KMAC_IKP;

	__hmac_update_imbl(hmac, inlen * 8);

	cc = cpacf_kmac(hmac->fc | flags, &hmac->param_kmac, in, inlen);
	assert(cc == 0 || cc == 1);
	if (cc == 1) {
		__hmac_update_imbl(hmac, -inlen * 8); /* decrease imbl for retry */
		rc = ZPC_ERROR_WKVPMISMATCH;
		goto err;
	}

	hmac->ikp = 1;

	if (tag != NULL) {
		switch (hmac->hmac_key->hfunc) {
		case ZPC_HMAC_HASHFUNC_SHA_224:
		case ZPC_HMAC_HASHFUNC_SHA_256:
			memcpy(tag, &hmac->param_kmac.hmac_224_256.h, taglen);
			break;
		case ZPC_HMAC_HASHFUNC_SHA_384:
		case ZPC_HMAC_HASHFUNC_SHA_512:
			memcpy(tag, &hmac->param_kmac.hmac_384_512.h, taglen);
			break;
		}
		__hmac_reset_state(hmac);
	}

	rc = 0;
err:
	return rc;
}

static void __hmac_reset(struct zpc_hmac *hmac)
{
	assert(hmac != NULL);

	__hmac_reset_state(hmac);
	memset(&hmac->param_kmac, 0, sizeof(hmac->param_kmac));

	if (hmac->hmac_key != NULL)
		zpc_hmac_key_free(&hmac->hmac_key);
	hmac->key_set = 0;

	hmac->fc = 0;
}

static void __hmac_reset_state(struct zpc_hmac *hmac)
{
	assert(hmac != NULL);

	hmac->initialized = 0;
	hmac->ikp = 0;
	memset(&hmac->param_kmac.hmac_224_256.h, 0, sizeof(hmac->param_kmac.hmac_224_256.h));
	memset(&hmac->param_kmac.hmac_224_256.imbl, 0, sizeof(hmac->param_kmac.hmac_224_256.imbl));
	memset(&hmac->param_kmac.hmac_384_512.h, 0, sizeof(hmac->param_kmac.hmac_384_512.h));
	memset(&hmac->param_kmac.hmac_384_512.imbl, 0, sizeof(hmac->param_kmac.hmac_384_512.imbl));
}
