/*
 * Copyright IBM Corp. 2021
 *
 * libzpc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <stdbool.h>

#include "zpc/error.h"
#include "zpc/ecdsa_ctx.h"

#include "ecc_key_local.h"
#include "ecdsa_ctx_local.h"
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

extern const size_t curve2siglen[];

static int __ec_sign(struct zpc_ecdsa_ctx *, const unsigned char *hash,
		unsigned int hash_len, unsigned char *signature, unsigned int *sig_len);
static int __ec_verify(struct zpc_ecdsa_ctx *, const unsigned char *hash,
		unsigned int hash_len, const unsigned char *signature, unsigned int sig_len);
static void __ec_ctx_reset(struct zpc_ecdsa_ctx *);
static void __copy_hash_to_sign_param(struct zpc_ecdsa_ctx *ctx,
		const unsigned char *hash, unsigned int hash_len);
static void __get_signature_from_sign_param(struct zpc_ecdsa_ctx *ctx,
		unsigned char *signature, unsigned int sig_len);
static void __copy_pubkey_to_verify_param(struct zpc_ecdsa_ctx *ctx);
static void __copy_protkey_to_sign_param(struct zpc_ecdsa_ctx *ctx);
static void __copy_args_to_verify_param(struct zpc_ecdsa_ctx *ctx,
		const unsigned char *hash, unsigned int hash_len,
		const unsigned char *signature, unsigned int sig_len);
static void __cleanup_verify_param(struct zpc_ecdsa_ctx *ctx);
static void __cleanup_sign_param(struct zpc_ecdsa_ctx *ctx);


size_t group_size[] = { 32, 48, 66 };

int zpc_ecdsa_ctx_alloc(struct zpc_ecdsa_ctx **ec_ctx)
{
	struct zpc_ecdsa_ctx *new_ec_ctx = NULL;
	int rc;

	if (pkeyfd < 0) {
		rc = ZPC_ERROR_DEVPKEY;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}
	if (!hwcaps.ecc_kdsa) {
		rc = ZPC_ERROR_HWCAPS;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}
	if (ec_ctx == NULL) {
		rc = ZPC_ERROR_ARG1NULL;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}

	new_ec_ctx = calloc(1, sizeof(*new_ec_ctx));
	if (new_ec_ctx == NULL) {
		rc = ZPC_ERROR_MALLOC;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}

	DEBUG("ec-ctx context at %p: allocated", new_ec_ctx);
	*ec_ctx = new_ec_ctx;
	rc = 0;
	DEBUG("return %d (%s)", rc, zpc_error_string(rc));
	return rc;
}

int zpc_ecdsa_ctx_set_key(struct zpc_ecdsa_ctx *ec_ctx, struct zpc_ec_key *ec_key)
{
	int rc, rv;
	const unsigned int fc_sign_from_curve[] = {
		CPACF_KDSA_ENCRYPTED_ECDSA_SIGN_P256,
		CPACF_KDSA_ENCRYPTED_ECDSA_SIGN_P384,
		CPACF_KDSA_ENCRYPTED_ECDSA_SIGN_P521,
		CPACF_KDSA_ENCRYPTED_EDDSA_SIGN_ED25519,
		CPACF_KDSA_ENCRYPTED_EDDSA_SIGN_ED448,
	};
	const unsigned int fc_verify_from_curve[] = {
		CPACF_KDSA_ECDSA_VERIFY_ECP256,
		CPACF_KDSA_ECDSA_VERIFY_ECP384,
		CPACF_KDSA_ECDSA_VERIFY_ECP521,
		CPACF_KDSA_EDDSA_VERIFY_ED25519,
		CPACF_KDSA_EDDSA_VERIFY_ED448,
	};

	UNUSED(rv);

	if (pkeyfd < 0) {
		rc = ZPC_ERROR_DEVPKEY;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}
	if (!hwcaps.ecc_kdsa) {
		rc = ZPC_ERROR_HWCAPS;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}
	if (ec_ctx == NULL) {
		rc = ZPC_ERROR_ARG1NULL;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}

	if (ec_key == NULL) {
		/* If another key is already set, unset it and decrease
		 * refcount. */
		DEBUG("ec-ctx context at %p: key unset", ec_ctx);
		__ec_ctx_reset(ec_ctx);
		rc = 0;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}

	rv = pthread_mutex_lock(&ec_key->lock);
	assert(rv == 0);

	rc = ec_key_check(ec_key);
	if (rc)
		goto ret;

	if (ec_ctx->ec_key == ec_key) {
		DEBUG("ec-ctx context at %p: key at %p already set", ec_ctx, ec_key);
		rc = 0; /* nothing to do */
		goto ret;
	}

	ec_key->refcount++;
	DEBUG("ec key at %p: refcount %llu", ec_key, ec_key->refcount);

	if (ec_ctx->key_set) {
		/* If another key is already set, unset it and decrease
		 * refcount. */
		DEBUG("ec-ctx context at %p: key unset", ec_ctx);
		__ec_ctx_reset(ec_ctx);
	}

	/* Set new key. */
	assert(!ec_ctx->key_set);

	DEBUG("ec-ctx context at %p: key at %p set", ec_ctx, ec_key);

	if (!ec_key->curve_set) {
		DEBUG("ec-ctx context at %p: key has no curve property", ec_ctx);
		rc = ZPC_ERROR_EC_CURVE_NOTSET;
		goto ret;
	}

	ec_ctx->fc_sign = fc_sign_from_curve[ec_key->curve];
	ec_ctx->fc_verify = fc_verify_from_curve[ec_key->curve];

	ec_ctx->ec_key = ec_key;
	ec_ctx->key_set = 1;

	if (ec_key->key_set)
		__copy_protkey_to_sign_param(ec_ctx);

	if (ec_key->pubkey_set)
		__copy_pubkey_to_verify_param(ec_ctx);

	rc = 0;
ret:
	rv = pthread_mutex_unlock(&ec_key->lock);
	assert(rv == 0);
	DEBUG("return %d (%s)", rc, zpc_error_string(rc));
	return rc;
}

int zpc_ecdsa_sign(struct zpc_ecdsa_ctx *ctx,
			const unsigned char *hash, unsigned int hash_len,
			unsigned char *signature, unsigned int *sig_len)
{
	int rc, rv, i;

	UNUSED(rv);

	if (pkeyfd < 0) {
		rc = ZPC_ERROR_DEVPKEY;
		goto ret;
	}
	if (!hwcaps.ecc_kdsa) {
		rc = ZPC_ERROR_HWCAPS;
		goto ret;
	}
	if (ctx == NULL) {
		rc = ZPC_ERROR_ARG1NULL;
		goto ret;
	}

	if (!ctx->key_set) {
		rc = ZPC_ERROR_EC_PRIVKEY_NOTSET;
		goto ret;
	}

	if (ctx->ec_key->curve == ZPC_EC_CURVE_P256 ||
		ctx->ec_key->curve == ZPC_EC_CURVE_P384 ||
		ctx->ec_key->curve == ZPC_EC_CURVE_P521) {
		if (hash == NULL || hash_len == 0) {
			rc = ZPC_ERROR_ARG2NULL;
			goto ret;
		}
	}

	/* If the hash/msg is longer than the group size, truncate the input
	 * according to NIST SP 800-107, section 5.1 Truncated Message Digest:
	 * use leftmost bytes and discard rightmost bytes.
	 * For p521 CPACF requires the 7 leftmost bytes to be zero to form a 521
	 * bit input. */
	if (ctx->ec_key->curve == ZPC_EC_CURVE_P256 ||
		ctx->ec_key->curve == ZPC_EC_CURVE_P384 ||
		ctx->ec_key->curve == ZPC_EC_CURVE_P521) {
		if (hash_len > group_size[ctx->ec_key->curve]) {
			hash_len = group_size[ctx->ec_key->curve];
		}
	}

	if (signature == NULL) {
		*sig_len = curve2siglen[ctx->ec_key->curve];
		rc = 0;
		goto ret;
	}

	if (*sig_len < curve2siglen[ctx->ec_key->curve]) {
		rc = ZPC_ERROR_SMALLOUTBUF;
		goto ret;
	}

	rc = -1;
	for (i = 0; i < 2 && rc != 0; i++) {
		assert(i == EC_KEY_SEC_CUR || i == EC_KEY_SEC_OLD);

		for (;;) {
			rc = __ec_sign(ctx, hash, hash_len, signature, sig_len);
			if (rc == 0) {
				break;
			} else {
				if (rc == ZPC_ERROR_WKVPMISMATCH) {
					rv = pthread_mutex_lock(&ctx->ec_key->lock);
					assert(rv == 0);

					DEBUG("ec context at %p: re-derive protected key from %s secure key from ec key at %p",
						ctx, i == 0 ? "current" : "old", ctx->ec_key);
					rc = ec_key_sec2prot(ctx->ec_key, i);

					__copy_protkey_to_sign_param(ctx);

					rv = pthread_mutex_unlock(&ctx->ec_key->lock);
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

int zpc_ecdsa_verify(struct zpc_ecdsa_ctx *ctx,
			const unsigned char *hash, unsigned int hash_len,
			const unsigned char *signature, unsigned int sig_len)
{
	int rc, rv;

	UNUSED(rv);

	if (pkeyfd < 0) {
		rc = ZPC_ERROR_DEVPKEY;
		goto ret;
	}
	if (!hwcaps.ecc_kdsa) {
		rc = ZPC_ERROR_HWCAPS;
		goto ret;
	}
	if (ctx == NULL) {
		rc = ZPC_ERROR_ARG1NULL;
		goto ret;
	}
	if (ctx->ec_key == NULL) {
		rc = ZPC_ERROR_EC_NO_KEY_PARTS;
		goto ret;
	}

	if (ctx->ec_key->curve == ZPC_EC_CURVE_P256 ||
		ctx->ec_key->curve == ZPC_EC_CURVE_P384 ||
		ctx->ec_key->curve == ZPC_EC_CURVE_P521) {
		if (hash == NULL || hash_len == 0) {
			rc = ZPC_ERROR_ARG2NULL;
			goto ret;
		}
	}

	if (ctx->ec_key->curve == ZPC_EC_CURVE_P256 ||
		ctx->ec_key->curve == ZPC_EC_CURVE_P384 ||
		ctx->ec_key->curve == ZPC_EC_CURVE_P521) {
		if (hash_len > group_size[ctx->ec_key->curve]) {
			hash_len = group_size[ctx->ec_key->curve];
		}
	}

	if (signature == NULL || sig_len == 0) {
		rc = ZPC_ERROR_ARG3NULL;
		goto ret;
	}

	if (sig_len != curve2siglen[ctx->ec_key->curve]) {
		rc = ZPC_ERROR_EC_SIGNATURE_LENGTH;
		goto ret;
	}

	if (!ctx->ec_key->pubkey_set) {
		rc = ZPC_ERROR_EC_PUBKEY_NOTSET;
		goto ret;
	}

	rc = __ec_verify(ctx, hash, hash_len, signature, sig_len);

ret:
	DEBUG("return %d (%s)", rc, zpc_error_string(rc));
	return rc;
}

void zpc_ecdsa_ctx_free(struct zpc_ecdsa_ctx **ctx)
{
	if (ctx == NULL)
		return;
	if (*ctx == NULL)
		return;

	if ((*ctx)->key_set) {
		/* Decrease EC key's refcount. */
		zpc_ec_key_free(&(*ctx)->ec_key);
		(*ctx)->key_set = 0;
	}

	__ec_ctx_reset(*ctx);

	free(*ctx);
	*ctx = NULL;
	DEBUG("return");
}

static int __ec_sign(struct zpc_ecdsa_ctx *ctx,
				const unsigned char *hash, unsigned int hash_len,
				unsigned char *signature, unsigned int *sig_len)
{
	void *param;
	int rc, cc;

	if (!ctx->ec_key->key_set) {
		rc = ZPC_ERROR_EC_PRIVKEY_NOTSET;
		goto err;
	}

	param = &ctx->signbuf;

	__copy_hash_to_sign_param(ctx, hash, hash_len);

	cc = cpacf_kdsa(ctx->fc_sign, param, hash, hash_len);
	assert(cc == 0 || cc == 1 || cc == 2);
	if (cc == 1) {
		rc = ZPC_ERROR_WKVPMISMATCH;
		goto err;
	}

	*sig_len = curve2siglen[ctx->ec_key->curve];
	__get_signature_from_sign_param(ctx, signature, *sig_len);

	__cleanup_sign_param(ctx);

	rc = 0;
err:
	return rc;
}

static int __ec_verify(struct zpc_ecdsa_ctx *ctx,
				const unsigned char *hash, unsigned int hash_len,
				const unsigned char *signature, unsigned int sig_len)
{
	void *param;
	int rc = ZPC_ERROR_EC_SIGNATURE_INVALID, cc;

	if (!ctx->ec_key->pubkey_set) {
		rc = ZPC_ERROR_EC_PUBKEY_NOTSET;
		goto err;
	}

	__copy_args_to_verify_param(ctx, hash, hash_len, signature, sig_len);

	param = &ctx->verifybuf;

	cc = cpacf_kdsa(ctx->fc_verify, param, hash, hash_len);
	if (cc == 0)
		rc = 0;

	__cleanup_verify_param(ctx);

err:
	return rc;
}

static void __ec_ctx_reset(struct zpc_ecdsa_ctx *ctx)
{
	assert(ctx != NULL);

	memset(&ctx->signbuf, 0, sizeof(ctx->signbuf));

	if (ctx->ec_key != NULL)
		zpc_ec_key_free(&ctx->ec_key);
	ctx->key_set = 0;

	ctx->fc_sign = 0;
	ctx->fc_verify = 0;
}

static void __copy_hash_to_sign_param(struct zpc_ecdsa_ctx *ctx,
						const unsigned char *hash, unsigned int hash_len)
{
	switch (ctx->ec_key->curve) {
	case ZPC_EC_CURVE_P256:
		memset(ctx->p256_sign_param.hash, 0, 32);
		memcpy(ctx->p256_sign_param.hash + 32 - hash_len, hash, hash_len);
		break;
	case ZPC_EC_CURVE_P384:
		memset(ctx->p384_sign_param.hash, 0, 48);
		memcpy(ctx->p384_sign_param.hash + 48 - hash_len, hash, hash_len);
		break;
	case ZPC_EC_CURVE_P521:
		memset(ctx->p521_sign_param.hash, 0, 80);
		memcpy(ctx->p521_sign_param.hash + 80 - hash_len, hash, hash_len);
		break;
	case ZPC_EC_CURVE_ED25519:
	case ZPC_EC_CURVE_ED448:
		/* For ED curves do nothing: the input hash is specified via KDSA
		 * parms, not in the CPACF parm block. */
		break;
	}
}

static void __get_signature_from_sign_param(struct zpc_ecdsa_ctx *ctx,
								unsigned char *signature, unsigned int sig_len)
{
	switch (ctx->ec_key->curve) {
	case ZPC_EC_CURVE_P256:
		memcpy(signature, ctx->p256_sign_param.sig_r, 32);
		memcpy(signature + sizeof(ctx->p256_sign_param.sig_r), ctx->p256_sign_param.sig_s, 32);
		break;
	case ZPC_EC_CURVE_P384:
		memcpy(signature, ctx->p384_sign_param.sig_r, 48);
		memcpy(signature + sizeof(ctx->p384_sign_param.sig_r), ctx->p384_sign_param.sig_s, 48);
		break;
	case ZPC_EC_CURVE_P521:
		memcpy(signature, ctx->p521_sign_param.sig_r + 80 - 66, sig_len / 2);
		memcpy(signature + (sig_len / 2), ctx->p521_sign_param.sig_s + 80 - 66, sig_len / 2);
		break;
	case ZPC_EC_CURVE_ED25519:
		s390_flip_endian_32(signature, ctx->ed25519_sign_param.sig_r);
		s390_flip_endian_32(signature + 32, ctx->ed25519_sign_param.sig_s);
		break;
	case ZPC_EC_CURVE_ED448:
		s390_flip_endian_64(ctx->ed448_sign_param.sig_r, ctx->ed448_sign_param.sig_r);
		s390_flip_endian_64(ctx->ed448_sign_param.sig_s, ctx->ed448_sign_param.sig_s);
		memcpy(signature, ctx->ed448_sign_param.sig_r, 57);
		memcpy(signature + 57, ctx->ed448_sign_param.sig_s, 57);
		break;
	}
}

static void __copy_pubkey_to_verify_param(struct zpc_ecdsa_ctx *ctx)
{
	unsigned char *pubkey = (unsigned char *)&ctx->ec_key->pub.pubkey;
	size_t publen = ctx->ec_key->pub.publen;

	switch (ctx->ec_key->curve) {
	case ZPC_EC_CURVE_P256:
		memcpy(ctx->p256_verify_param.pub_x, pubkey, publen);
		break;
	case ZPC_EC_CURVE_P384:
		memcpy(ctx->p384_verify_param.pub_x, pubkey, publen);
		break;
	case ZPC_EC_CURVE_P521:
		memcpy(ctx->p521_verify_param.pub_x + 80 - (publen / 2), pubkey, publen / 2);
		memcpy(ctx->p521_verify_param.pub_y + 80 - (publen / 2), pubkey + (publen / 2), publen / 2);
		break;
	case ZPC_EC_CURVE_ED25519:
		s390_flip_endian_32(ctx->ed25519_verify_param.pub, pubkey);
		break;
	case ZPC_EC_CURVE_ED448:
		memcpy(ctx->ed448_verify_param.pub, pubkey, publen);
		s390_flip_endian_64(ctx->ed448_verify_param.pub, ctx->ed448_verify_param.pub);
		break;
	}
}

static void __copy_protkey_to_sign_param(struct zpc_ecdsa_ctx *ctx)
{
	u8 *protkey = (unsigned char *)&ctx->ec_key->prot.protkey;

	switch (ctx->ec_key->curve) {
	case ZPC_EC_CURVE_P256:
		memcpy(ctx->p256_sign_param.prot, protkey, 32);
		memcpy(ctx->p256_sign_param.wkvp, protkey + 32, 32);
		break;
	case ZPC_EC_CURVE_P384:
		memcpy(ctx->p384_sign_param.prot, protkey, 48);
		memcpy(ctx->p384_sign_param.wkvp, protkey + 48, 32);
		break;
	case ZPC_EC_CURVE_P521:
		memcpy(ctx->p521_sign_param.prot, protkey, 80);
		memcpy(ctx->p521_sign_param.wkvp, protkey + 80, 32);
		break;
	case ZPC_EC_CURVE_ED25519:
		memcpy(ctx->ed25519_sign_param.prot, protkey, 32);
		memcpy(ctx->ed25519_sign_param.wkvp, protkey + 32, 32);
		break;
	case ZPC_EC_CURVE_ED448:
		memcpy(ctx->ed448_sign_param.prot, protkey, 64);
		memcpy(ctx->ed448_sign_param.wkvp, protkey + 64, 32);
		break;
	}
}

static void __copy_args_to_verify_param(struct zpc_ecdsa_ctx *ctx,
						const unsigned char *hash, unsigned int hash_len,
						const unsigned char *signature, unsigned int sig_len)
{
	switch (ctx->ec_key->curve) {
	case ZPC_EC_CURVE_P256:
		memset(ctx->p256_verify_param.hash, 0, 32);
		memcpy(ctx->p256_verify_param.hash + 32 - hash_len, hash, hash_len);
		memcpy(ctx->p256_verify_param.sig_r, signature, sig_len);
		break;
	case ZPC_EC_CURVE_P384:
		memset(ctx->p384_verify_param.hash, 0, 48);
		memcpy(ctx->p384_verify_param.hash + 48 - hash_len, hash, hash_len);
		memcpy(ctx->p384_verify_param.sig_r, signature, sig_len);
		break;
	case ZPC_EC_CURVE_P521:
		memset(ctx->p521_verify_param.hash, 0, 80);
		memcpy(ctx->p521_verify_param.hash + 80 - hash_len, hash, hash_len);
		memcpy(ctx->p521_verify_param.sig_r + 80 - (sig_len / 2), signature, sig_len / 2);
		memcpy(ctx->p521_verify_param.sig_s + 80 - (sig_len / 2), signature + (sig_len / 2), sig_len / 2);
		break;
	case ZPC_EC_CURVE_ED25519:
		s390_flip_endian_32(ctx->ed25519_verify_param.sig_r, signature);
		s390_flip_endian_32(ctx->ed25519_verify_param.sig_s, signature + 32);
		break;
	case ZPC_EC_CURVE_ED448:
		memcpy(ctx->ed448_verify_param.sig_r, signature, sig_len / 2);
		memcpy(ctx->ed448_verify_param.sig_s, signature + (sig_len / 2), sig_len / 2);
		s390_flip_endian_64(ctx->ed448_verify_param.sig_r, ctx->ed448_verify_param.sig_r);
		s390_flip_endian_64(ctx->ed448_verify_param.sig_s, ctx->ed448_verify_param.sig_s);
		break;
	}
}

static void __cleanup_sign_param(struct zpc_ecdsa_ctx *ctx)
{
	switch (ctx->ec_key->curve) {
	case ZPC_EC_CURVE_P256:
		memset(ctx->p256_sign_param.hash, 0, sizeof(ctx->p256_sign_param.hash));
		/* zeroize both, sig_r and sig_s */
		memset(ctx->p256_sign_param.sig_r, 0,
			sizeof(ctx->p256_sign_param.sig_r) + sizeof(ctx->p256_sign_param.sig_s));
		break;
	case ZPC_EC_CURVE_P384:
		memset(ctx->p384_sign_param.hash, 0, sizeof(ctx->p384_sign_param.hash));
		/* zeroize both, sig_r and sig_s */
		memset(ctx->p384_sign_param.sig_r, 0,
			sizeof(ctx->p384_sign_param.sig_r) + sizeof(ctx->p384_sign_param.sig_s));
		break;
	case ZPC_EC_CURVE_P521:
		memset(ctx->p521_sign_param.hash, 0, sizeof(ctx->p521_sign_param.hash));
		/* zeroize both, sig_r and sig_s */
		memset(ctx->p521_sign_param.sig_r, 0,
			sizeof(ctx->p521_sign_param.sig_r) + sizeof(ctx->p521_sign_param.sig_s));
		break;
	case ZPC_EC_CURVE_ED25519:
		/* zeroize both, sig_r and sig_s */
		memset(ctx->ed25519_sign_param.sig_r, 0,
			sizeof(ctx->ed25519_sign_param.sig_r) + sizeof(ctx->ed25519_sign_param.sig_s));
		break;
	case ZPC_EC_CURVE_ED448:
		/* zeroize both, sig_r and sig_s */
		memset(ctx->ed448_sign_param.sig_r, 0,
			sizeof(ctx->ed448_sign_param.sig_r) + sizeof(ctx->ed448_sign_param.sig_s));
		break;
	}
}

static void __cleanup_verify_param(struct zpc_ecdsa_ctx *ctx)
{
	switch (ctx->ec_key->curve) {
	case ZPC_EC_CURVE_P256:
		memset(ctx->p256_verify_param.hash, 0, sizeof(ctx->p256_verify_param.hash));
		/* zeroize both, sig_r and sig_s */
		memset(ctx->p256_verify_param.sig_r, 0,
			sizeof(ctx->p256_verify_param.sig_r) + sizeof(ctx->p256_verify_param.sig_s));
		break;
	case ZPC_EC_CURVE_P384:
		memset(ctx->p384_verify_param.hash, 0, sizeof(ctx->p384_verify_param.hash));
		/* zeroize both, sig_r and sig_s */
		memset(ctx->p384_verify_param.sig_r, 0,
			sizeof(ctx->p384_verify_param.sig_r) + sizeof(ctx->p384_verify_param.sig_s));
		break;
	case ZPC_EC_CURVE_P521:
		memset(ctx->p521_verify_param.hash, 0, sizeof(ctx->p521_verify_param.hash));
		/* zeroize both, sig_r and sig_s */
		memset(ctx->p521_verify_param.sig_r, 0,
			sizeof(ctx->p521_verify_param.sig_r) + sizeof(ctx->p521_verify_param.sig_s));
		break;
	case ZPC_EC_CURVE_ED25519:
		/* zeroize both, sig_r and sig_s */
		memset(ctx->ed25519_verify_param.sig_r, 0,
			sizeof(ctx->ed25519_verify_param.sig_r) + sizeof(ctx->ed25519_verify_param.sig_s));
		break;
	case ZPC_EC_CURVE_ED448:
		/* zeroize both, sig_r and sig_s */
		memset(ctx->ed448_verify_param.sig_r, 0,
			sizeof(ctx->ed448_verify_param.sig_r) + sizeof(ctx->ed448_verify_param.sig_s));
		break;
	}
}
