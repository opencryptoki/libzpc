/*
 * Copyright IBM Corp. 2021
 *
 * libzpc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <stdbool.h>
#include <unistd.h>

#include "zpc/ecc_key.h"
#include "zpc/error.h"

#include "ecc_key_local.h"
#include "cpacf.h"
#include "globals.h"
#include "debug.h"
#include "misc.h"
#include "zkey/pkey.h"

#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>

extern const size_t curve2publen[];
extern const size_t curve2privlen[];
extern const size_t curve2puboffset[];
extern const size_t curve2macedspkilen[];
extern const size_t curve2rawspkilen[];
extern const u32 curve2pkey_keytype[];

const u16 curve2pvsecret_type[] = {
	ZPC_EC_SECRET_ECDSA_P256,
	ZPC_EC_SECRET_ECDSA_P384,
	ZPC_EC_SECRET_ECDSA_P521,
	ZPC_EC_SECRET_EDDSA_ED25519,
	ZPC_EC_SECRET_EDDSA_ED448,
};

static void __ec_key_reset(struct zpc_ec_key *);
static int ec_key_check_ep11_spki(const struct zpc_ec_key *ec_key,
						const unsigned char *spki, unsigned int spki_len);
static void ec_key_use_maced_spki_from_buf(struct zpc_ec_key *ec_key,
						const unsigned char *spki, unsigned int spki_len);
static int ec_key_use_raw_spki_from_buf(struct zpc_ec_key *ec_key,
						const unsigned char *spki, unsigned int spki_len);
static int ec_key_spki_has_valid_mkvp(const struct zpc_ec_key *ec_key,
						const unsigned char *spki, unsigned int spki_len);
static int ec_key_blob_has_valid_mkvp(struct zpc_ec_key *ec_key,
						const unsigned char *buf);
static int ec_key_blob_is_pkey_extractable(struct zpc_ec_key *ec_key,
						const unsigned char *buf);
static int ec_key_apqns_have_valid_version(struct zpc_ec_key *ec_key);
int ec_key_pvsec2prot(struct zpc_ec_key *ec_key);
int ec_key_blob_is_valid_pvsecret_id(struct zpc_ec_key *ec_key,
						const unsigned char *id);


int zpc_ec_key_alloc(struct zpc_ec_key **ec_key)
{
	pthread_mutexattr_t attr;
	struct zpc_ec_key *new_ec_key = NULL;
	int rc, rv, attr_init = 0;

	UNUSED(rv);

	if (pkeyfd < 0) {
		rc = ZPC_ERROR_DEVPKEY;
		goto ret;
	}
	if (ec_key == NULL) {
		rc = ZPC_ERROR_ARG1NULL;
		goto ret;
	}

	new_ec_key = calloc(1, sizeof(*new_ec_key));
	if (new_ec_key == NULL) {
		rc = ZPC_ERROR_MALLOC;
		goto ret;
	}

	rc = pthread_mutexattr_init(&attr);
	if (rc) {
		rc = ZPC_ERROR_MALLOC;
		goto ret;
	}
	attr_init = 1;
	rv = pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
	assert(rv == 0);
	rc = pthread_mutex_init(&new_ec_key->lock, &attr);
	if (rc) {
		rc = ZPC_ERROR_INITLOCK;
		goto ret;
	}
	new_ec_key->refcount = 1;
	DEBUG("ec key at %p: refcount %llu", new_ec_key,
	    new_ec_key->refcount);

	*ec_key = new_ec_key;
	rc = 0;
ret:
	if (attr_init == 1) {
		rv = pthread_mutexattr_destroy(&attr);
		assert(rv == 0);
	}
	if (rc)
		free(new_ec_key);
	DEBUG("return %d (%s)", rc, zpc_error_string(rc));
	return rc;
}

int zpc_ec_key_set_curve(struct zpc_ec_key *ec_key, zpc_ec_curve_t curve)
{
	int rc, rv;

	UNUSED(rv);

	if (pkeyfd < 0) {
		rc = ZPC_ERROR_DEVPKEY;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}
	if (ec_key == NULL) {
		rc = ZPC_ERROR_ARG1NULL;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}

	switch (curve) {
	case ZPC_EC_CURVE_P256:      /* fall-through */
	case ZPC_EC_CURVE_P384:      /* fall-through */
	case ZPC_EC_CURVE_P521:
	case ZPC_EC_CURVE_ED25519:
	case ZPC_EC_CURVE_ED448:
		break;
	default:
		rc = ZPC_ERROR_EC_INVALID_CURVE;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}

	rv = pthread_mutex_lock(&ec_key->lock);
	assert(rv == 0);

	if (ec_key->refcount != 1) {
		rc = ZPC_ERROR_OBJINUSE;
		goto ret;
	}

	if (ec_key->curve_set == 1 && ec_key->curve != curve) {
		/* Unset key if it does not match the new EC curve. */
		DEBUG("ec key at %p: key unset", ec_key);
		memset(&ec_key->cur, 0, sizeof(ec_key->cur));
		memset(&ec_key->old, 0, sizeof(ec_key->old));
		ec_key->curve_set = 0;
	}

	DEBUG("ec key at %p: curve set to %d", ec_key, curve);
	ec_key->curve = curve;
	ec_key->curve_set = 1;
	rc = 0;
ret:
	rv = pthread_mutex_unlock(&ec_key->lock);
	assert(rv == 0);
	DEBUG("return %d (%s)", rc, zpc_error_string(rc));
	return rc;
}

int zpc_ec_key_set_type(struct zpc_ec_key *ec_key, int type)
{
	int rc, rv;

	UNUSED(rv);

	if (pkeyfd < 0) {
		rc = ZPC_ERROR_DEVPKEY;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}
	if (ec_key == NULL) {
		rc = ZPC_ERROR_ARG1NULL;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}

	switch (type) {
	case ZPC_EC_KEY_TYPE_CCA:        /* fall-through */
	case ZPC_EC_KEY_TYPE_EP11:
	case ZPC_EC_KEY_TYPE_PVSECRET:
		break;
	default:
		rc = ZPC_ERROR_KEYTYPE;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}

	if (!swcaps.ecdsa_cca && type == ZPC_EC_KEY_TYPE_CCA)
		return ZPC_ERROR_CCA_HOST_LIB_NOT_AVAILABLE;
	else if (!swcaps.ecdsa_ep11 && type == ZPC_EC_KEY_TYPE_EP11)
		return ZPC_ERROR_EP11_HOST_LIB_NOT_AVAILABLE;
	else if (!swcaps.uv_pvsecrets && type == ZPC_EC_KEY_TYPE_PVSECRET)
		return ZPC_ERROR_UV_PVSECRETS_NOT_AVAILABLE;

	rv = pthread_mutex_lock(&ec_key->lock);
	assert(rv == 0);

	if (ec_key->refcount != 1) {
		rc = ZPC_ERROR_OBJINUSE;
		goto ret;
	}

	if (ec_key->type_set == 1 && ec_key->type != type && ec_key->mkvp_set == 1) {
		/* Update mkvp-based apqn choices in case of type change. */
		DEBUG("ec key at %p: update apqns to match type %d", ec_key,
		    type);
		free(ec_key->apqns);
		ec_key->apqns = NULL;
		ec_key->napqns = 0;
		ec_key->apqns_set = 0;

		rc = alloc_apqns_from_mkvp(pkeyfd, &(ec_key->apqns), &(ec_key->napqns),
								ec_key->mkvp, type);
		if (rc != 0)
			goto ret;

		DEBUG("ec key at %p: %lu apqns set", ec_key, ec_key->napqns);
		ec_key->apqns_set = 1;
	}

	DEBUG("ec key at %p: type set to %d", ec_key, type);
	ec_key->type = type;
	ec_key->type_set = 1;
	rc = 0;
ret:
	rv = pthread_mutex_unlock(&ec_key->lock);
	assert(rv == 0);
	DEBUG("return %d (%s)", rc, zpc_error_string(rc));
	return rc;
}

int zpc_ec_key_set_flags(struct zpc_ec_key *ec_key, unsigned int flags)
{
	int rc, rv;

	UNUSED(rv);

	if (pkeyfd < 0) {
		rc = ZPC_ERROR_DEVPKEY;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}
	if (ec_key == NULL) {
		rc = ZPC_ERROR_ARG1NULL;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}

	rv = pthread_mutex_lock(&ec_key->lock);
	assert(rv == 0);

	if (ec_key->refcount != 1) {
		rc = ZPC_ERROR_OBJINUSE;
		goto ret;
	}

	DEBUG("ec key at %p: flags set to %u", ec_key, flags);
	ec_key->flags = flags;
	ec_key->flags_set = 1;
	rc = 0;
ret:
	rv = pthread_mutex_unlock(&ec_key->lock);
	assert(rv == 0);
	DEBUG("return %d (%s)", rc, zpc_error_string(rc));
	return rc;
}

/*
 * Associate ec_key to all apqns of the given mkvp.
 */
int zpc_ec_key_set_mkvp(struct zpc_ec_key *ec_key, const char *mkvp)
{
	u8 mkvpbuf[MAX_MKVPLEN];
	size_t mkvpbuflen;
	int rc, rv;

	UNUSED(rv);

	if (pkeyfd < 0) {
		rc = ZPC_ERROR_DEVPKEY;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}
	if (ec_key == NULL) {
		rc = ZPC_ERROR_ARG1NULL;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}

	if (!swcaps.ecdsa_cca && ec_key->type == ZPC_EC_KEY_TYPE_CCA)
		return ZPC_ERROR_CCA_HOST_LIB_NOT_AVAILABLE;
	else if (!swcaps.ecdsa_ep11 && ec_key->type == ZPC_EC_KEY_TYPE_EP11)
		return ZPC_ERROR_EP11_HOST_LIB_NOT_AVAILABLE;

	rv = pthread_mutex_lock(&ec_key->lock);
	assert(rv == 0);

	if (ec_key->refcount != 1) {
		rc = ZPC_ERROR_OBJINUSE;
		goto ret;
	}

	if (mkvp == NULL) {
		DEBUG("ec key at %p: apqns unset", ec_key);
		free(ec_key->apqns);
		ec_key->apqns = NULL;
		ec_key->napqns = 0;
		ec_key->apqns_set = 0;
		rc = 0;
		goto ret;
	}

	mkvpbuflen = sizeof(mkvpbuf);
	if (hexstr2buf(mkvpbuf, &mkvpbuflen, mkvp)) {
		rc = ZPC_ERROR_PARSE;
		goto ret;
	}

	if (mkvpbuflen != 8 && mkvpbuflen != 16 && mkvpbuflen != 32) {
		rc = ZPC_ERROR_MKVPLEN;
		goto ret;
	}

	if (ec_key->type_set != 1) {
		rc = ZPC_ERROR_KEYTYPENOTSET;
		goto ret;
	}

	DEBUG("ec key at %p: apqns unset", ec_key);
	free(ec_key->apqns);
	ec_key->apqns = NULL;
	ec_key->napqns = 0;
	ec_key->apqns_set = 0;

	if (ec_key->type == ZPC_EC_KEY_TYPE_PVSECRET) {
		rc = 0; /* function has no effect */
		goto ret;
	}

	rc = alloc_apqns_from_mkvp(pkeyfd, &(ec_key->apqns), &(ec_key->napqns),
							mkvpbuf, ec_key->type);
	if (rc != 0)
		goto ret;

	DEBUG("ec key at %p: mkvp and %lu apqns set", ec_key,
		ec_key->napqns);
	memcpy(ec_key->mkvp, mkvpbuf, mkvpbuflen);
	ec_key->apqns_set = 1;
	ec_key->mkvp_set = 1;

	/* If the key already has a secure key set, its mkvp must match */
	if (ec_key->cur.seclen > 0 && !ec_key_blob_has_valid_mkvp(ec_key, ec_key->cur.sec)) {
		rc = ZPC_ERROR_WKVPMISMATCH;
		goto ret;
	}

	rc = 0;

ret:
	rv = pthread_mutex_unlock(&ec_key->lock);
	assert(rv == 0);
	DEBUG("return %d (%s)", rc, zpc_error_string(rc));
	return rc;
}

/*
 * Associate ec_key to a list NULL terminated list of apqns.
 */
int zpc_ec_key_set_apqns(struct zpc_ec_key *ec_key, const char *apqns[])
{
	unsigned int card, domain;
	size_t i, napqns;
	int rc, rv;

	UNUSED(rv);

	if (pkeyfd < 0) {
		rc = ZPC_ERROR_DEVPKEY;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}
	if (ec_key == NULL) {
		rc = ZPC_ERROR_ARG1NULL;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}

	rv = pthread_mutex_lock(&ec_key->lock);
	assert(rv == 0);

	if (apqns == NULL) {
		DEBUG("ec key at %p: apqns unset", ec_key);
		free(ec_key->apqns);
		ec_key->apqns = NULL;
		ec_key->napqns = 0;
		ec_key->apqns_set = 0;
		rc = 0;
		goto ret;
	}

	if (ec_key->type == ZPC_EC_KEY_TYPE_PVSECRET) {
		rc = 0; /* function has no effect */
		goto ret;
	}

	for (napqns = 0; apqns[napqns] != NULL; napqns++);

	if (ec_key->refcount != 1) {
		rc = ZPC_ERROR_OBJINUSE;
		goto ret;
	}

	DEBUG("ec key at %p: apqns unset", ec_key);
	free(ec_key->apqns);
	ec_key->apqns = NULL;
	ec_key->napqns = 0;
	ec_key->apqns_set = 0;

	DEBUG("ec key at %p: mkvp unset", ec_key);
	memset(ec_key->mkvp, 0, sizeof(ec_key->mkvp));
	ec_key->mkvplen = 0;
	ec_key->mkvp_set = 0;

	if (napqns == 0) {
		rc = 0; /* nothing to do */
		goto ret;
	}

	ec_key->apqns = calloc(napqns, sizeof(*(ec_key->apqns)));
	if (ec_key->apqns == NULL)
		return ZPC_ERROR_MALLOC;

	for (i = 0; i < napqns; i++) {
		rc = sscanf(apqns[i], " %x.%x ", &card, &domain);
		if (rc != 2) {
			rc = ZPC_ERROR_PARSE;
			goto ret;
		}
		ec_key->apqns[i].card = card;
		ec_key->apqns[i].domain = domain;
	}

	DEBUG("ec key at %p: %lu apqns set", ec_key, ec_key->napqns);
	ec_key->napqns = napqns;
	ec_key->apqns_set = 1;

	/* If the key already has a secure key set, its mkvp must match */
	if (ec_key->cur.seclen > 0 && !ec_key_blob_has_valid_mkvp(ec_key, ec_key->cur.sec)) {
		rc = ZPC_ERROR_WKVPMISMATCH;
		goto ret;
	}

	/* All APQNs must fulfill the hardware requirements for ECDSA */
	if (!ec_key_apqns_have_valid_version(ec_key)) {
		rc = ZPC_ERROR_APQNS_INVALID_VERSION;
		goto ret;
	}

	rc = 0;

ret:
	if (rc != 0) {
		free(ec_key->apqns);
		ec_key->apqns = NULL;
		ec_key->napqns = 0;
	}
	rv = pthread_mutex_unlock(&ec_key->lock);
	assert(rv == 0);
	DEBUG("return %d (%s)", rc, zpc_error_string(rc));
	return rc;
}


int
zpc_ec_key_export(struct zpc_ec_key *ec_key, unsigned char *buf,
				unsigned int *buflen)
{
	int rc, rv;

	UNUSED(rv);

	if (pkeyfd < 0) {
		rc = ZPC_ERROR_DEVPKEY;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}
	if (ec_key == NULL) {
		rc = ZPC_ERROR_ARG1NULL;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}
	if (buflen == NULL) {
		rc = ZPC_ERROR_ARG3NULL;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}

	rv = pthread_mutex_lock(&ec_key->lock);
	assert(rv == 0);

	rc = ec_key_check(ec_key);
	if (rc)
		goto ret;

	if (buf == NULL) {
		*buflen = ec_key->cur.seclen;
		if (ec_key->pubkey_set)
			*buflen += ec_key->pub.spkilen;
		rc = 0;
		goto ret;
	}

	if (ec_key->pubkey_set && *buflen < ec_key->cur.seclen + ec_key->pub.spkilen) {
		*buflen = ec_key->cur.seclen + ec_key->pub.spkilen;
		rc = ZPC_ERROR_SMALLOUTBUF;
		goto ret;
	}

	if (!ec_key->pubkey_set && *buflen < ec_key->cur.seclen) {
		*buflen = ec_key->cur.seclen;
		rc = ZPC_ERROR_SMALLOUTBUF;
		goto ret;
	}

	*buflen = ec_key->cur.seclen;
	memcpy(buf, ec_key->cur.sec, *buflen);

	if (ec_key->pubkey_set) {
		memcpy(buf + *buflen, ec_key->pub.spki, ec_key->pub.spkilen);
		*buflen += ec_key->pub.spkilen;
	}

	rc = 0;
ret:
	rv = pthread_mutex_unlock(&ec_key->lock);
	assert(rv == 0);
	DEBUG("return %d (%s)", rc, zpc_error_string(rc));
	return rc;
}

int zpc_ec_key_export_public(struct zpc_ec_key *ec_key,
						unsigned char *buf, unsigned int *buflen)
{
	int rc, rv;

	UNUSED(rv);

	if (pkeyfd < 0) {
		rc = ZPC_ERROR_DEVPKEY;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}
	if (ec_key == NULL) {
		rc = ZPC_ERROR_ARG1NULL;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}
	if (buflen == NULL) {
		rc = ZPC_ERROR_ARG3NULL;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}

	rv = pthread_mutex_lock(&ec_key->lock);
	assert(rv == 0);

	if (!ec_key->pubkey_set) {
		rc = ZPC_ERROR_EC_PUBKEY_NOTSET;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		goto ret;
	}

	if (buf == NULL) {
		*buflen = ec_key->pub.publen;
		rc = 0;
		goto ret;
	}

	if (*buflen < ec_key->pub.publen) {
		*buflen = ec_key->pub.publen;
		rc = ZPC_ERROR_SMALLOUTBUF;
		goto ret;
	}

	*buflen = ec_key->pub.publen;
	memcpy(buf, ec_key->pub.pubkey, *buflen);

	rc = 0;
ret:
	rv = pthread_mutex_unlock(&ec_key->lock);
	assert(rv == 0);
	DEBUG("return %d (%s)", rc, zpc_error_string(rc));
	return rc;
}

int zpc_ec_key_import(struct zpc_ec_key *ec_key, const unsigned char *buf,
				unsigned int buflen)
{
	target_t target;
	int rc, rv, seclen;
	size_t i, trailing_spki_len = 0;

	UNUSED(rv);

	if (pkeyfd < 0) {
		return ZPC_ERROR_DEVPKEY;
	}
	if (ec_key == NULL) {
		return ZPC_ERROR_ARG1NULL;
	}
	if (buf == NULL) {
		return ZPC_ERROR_ARG2NULL;
	}

	rv = pthread_mutex_lock(&ec_key->lock);
	assert(rv == 0);

	if (ec_key->refcount != 1) {
		rc = ZPC_ERROR_OBJINUSE;
		goto ret;
	}

	if (ec_key->type != ZPC_EC_KEY_TYPE_PVSECRET) {
		if (buflen < MIN_EC_BLOB_SIZE || buflen > MAX_EC_BLOB_SIZE) {
			rc = ZPC_ERROR_ARG3RANGE;
			goto ret;
		}
	} else {
		if (buflen != UV_SECRET_ID_LEN) {
			rc = ZPC_ERROR_ARG3RANGE;
			goto ret;
		}
	}

	if (ec_key->curve_set != 1) {
		rc = ZPC_ERROR_EC_CURVE_NOTSET;
		goto ret;
	}
	if (ec_key->type_set != 1) {
		rc = ZPC_ERROR_KEYTYPENOTSET;
		goto ret;
	}

	if (ec_key->type == ZPC_EC_KEY_TYPE_CCA && !is_cca_ec_key(buf, buflen)) {
		rc = ZPC_ERROR_EC_NO_CCA_SECUREKEY_TOKEN;
		goto ret;
	}

	if (ec_key->type == ZPC_EC_KEY_TYPE_EP11 && !is_ep11_ec_key_with_header(buf, buflen)) {
		rc = ZPC_ERROR_EC_NO_EP11_SECUREKEY_TOKEN;
		goto ret;
	}

	if (ec_key->type != ZPC_EC_KEY_TYPE_PVSECRET) {
		if (!ec_key_blob_has_valid_mkvp(ec_key, buf)) {
			rc = ZPC_ERROR_WKVPMISMATCH;
			goto ret;
		}

		if (!ec_key_blob_is_pkey_extractable(ec_key, buf)) {
			rc = ZPC_ERROR_BLOB_NOT_PKEY_EXTRACTABLE;
			goto ret;
		}
	}

	if (ec_key->type == ZPC_EC_KEY_TYPE_PVSECRET) {
		if (ec_key_blob_is_valid_pvsecret_id(ec_key, buf) != 0) {
			rc = ZPC_ERROR_PVSECRET_ID_NOT_FOUND_IN_UV;
			goto ret;
		}
	}

	/* In case of ep11, the imported buffer may contain the actual secure key
	 * blob concatenated with a public key spki. */
	if (ec_key->type == ZPC_EC_KEY_TYPE_EP11)
		trailing_spki_len = buflen - ep11_get_raw_blob_length(buf);

	/* Set (secure) private key. Host lib not needed for this. */
	seclen = buflen - trailing_spki_len;
	memset(ec_key->cur.sec, 0, sizeof(ec_key->cur.sec));
	memcpy(ec_key->cur.sec, buf, seclen);
	ec_key->cur.seclen = seclen;
	ec_key->key_set = 1;

	/* Extract and set public key. For this we need the related host lib. If
	 * the host lib is not available, only the secure key is available in
	 * this key object. */
	if (ec_key->type == ZPC_EC_KEY_TYPE_CCA) {
		if (!swcaps.ecdsa_cca) {
			rc = 0;
			goto ret;
		}
		ec_key->pubkey_set = 1;
		rv = pthread_mutex_lock(&ccalock);
		assert(rv == 0);
		rc = ec_key_extract_public_cca(&cca,
					(unsigned char *)&ec_key->cur.sec, ec_key->cur.seclen,
					(unsigned char *)&ec_key->pub.pubkey, &ec_key->pub.publen,
					true);
		rv = pthread_mutex_unlock(&ccalock);
		assert(rv == 0);
		if (rc != 0 || ec_key->pub.publen == 0)
			ec_key->pubkey_set = 0;
	} else if (ec_key->type == ZPC_EC_KEY_TYPE_EP11){
		if (!swcaps.ecdsa_ep11) {
			rc = 0;
			goto ret;
		}
		ec_key->pubkey_set = 1;
		rv = pthread_mutex_lock(&ep11lock);
		assert(rv == 0);
		for (i = 0; i < ec_key->napqns; i++) {
			rc = get_ep11_target_for_apqn(&ep11, ec_key->apqns[i].card,
					ec_key->apqns[i].domain, &target, true);
			if (rc)
				continue;
			rc = ec_key_extract_public_ep11(&ep11, ec_key->curve,
					(unsigned char *)&ec_key->cur.sec, ec_key->cur.seclen,
					(unsigned char *)&ec_key->pub.pubkey, &ec_key->pub.publen,
					(unsigned char *)&ec_key->pub.spki, &ec_key->pub.spkilen,
					target);
			free_ep11_target_for_apqn(&ep11, target);
			if (rc == 0)
				break;
		}
		rv = pthread_mutex_unlock(&ep11lock);
		assert(rv == 0);
		if (rc != 0 || ec_key->pub.publen == 0)
			ec_key->pubkey_set = 0;
	} else {
		/* PVSECRET: not possible to calculate public key from secret */
		ec_key->pubkey_set = 0;
		rc = 0;
		goto ret;
	}

	/* At this point the secure key blob is imported.
	 * - If the blob itself contains a public key, it's now extracted into the
	 *   key struct, but only if this key obj has apqns/mkvps. Otherwise we
	 *   could not extract the public key from the blob and the key obj has
	 *   no public key so far.
	 * - If there is a public key SPKI appended to the blob, we parse it out
	 *   of the SPKI (which does not require apqns/mkvps). But we have no way
	 *   for checking the correctness of the public key.
	 * - If the public key could be extracted from the blob and SPKI, we have
	 *   the public key given a second time. In this case we check if both
	 *   pubkeys match.
	 */
	if (ec_key->type == ZPC_EC_KEY_TYPE_EP11 && trailing_spki_len > 0) {
		const unsigned char *spki = buf + seclen;
		if (ec_key_check_ep11_spki(ec_key, spki, trailing_spki_len) == 0) {
			if (trailing_spki_len == curve2rawspkilen[ec_key->curve]) {
				rc = ec_key_use_raw_spki_from_buf(ec_key, spki, trailing_spki_len);
				if (rc != 0)
					goto ret;
			} else {
				ec_key_use_maced_spki_from_buf(ec_key, spki, trailing_spki_len);
			}
		}
	}

	rc = 0;

ret:
	rv = pthread_mutex_unlock(&ec_key->lock);
	assert(rv == 0);
	DEBUG("return %d (%s)", rc, zpc_error_string(rc));
	return rc;
}

int zpc_ec_key_import_clear(struct zpc_ec_key *ec_key, const unsigned char *pubkey,
						unsigned int publen, const unsigned char *privkey,
						unsigned int privlen)
{
	unsigned int flags;
	int rc, rv;
	size_t i;
	target_t target;

	UNUSED(rv);

	if (pkeyfd < 0) {
		rc = ZPC_ERROR_DEVPKEY;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}
	if (ec_key == NULL) {
		rc = ZPC_ERROR_ARG1NULL;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}
	if (!pubkey && !privkey) {
		rc = ZPC_ERROR_EC_NO_KEY_PARTS;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}

	if (privkey && privlen > 0) {
		/* We only need host libs if we import the privkey. */
		if (!swcaps.ecdsa_cca && ec_key->type == ZPC_EC_KEY_TYPE_CCA)
			return ZPC_ERROR_CCA_HOST_LIB_NOT_AVAILABLE;
		else if (!swcaps.ecdsa_ep11 && ec_key->type == ZPC_EC_KEY_TYPE_EP11)
			return ZPC_ERROR_EP11_HOST_LIB_NOT_AVAILABLE;
	}

	rv = pthread_mutex_lock(&ec_key->lock);
	assert(rv == 0);

	if (ec_key->refcount != 1) {
		rc = ZPC_ERROR_OBJINUSE;
		goto ret;
	}
	if (ec_key->curve_set != 1) {
		rc = ZPC_ERROR_EC_CURVE_NOTSET;
		goto ret;
	}
	if (ec_key->type_set != 1) {
		rc = ZPC_ERROR_KEYTYPENOTSET;
		goto ret;
	}
	if (ec_key->type != ZPC_EC_KEY_TYPE_PVSECRET && ec_key->apqns_set != 1) {
		rc = ZPC_ERROR_APQNSNOTSET;
		goto ret;
	}
	flags = ec_key->flags_set == 1 ? ec_key->flags : 0;

	if (publen > 0 && publen != curve2publen[ec_key->curve]) {
		rc = ZPC_ERROR_EC_PUBKEY_LENGTH;
		goto ret;
	}

	if (privlen > 0 && privlen != curve2privlen[ec_key->curve]) {
		rc = ZPC_ERROR_EC_PRIVKEY_LENGTH;
		goto ret;
	}

	if (privkey && privlen > 0) {
		memset(&ec_key->cur, 0, sizeof(ec_key->cur));
		memset(&ec_key->old, 0, sizeof(ec_key->old));
		memset(&ec_key->prot, 0, sizeof(ec_key->prot));
		ec_key->key_set = 0;

		rc = ec_key_clr2sec(ec_key, flags, pubkey, publen, privkey, privlen);
		if (rc) {
			goto ret;
		}

		rc = ec_key_clr2prot(ec_key, privkey, privlen);
		if (rc) {
			rc = ec_key_sec2prot(ec_key, EC_KEY_SEC_CUR);
			if (rc) {
				goto ret;
			}
		}

		DEBUG("ec key at %p: private/protected key set", ec_key);
		ec_key->key_set = 1;
	}

	if (pubkey && publen > 0) {
		memcpy(&ec_key->pub.pubkey, pubkey, publen);
		ec_key->pub.publen = publen;
		DEBUG("ec key at %p: public key set", ec_key);
		ec_key->pubkey_set = 1;
	}

	/* In case of ep11, create a MACed spki from the given raw public key and
	 * add it to the key struct. */
	if (ec_key->pubkey_set == 1 && ec_key->type == ZPC_EC_KEY_TYPE_EP11) {

		unsigned char temp[MAX_MACED_SPKI_SIZE];
		unsigned int temp_len = sizeof(temp);

		rv = pthread_mutex_lock(&ep11lock);
		assert(rv == 0);
		for (i = 0; i < ec_key->napqns; i++) {
			rc = get_ep11_target_for_apqn(&ep11, ec_key->apqns[i].card,
						ec_key->apqns[i].domain, &target, true);
			if (rc)
				continue;

			ep11_make_spki(ec_key->curve, ec_key->pub.pubkey, ec_key->pub.publen,
					(unsigned char *)&temp, &temp_len);

			ec_key->pub.spkilen = sizeof(ec_key->pub.spki);
			rc = ep11_make_maced_spki(&ep11, temp, temp_len, ec_key->pub.spki,
					&ec_key->pub.spkilen, target);

			free_ep11_target_for_apqn(&ep11, target);
			if (rc == 0)
				break;
		}
		rv = pthread_mutex_unlock(&ep11lock);
		assert(rv == 0);
	}

	rc = 0;

ret:
	if (rc != 0)
		memset(&ec_key->cur, 0, sizeof(ec_key->cur));

	rv = pthread_mutex_unlock(&ec_key->lock);
	assert(rv == 0);

	DEBUG("return %d (%s)", rc, zpc_error_string(rc));
	return rc;
}

int zpc_ec_key_generate(struct zpc_ec_key *ec_key)
{
	target_t target;
	unsigned int flags;
	int rc, rv;
	size_t i;

	UNUSED(rv);

	if (pkeyfd < 0) {
		rc = ZPC_ERROR_DEVPKEY;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}
	if (ec_key == NULL) {
		rc = ZPC_ERROR_ARG1NULL;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}

	if (!swcaps.ecdsa_cca && ec_key->type == ZPC_EC_KEY_TYPE_CCA)
		return ZPC_ERROR_CCA_HOST_LIB_NOT_AVAILABLE;
	else if (!swcaps.ecdsa_ep11 && ec_key->type == ZPC_EC_KEY_TYPE_EP11)
		return ZPC_ERROR_EP11_HOST_LIB_NOT_AVAILABLE;

	rv = pthread_mutex_lock(&ec_key->lock);
	assert(rv == 0);

	if (ec_key->refcount != 1) {
		rc = ZPC_ERROR_OBJINUSE;
		goto ret;
	}

	if (ec_key->type == ZPC_EC_KEY_TYPE_PVSECRET) {
		rc = ZPC_ERROR_KEYTYPE;
		goto ret;
	}

	if (ec_key->curve_set != 1) {
		rc = ZPC_ERROR_EC_CURVE_NOTSET;
		goto ret;
	}
	if (ec_key->apqns_set != 1) {
		/* EC keys cannot be generated without APQNs, because we do it via
		 * the host libs. */
		rc = ZPC_ERROR_APQNS_NOTSET;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		goto ret;
	}

	if (ec_key->type_set != 1) {
		rc = ZPC_ERROR_KEYTYPENOTSET;
		goto ret;
	}

	flags = ec_key->flags_set == 1 ? ec_key->flags : 0;

	memset(&ec_key->cur, 0, sizeof(ec_key->cur));
	memset(&ec_key->old, 0, sizeof(ec_key->old));
	ec_key->key_set = 0;
	ec_key->pubkey_set = 0;

	/* Generate secure EC key via host libs */
	switch (ec_key->type) {
	case ZPC_EC_KEY_TYPE_CCA:
			rv = pthread_mutex_lock(&ccalock);
		assert(rv == 0);
		rc = ec_key_generate_cca(&cca, ec_key->curve, flags,
				(unsigned char *)&ec_key->cur.sec, &ec_key->cur.seclen,
				(unsigned char *)&ec_key->pub.pubkey, &ec_key->pub.publen,
				true);
		rv = pthread_mutex_unlock(&ccalock);
		assert(rv == 0);
		if (rc)
			goto ret;
		break;
	case ZPC_EC_KEY_TYPE_EP11:
		rv = pthread_mutex_lock(&ep11lock);
		assert(rv == 0);
		for (i = 0; i < ec_key->napqns; i++) {
			rc = get_ep11_target_for_apqn(&ep11, ec_key->apqns[i].card,
						ec_key->apqns[i].domain, &target, true);
			if (rc)
				continue;

			rc = ec_key_generate_ep11(&ep11, ec_key->curve, flags,
					(unsigned char *)&ec_key->cur.sec, &ec_key->cur.seclen,
					(unsigned char *)&ec_key->pub.pubkey, &ec_key->pub.publen,
					(unsigned char *)&ec_key->pub.spki, &ec_key->pub.spkilen,
					target);

			free_ep11_target_for_apqn(&ep11, target);
			if (rc == 0)
				break;
		}
		rv = pthread_mutex_unlock(&ep11lock);
		assert(rv == 0);
		break;
	default:
		rc = ZPC_ERROR_KEYTYPE;
		goto ret;
	}

	DEBUG("ec key at %p: privkey set to generated secure key", ec_key);
	DEBUG("ec key at %p: pubkey extracted from secure key token", ec_key);
	ec_key->key_set = 1;
	ec_key->pubkey_set = 1;

	/* Transform secure key into protected key */
	rc = ec_key_sec2prot(ec_key, EC_KEY_SEC_CUR);
	if (rc)
		goto ret;

	DEBUG("ec key at %p: protkey created from secure key token", ec_key);

	rc = 0;

ret:
	if (rc != 0)
		memset(&ec_key->cur, 0, sizeof(ec_key->cur));

	rv = pthread_mutex_unlock(&ec_key->lock);
	assert(rv == 0);
	DEBUG("return %d (%s)", rc, zpc_error_string(rc));
	return rc;
}

int zpc_ec_key_reencipher(struct zpc_ec_key *ec_key, unsigned int method)
{
	struct ec_key reenc;
	unsigned int seckeylen;
	target_t target;
	int rv, rc = ZPC_ERROR_APQNSNOTSET;
	size_t i;
	unsigned char temp[MAX_MACED_SPKI_SIZE];
	unsigned int temp_len = sizeof(temp);

	UNUSED(rv);

	if (pkeyfd < 0) {
		rc = ZPC_ERROR_DEVPKEY;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}
	if (ec_key == NULL) {
		rc = ZPC_ERROR_ARG1NULL;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}

	rv = pthread_mutex_lock(&ec_key->lock);
	assert(rv == 0);

	if (ec_key->key_set == 0) {
		rc = ZPC_ERROR_EC_PRIVKEY_NOTSET;
		goto ret;
	}
	if (ec_key->curve_set == 0) {
		rc = ZPC_ERROR_EC_CURVE_NOTSET;
		goto ret;
	}
	if (ec_key->type_set == 0) {
		rc = ZPC_ERROR_KEYTYPENOTSET;
		goto ret;
	}
	if (ec_key->type == ZPC_EC_KEY_TYPE_PVSECRET) {
		/* reencipher not applicable for pvsecrets */
		rc = ZPC_ERROR_KEYTYPE;
		goto ret;
	}
	if (ec_key->apqns_set == 0 || ec_key->napqns == 0) {
		rc = ZPC_ERROR_APQNSNOTSET;
		goto ret;
	}

	memcpy(&reenc, &ec_key->cur, sizeof(reenc));

	switch (ec_key->type) {
	case ZPC_EC_KEY_TYPE_CCA:
		seckeylen = ec_key->cur.seclen;
		rv = pthread_mutex_lock(&ccalock);
		assert(rv == 0);
		for (i = 0; i < ec_key->napqns; i++) {
			rc = select_cca_adapter(&cca, ec_key->apqns[i].card,
					ec_key->apqns[i].domain, true);
			if (rc)
				continue;
			rc = key_token_change(&cca, reenc.sec, seckeylen,
					method == ZPC_EC_KEY_REENCIPHER_OLD_TO_CURRENT ?
							METHOD_OLD_TO_CURRENT : METHOD_CURRENT_TO_NEW,
					true);
			if (rc == 0)
				break;
		}
		rv = pthread_mutex_unlock(&ccalock);
		assert(rv == 0);
		break;
	case ZPC_EC_KEY_TYPE_EP11:
		if (method != ZPC_EC_KEY_REENCIPHER_CURRENT_TO_NEW) {
			rc = ZPC_ERROR_NOTSUP;
			goto ret;
		}

		rv = pthread_mutex_lock(&ep11lock);
		assert(rv == 0);
		for (i = 0; i < ec_key->napqns; i++) {
			rc = get_ep11_target_for_apqn(&ep11, ec_key->apqns[i].card,
					ec_key->apqns[i].domain, &target, true);
			if (rc)
				continue;

			/* Note that the secure key is a TOKVER_EP11_ECC_WITH_HEADER and has a
			 * 16-byte ep11kblob_header prepended before the actual secure key blob.
			 * For reencipher we have to skip this prepended hdr and provide the
			 * key blob directly. */
			rc = reencipher_ep11_key(&ep11, target, ec_key->apqns[i].card,
					ec_key->apqns[i].domain, reenc.sec + sizeof(struct ep11kblob_header),
					ec_key->cur.seclen - sizeof(struct ep11kblob_header),
					true);

			rc += ep11_make_maced_spki(&ep11,
								(unsigned char *)&ec_key->pub.spki,
								curve2rawspkilen[ec_key->curve],
								temp, &temp_len, target);
			if (rc == 0) {
				memcpy(ec_key->pub.spki, temp, temp_len);
				ec_key->pub.spkilen = temp_len;
			}

			free_ep11_target_for_apqn(&ep11, target);
			if (rc == 0)
				break;
		}
		rv = pthread_mutex_unlock(&ep11lock);
		assert(rv == 0);
		break;
	default:
		rc = ZPC_ERROR_KEYTYPE;
	}

	if (rc)
		goto ret;

	memcpy(&ec_key->old, &ec_key->cur, sizeof(ec_key->old));
	memcpy(&ec_key->cur, &reenc, sizeof(ec_key->cur));
	rc = 0;
ret:
	rv = pthread_mutex_unlock(&ec_key->lock);
	assert(rv == 0);
	DEBUG("return %d (%s)", rc, zpc_error_string(rc));
	return rc;
}

void zpc_ec_key_free(struct zpc_ec_key **ec_key)
{
	int rv, free_obj = 0;

	UNUSED(rv);

	if (ec_key == NULL)
		return;
	if (*ec_key == NULL)
		return;

	rv = pthread_mutex_lock(&(*ec_key)->lock);
	assert(rv == 0);

	if ((*ec_key)->refcount == 0)
		goto ret;

	(*ec_key)->refcount--;
	DEBUG("ec key at %p: refcount %llu", *ec_key, (*ec_key)->refcount);

	if ((*ec_key)->refcount == 0) {
		free_obj = 1;
		__ec_key_reset(*ec_key);
	}

ret:
	rv = pthread_mutex_unlock(&(*ec_key)->lock);
	assert(rv == 0);

	if (free_obj == 1) {
		rv = pthread_mutex_destroy(&(*ec_key)->lock);
		assert(rv == 0);

		free(*ec_key);
	}
	*ec_key = NULL;
	DEBUG("return");
}

/*
 * Reset everything that was set after allocation.
 * Caller must hold ec_key's wr lock.
 */
static void __ec_key_reset(struct zpc_ec_key *ec_key)
{

	assert(ec_key != NULL);

	memset(&ec_key->cur, 0, sizeof(ec_key->cur));
	memset(&ec_key->old, 0, sizeof(ec_key->old));
	memset(&ec_key->prot, 0, sizeof(ec_key->prot));
	memset(&ec_key->pub, 0, sizeof(ec_key->pub));
	ec_key->key_set = 0;
	ec_key->pubkey_set = 0;

	ec_key->curve = 0;
	ec_key->curve_set = 0;

	ec_key->flags = 0;
	ec_key->flags_set = 0;

	ec_key->type = 0;
	ec_key->type_set = 0;

	memset(ec_key->mkvp, 0, sizeof(ec_key->mkvp));
	ec_key->mkvplen = 0;
	ec_key->mkvp_set = 0;

	free(ec_key->apqns);
	ec_key->apqns = NULL;
	ec_key->napqns = 0;
	ec_key->apqns_set = 0;

	ec_key->refcount = 1;
}

u16 ecprotkeylen_from_pvsectype(u16 pvsectype)
{
	switch (pvsectype) {
	case ZPC_EC_SECRET_ECDSA_P256:
		return 32 + 32;
	case ZPC_EC_SECRET_ECDSA_P384:
		return 48 + 32;
	case ZPC_EC_SECRET_ECDSA_P521:
		return 80 + 32;
	case ZPC_EC_SECRET_EDDSA_ED25519:
		return 32 + 32;
	case ZPC_EC_SECRET_EDDSA_ED448:
		return 64 + 32;
	default:
		break;
	}

	return 0;
}

void ec_key_make_uvrsecrettoken(struct zpc_ec_key *ec_key, const unsigned char *id,
				unsigned char *buf)
{
	struct uvrsecrettoken *clrtok = (struct uvrsecrettoken *)buf;

	clrtok->version = TOKVER_UV_SECRET;
	clrtok->secret_type = curve2pvsecret_type[ec_key->curve];
	clrtok->secret_len = ecprotkeylen_from_pvsectype(clrtok->secret_type);
	memcpy(clrtok->secret_id, id, UV_SECRET_ID_LEN);
}

/*
 * Verify that a given pvsecret ID is a valid ID on this system, i.e. an UV
 * secret exists with this ID and has the expected key length.
 */
int ec_key_blob_is_valid_pvsecret_id(struct zpc_ec_key *ec_key, const unsigned char *id)
{
	struct pkey_verifykey2 io;
	unsigned char buf[sizeof(struct uvrsecrettoken)] = { 0, };
	int rc;

	ec_key_make_uvrsecrettoken(ec_key, id, buf);

	memset(&io, 0, sizeof(io));
	io.key = buf;
	io.keylen = sizeof(struct uvrsecrettoken);

	errno = 0;
	rc = ioctl(pkeyfd, PKEY_VERIFYKEY2, &io);
	if (rc != 0) {
		DEBUG("ec key at %p: PKEY_VERIFYKEY2 ioctl failed, errno = %d", ec_key, errno);
		return ZPC_ERROR_IOCTLVERIFYKEY2;
	}

	return 0;
}

/*
 * (Re)derive protected key from a retrievable secret ID.
 * Caller must hold aes_key's wr lock.
 */
int ec_key_pvsec2prot(struct zpc_ec_key *ec_key)
{
	struct pkey_kblob2pkey3 io;
	unsigned char buf[sizeof(struct uvrsecrettoken)] = { 0, };
	int rc;

	ec_key_make_uvrsecrettoken(ec_key, ec_key->cur.sec, buf);

	memset(&io, 0, sizeof(io));
	io.key = buf;
	io.keylen = sizeof(struct uvrsecrettoken);
	io.pkeytype = ec_key->type;
	io.pkeylen = sizeof(ec_key->prot.protkey);
	io.pkey = (unsigned char *)&ec_key->prot.protkey;

	errno = 0;
	rc = ioctl(pkeyfd, PKEY_KBLOB2PROTK3, &io);
	if (rc != 0) {
		DEBUG("ec key at %p: PKEY_VERIFYKEY2 ioctl failed, errno = %d", ec_key, errno);
		return ZPC_ERROR_IOCTLBLOB2PROTK3;
	}

	return 0;
}

int ec_key_clr2sec(struct zpc_ec_key *ec_key, unsigned int flags,
			const unsigned char *pubkey, unsigned int publen,
			const unsigned char *privkey, unsigned int privlen)
{
	target_t target;
	int rv, rc = ZPC_ERROR_APQNSNOTSET;
	size_t i;

	switch (ec_key->type) {
	case ZPC_EC_KEY_TYPE_CCA:
		rv = pthread_mutex_lock(&ccalock);
		assert(rv == 0);
		rc = ec_key_clr2sec_cca(&cca, ec_key->curve, flags,
							(unsigned char *)&ec_key->cur.sec,
							&ec_key->cur.seclen,
							pubkey, publen, privkey, privlen, true);
		rv = pthread_mutex_unlock(&ccalock);
		assert(rv == 0);
		if (rc != 0)
			rc = ZPC_ERROR_EC_KEY_PARTS_INCONSISTENT;
		break;
	case ZPC_EC_KEY_TYPE_EP11:
		rv = pthread_mutex_lock(&ep11lock);
		assert(rv == 0);
		for (i = 0; i < ec_key->napqns; i++) {
			rc = get_ep11_target_for_apqn(&ep11, ec_key->apqns[i].card,
					ec_key->apqns[i].domain, &target, true);
			if (rc)
				continue;
			rc = ec_key_clr2sec_ep11(&ep11, ec_key->curve, flags,
							(unsigned char *)&ec_key->cur.sec,
							&ec_key->cur.seclen, pubkey, publen,
							privkey, privlen, target);
			free_ep11_target_for_apqn(&ep11, target);
			if (rc == 0)
				break;
		}
		rv = pthread_mutex_unlock(&ep11lock);
		assert(rv == 0);
		if (rc != 0)
			rc = ZPC_ERROR_EC_KEY_PARTS_INCONSISTENT;
		break;
	default:
		rc = ZPC_ERROR_KEYTYPE;
		break;
	}

	return rc;
}

/*
 * (Re)derive protected key from a secure key.
 * Caller must hold ec_key's wr lock.
 */
int ec_key_sec2prot(struct zpc_ec_key *ec_key, enum ec_key_sec sec)
{
	struct pkey_kblob2pkey3 io;
	struct ec_key *key = NULL;
	unsigned int keybuf_len;
	int rc, i;

	assert(sec == EC_KEY_SEC_OLD || sec == EC_KEY_SEC_CUR);

	if (sec == EC_KEY_SEC_CUR)
		key = &ec_key->cur;
	else if (sec == EC_KEY_SEC_OLD)
		key = &ec_key->old;
	assert(key != NULL);

	if (ec_key->type == ZPC_EC_KEY_TYPE_PVSECRET)
		return ec_key_pvsec2prot(ec_key);
	else if (ec_key->type == ZPC_EC_KEY_TYPE_EP11)
		keybuf_len = key->seclen + sizeof(struct ep11kblob_header);
	else
		keybuf_len = key->seclen;

	memset(&io, 0, sizeof(io));
	io.key = key->sec;
	io.keylen = keybuf_len;
	io.apqns = ec_key->apqns;
	io.apqn_entries = ec_key->napqns;
	io.pkeytype = (ec_key->type == ZPC_EC_KEY_TYPE_CCA ? PKEY_TYPE_CCA_ECC : PKEY_TYPE_EP11_ECC);
	io.pkeylen = sizeof(ec_key->prot.protkey);
	io.pkey = (unsigned char *)&ec_key->prot.protkey;

	for (i = 0; i < 10; i++) {
		rc = ioctl(pkeyfd, PKEY_KBLOB2PROTK3, &io);
		if (rc == 0 || (errno != -EBUSY && errno != -EAGAIN))
			break;
		sleep(1);
	}

	if (rc != 0) {
		return ZPC_ERROR_IOCTLBLOB2PROTK3;
	}

	return 0;
}

int ec_key_clr2prot(struct zpc_ec_key *ec_key, const unsigned char *privkey,
					unsigned int privlen)
{
	struct pkey_kblob2pkey3 io;
	unsigned char buf[sizeof(struct clearkeytoken) + 80];
	struct clearkeytoken *clrtok = (struct clearkeytoken *)&buf;
	int rc;

	memset(buf, 0, sizeof(buf));
	clrtok->version = 0x02;
	clrtok->keytype = curve2pkey_keytype[ec_key->curve];
	switch (clrtok->keytype) {
	case PKEY_KEYTYPE_ECC_P256:
	case PKEY_KEYTYPE_ECC_P384:
	case PKEY_KEYTYPE_ECC_ED25519:
		memcpy(clrtok->clearkey, privkey, privlen);
		clrtok->len = privlen;
		break;
	case PKEY_KEYTYPE_ECC_P521:
		memcpy(clrtok->clearkey + 80 - privlen, privkey, privlen);
		clrtok->len = 80;
		break;
	case PKEY_KEYTYPE_ECC_ED448:
		memcpy(clrtok->clearkey + 64 - privlen, privkey, privlen);
		clrtok->len = 64;
		break;
	default: /* should not occur */
		return ZPC_ERROR_EC_INVALID_CURVE;
	}

	memset(&io, 0, sizeof(io));
	io.key = buf;
	switch (clrtok->keytype) {
	case PKEY_KEYTYPE_ECC_P256:
	case PKEY_KEYTYPE_ECC_P384:
	case PKEY_KEYTYPE_ECC_ED25519:
		io.keylen = sizeof(struct clearkeytoken) + privlen;
		break;
	case PKEY_KEYTYPE_ECC_P521:
		io.keylen = sizeof(struct clearkeytoken) + 80;
		break;
	case PKEY_KEYTYPE_ECC_ED448:
		io.keylen = sizeof(struct clearkeytoken) + 64;
		break;
	default: /* should not occur */
		return ZPC_ERROR_EC_INVALID_CURVE;
	}

	io.apqns = ec_key->apqns;
	io.apqn_entries = ec_key->napqns;
	io.pkeytype = (ec_key->type == ZPC_EC_KEY_TYPE_CCA ? PKEY_TYPE_CCA_ECC : PKEY_TYPE_EP11_ECC);
	io.pkeylen = sizeof(ec_key->prot.protkey);
	io.pkey = (unsigned char *)&ec_key->prot.protkey;

	rc = ioctl(pkeyfd, PKEY_KBLOB2PROTK3, &io);
	if (rc != 0) {
		return ZPC_ERROR_IOCTLBLOB2PROTK3;
	}

	return 0;
}

int ec_key_check(const struct zpc_ec_key *ec_key)
{
	if (ec_key->key_set != 1 && ec_key->pubkey_set != 1)
		return ZPC_ERROR_EC_NO_KEY_PARTS;
	if (ec_key->curve_set != 1)
		return ZPC_ERROR_EC_CURVE_NOTSET;
	if (ec_key->type_set != 1)
		return ZPC_ERROR_KEYTYPENOTSET;

	return 0;
}

int ec_key_spki_valid_for_pubkey(const struct zpc_ec_key *ec_key,
								const unsigned char *spki)
{
	if (ec_key->pubkey_set == 0)
		return 1; /* no pubkey given to check against */

	if (memcmp(ec_key->pub.pubkey, spki + curve2puboffset[ec_key->curve],
			ec_key->pub.publen) == 0)
		return 1;

	return 0;
}

static int ec_key_check_ep11_spki(const struct zpc_ec_key *ec_key,
							const unsigned char *spki, unsigned int spki_len)
{
	if (spki_len > curve2macedspkilen[ec_key->curve] &&
		spki_len < curve2rawspkilen[ec_key->curve])
		return ZPC_ERROR_EC_EP11_SPKI_INVALID_LENGTH;

	if (!ep11_spki_valid_for_curve(ec_key->curve, spki, spki_len))
		return ZPC_ERROR_EC_EP11_SPKI_INVALID_CURVE;

	if (spki_len == curve2macedspkilen[ec_key->curve] &&
		!ec_key_spki_valid_for_pubkey(ec_key, spki))
		return ZPC_ERROR_EC_EP11_SPKI_INVALID_PUBKEY;

	if (spki_len == curve2macedspkilen[ec_key->curve] &&
		!ec_key_spki_has_valid_mkvp(ec_key, spki, spki_len))
		return ZPC_ERROR_EC_EP11_SPKI_INVALID_MKVP;

	return 0;
}

static void ec_key_use_maced_spki_from_buf(struct zpc_ec_key *ec_key,
						const unsigned char *spki, unsigned int spki_len)
{
	memcpy(ec_key->pub.spki, spki, spki_len);
	ec_key->pub.spkilen = spki_len;

	memcpy(ec_key->pub.pubkey, spki + curve2puboffset[ec_key->curve],
			curve2publen[ec_key->curve]);
	ec_key->pub.publen = curve2publen[ec_key->curve];

	ec_key->pubkey_set = 1;
}

static int ec_key_use_raw_spki_from_buf(struct zpc_ec_key *ec_key,
						const unsigned char *spki, unsigned int spki_len)
{
	target_t target;
	int rc = -EIO, rv;
	size_t i;

	rv = pthread_mutex_lock(&ep11lock);
	assert(rv == 0);

	for (i = 0; i < ec_key->napqns; i++) {
		rc = get_ep11_target_for_apqn(&ep11, ec_key->apqns[i].card,
					ec_key->apqns[i].domain, &target, true);
		if (rc)
			continue;

		rc = ep11_make_maced_spki(&ep11, spki, spki_len, ec_key->pub.spki,
								&ec_key->pub.spkilen, target);

		free_ep11_target_for_apqn(&ep11, target);
		if (rc == 0)
			break;
	}

	if (rc == 0) {
		memcpy(ec_key->pub.pubkey, spki + curve2puboffset[ec_key->curve],
				curve2publen[ec_key->curve]);
		ec_key->pub.publen = curve2publen[ec_key->curve];
		ec_key->pubkey_set = 1;
	}

	rv = pthread_mutex_unlock(&ep11lock);
	assert(rv == 0);

	return rc;
}

static int ec_key_spki_has_valid_mkvp(const struct zpc_ec_key *ec_key,
						const unsigned char *spki, unsigned int spki_len)
{
	(void)spki_len; /* suppress unused parm compiler warning */

	spki_mac_t *mac_part = (spki_mac_t *)(spki + curve2rawspkilen[ec_key->curve]);

	if (ec_key->mkvp_set == 0)
		return 1; /* cannot judge */

	if (memcmp(ec_key->mkvp, mac_part->wk_id, 16) == 0)
		return 1;

	return 0;
}

static int ec_key_blob_has_valid_mkvp(struct zpc_ec_key *ec_key, const unsigned char *buf)
{
	const unsigned char *mkvp;
	unsigned int mkvp_len;

	if (ec_key->mkvp_set == 0)
		return 1; /* cannot judge */

	if (ec_key->type == ZPC_EC_KEY_TYPE_CCA) {
		mkvp = ((struct ccakeytoken *)buf)->mkvp;
		mkvp_len = MKVP_LEN_CCA;
	} else {
		/* Keys of type PKEY_TYPE_EP11_ECC have a ep11kblob_header prepended
		 * before the actual key blob */
		const unsigned char *buf2 = buf + sizeof(struct ep11kblob_header);
		mkvp = ((struct ep11keytoken *)buf2)->wkvp;
		mkvp_len = MKVP_LEN_EP11;
	}

	if (memcmp(ec_key->mkvp, mkvp, mkvp_len) == 0)
		return 1;

	return 0;
}

static int ec_key_blob_is_pkey_extractable(struct zpc_ec_key *ec_key, const unsigned char *buf)
{
	if (ec_key->type == ZPC_EC_KEY_TYPE_CCA) {
		u8 keyusage = ((struct ccakeytoken *)buf)->keyusage;
		if (keyusage & CCA_XPRTCPAC)
			return 1;
	} else {
		/* Keys of type PKEY_TYPE_EP11_ECC have a ep11kblob_header prepended
		 * before the actual key blob */
		const unsigned char *buf2 = buf + sizeof(struct ep11kblob_header);
		u64 attr = ((struct ep11keytoken *)buf2)->attr;
		if (attr & XCP_BLOB_PROTKEY_EXTRACTABLE)
			return 1;
	}

	return 0;
}

static int file_fgets(const char *fname, char *buf, size_t buflen)
{
	FILE *fp;
	char *end;
	int rc = CKR_OK;

	buf[0] = '\0';

	fp = fopen(fname, "r");
	if (fp == NULL) {
		DEBUG("Failed to open file '%s'\n", fname);
		return EIO;
	}
	if (fgets(buf, buflen, fp) == NULL) {
		DEBUG("Failed to read from file '%s'\n", fname);
		rc = EIO;
		goto out_fclose;
	}

	end = memchr(buf, '\n', buflen);
	if (end)
		*end = 0;
	else
		buf[buflen - 1] = 0;

	if (strlen(buf) == 0)
		rc = EIO;

out_fclose:

	fclose(fp);
	return rc;
}

static int get_card_type(unsigned int adapter, unsigned int *type)
{
	char fname[250];
	char buf[250];
	int rc;
	unsigned int hwtype, rawtype;

	sprintf(fname, "%scard%02x/type", SYSFS_DEVICES_AP, adapter);
	rc = file_fgets(fname, buf, sizeof(buf));
	if (rc != 0)
		return rc;
	if (sscanf(buf, "CEX%uP", type) != 1 && sscanf(buf, "CEX%uC", type) != 1)
		return EIO;

	sprintf(fname, "%scard%02x/hwtype", SYSFS_DEVICES_AP, adapter);
	rc = file_fgets(fname, buf, sizeof(buf));
	if (rc != 0)
		return rc;
	if (sscanf(buf, "%u", &hwtype) != 1)
		return EIO;

	sprintf(fname, "%scard%02x/raw_hwtype", SYSFS_DEVICES_AP, adapter);
	rc = file_fgets(fname, buf, sizeof(buf));
	if (rc != 0)
		return rc;
	if (sscanf(buf, "%u", &rawtype) != 1)
		return EIO;

	if (rawtype > hwtype) {
		DEBUG("%s adapter: %u hwtype: %u raw_hwtype: %u\n", __func__, adapter, hwtype, rawtype);
		/* Tolerated new card level: report calculated type */
		*type += (rawtype - hwtype);
	}

	return 0;
}

static int is_min_cex7(unsigned int card)
{
	unsigned int type;
	int rc;

	rc = get_card_type(card, &type);
	if (rc != 0 || type < 7)
		return 0;

	return 1;
}

static int ec_key_apqns_have_valid_version(struct zpc_ec_key *ec_key)
{
	size_t i;

	/* For all key types we need at least a CEX7 card. More detailed card
	 * version checking (e.g. card firmware level) may follow in future. */
	for (i = 0; i < ec_key->napqns; i++) {
		if (!is_min_cex7(ec_key->apqns[i].card))
			return 0;
	}

	return 1;
}
