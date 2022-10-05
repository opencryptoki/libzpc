/*
 * Copyright IBM Corp. 2021
 *
 * libzpc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <stdbool.h>

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

static int __ec_key_alloc_apqns_from_mkvp(struct pkey_apqn **, size_t *,
									const unsigned char[], int);
static void __ec_key_reset(struct zpc_ec_key *);


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

		rc = __ec_key_alloc_apqns_from_mkvp(&(ec_key->apqns),
			&(ec_key->napqns), ec_key->mkvp, type);
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

	rc = __ec_key_alloc_apqns_from_mkvp(&(ec_key->apqns),
	    &(ec_key->napqns), mkvpbuf, ec_key->type);
	if (rc != 0)
		goto ret;

	DEBUG("ec key at %p: mkvp and %lu apqns set", ec_key,
		ec_key->napqns);
	memcpy(ec_key->mkvp, mkvpbuf, mkvpbuflen);
	ec_key->apqns_set = 1;
	ec_key->mkvp_set = 1;
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
		rc = 0;
		goto ret;
	}

	if (*buflen < ec_key->cur.seclen) {
		*buflen = ec_key->cur.seclen;
		rc = ZPC_ERROR_SMALLOUTBUF;
		goto ret;
	}

	*buflen = ec_key->cur.seclen;
	memcpy(buf, ec_key->cur.sec, *buflen);

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
	int rc, rv;
	size_t i;

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

	if (buflen < MIN_EC_BLOB_SIZE || buflen > MAX_EC_BLOB_SIZE) {
		return ZPC_ERROR_ARG3RANGE;
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

	if (ec_key->type == ZPC_EC_KEY_TYPE_CCA && !is_cca_ec_key(buf, buflen)) {
		rc = ZPC_ERROR_EC_NO_CCA_SECUREKEY_TOKEN;
		goto ret;
	}

	if (ec_key->type == ZPC_EC_KEY_TYPE_EP11 && !is_ep11_ec_key(buf, buflen)) {
		rc = ZPC_ERROR_EC_NO_EP11_SECUREKEY_TOKEN;
		goto ret;
	}

	/* Set (secure) private key. Host lib not needed for this. */
	memset(ec_key->cur.sec, 0, sizeof(ec_key->cur.sec));
	memcpy(ec_key->cur.sec, buf, buflen);
	ec_key->cur.seclen = buflen;
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
	} else {
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
					target);
			free_ep11_target_for_apqn(&ep11, target);
			if (rc == 0)
				break;
		}
		rv = pthread_mutex_unlock(&ep11lock);
		assert(rv == 0);
		if (rc != 0 || ec_key->pub.publen == 0)
			ec_key->pubkey_set = 0;
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

	if (ec_key->apqns_set != 1) {
		rc = ZPC_ERROR_APQNSNOTSET;
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

		rc = ec_key_sec2prot(ec_key, EC_KEY_SEC_CUR);
		if (rc) {
			goto ret;
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

			rc = reencipher_ep11_key(&ep11, target, ec_key->apqns[i].card,
					ec_key->apqns[i].domain, reenc.sec, ec_key->cur.seclen,
					true);
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
		return rc;
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
		return rc;
		break;
	default:
		return ZPC_ERROR_KEYTYPE;
	}
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
	int rc;

	assert(sec == EC_KEY_SEC_OLD || sec == EC_KEY_SEC_CUR);

	if (sec == EC_KEY_SEC_CUR)
		key = &ec_key->cur;
	else if (sec == EC_KEY_SEC_OLD)
		key = &ec_key->old;
	assert(key != NULL);

	if (ec_key->type == ZPC_EC_KEY_TYPE_EP11)
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

	rc = ioctl(pkeyfd, PKEY_KBLOB2PROTK3, &io);
	if (rc != 0) {
		return ZPC_ERROR_IOCTLBLOB2PROTK3;
	}

	return 0;
}

/*
 * Returns list of napqns in apqns that match the mkvp and key type.
 * Caller takes ownership of apqns.
 * Returns 0 on success. Otherwise, an appropriate ZPC_ERROR is returned.
 */
static int __ec_key_alloc_apqns_from_mkvp(struct pkey_apqn **apqns,
								size_t *napqns, const unsigned char mkvp[],
								int type)
{
	struct pkey_apqns4keytype apqns4keytype;
	int rc;

	assert(apqns != NULL);
	assert(napqns != NULL);
	assert(mkvp != NULL);

	*apqns = NULL;
	*napqns = 0;

	for (;;) {
		if (*napqns > 0) {
			*apqns = calloc(*napqns, sizeof(**apqns));
			if (*apqns == NULL) {
				rc = ZPC_ERROR_MALLOC;
				goto ret;
			}
		}

		memset(&apqns4keytype, 0, sizeof(apqns4keytype));
		apqns4keytype.type = type;
		memcpy(apqns4keytype.cur_mkvp, mkvp,
		    sizeof(apqns4keytype.cur_mkvp));
		memcpy(apqns4keytype.alt_mkvp, mkvp,
		    sizeof(apqns4keytype.alt_mkvp));
		apqns4keytype.flags = PKEY_FLAGS_MATCH_CUR_MKVP;
		apqns4keytype.apqns = *apqns;
		apqns4keytype.apqn_entries = *napqns;

		rc = ioctl(pkeyfd, PKEY_APQNS4KT, &apqns4keytype);
		if (rc && (*napqns == 0 || (*napqns > 0 && rc != ENOSPC))) {
			rc = ZPC_ERROR_IOCTLAPQNS4KT;
			goto ret;
		} else if (rc == 0 && apqns4keytype.apqn_entries == 0) {
			rc = ZPC_ERROR_APQNNOTFOUND;
			goto ret;
		} else if (rc == 0 && *napqns > 0) {
			break;
		}

		free(*apqns);
		*apqns = NULL;

		*napqns = apqns4keytype.apqn_entries;
	}
	rc = 0;
ret:
	return rc;
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
