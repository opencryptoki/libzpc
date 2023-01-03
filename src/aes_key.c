/*
 * Copyright IBM Corp. 2021
 *
 * libzpc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <stdbool.h>

#include "zpc/aes_key.h"
#include "zpc/error.h"

#include "aes_key_local.h"
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

static void __aes_key_reset(struct zpc_aes_key *);
static int aes_key_blob_has_valid_mkvp(struct zpc_aes_key *aes_key,
								const unsigned char *buf, size_t buflen);
static int aes_key_blob_is_pkey_extractable(struct zpc_aes_key *aes_key,
								const unsigned char *buf, size_t buflen);
static int aes_key_add_ep11_header(struct zpc_aes_key *aes_key);

int
zpc_aes_key_alloc(struct zpc_aes_key **aes_key)
{
	pthread_mutexattr_t attr;
	struct zpc_aes_key *new_aes_key = NULL;
	int rc, rv, attr_init = 0;

	UNUSED(rv);

	if (pkeyfd < 0) {
		rc = ZPC_ERROR_DEVPKEY;
		goto ret;
	}
	if (aes_key == NULL) {
		rc = ZPC_ERROR_ARG1NULL;
		goto ret;
	}

	new_aes_key = calloc(1, sizeof(*new_aes_key));
	if (new_aes_key == NULL) {
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
	rc = pthread_mutex_init(&new_aes_key->lock, &attr);
	if (rc) {
		rc = ZPC_ERROR_INITLOCK;
		goto ret;
	}
	new_aes_key->refcount = 1;
	DEBUG("aes key at %p: refcount %llu", new_aes_key,
	    new_aes_key->refcount);

	*aes_key = new_aes_key;
	rc = 0;
ret:
	if (attr_init == 1) {
		rv = pthread_mutexattr_destroy(&attr);
		assert(rv == 0);
	}
	if (rc)
		free(new_aes_key);
	DEBUG("return %d (%s)", rc, zpc_error_string(rc));
	return rc;
}

int
zpc_aes_key_set_size(struct zpc_aes_key *aes_key, int keysize)
{
	int rc, rv;

	UNUSED(rv);

	if (pkeyfd < 0) {
		rc = ZPC_ERROR_DEVPKEY;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}
	if (aes_key == NULL) {
		rc = ZPC_ERROR_ARG1NULL;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}

	switch (keysize) {
	case 128:      /* fall-through */
	case 192:      /* fall-through */
	case 256:
		break;
	default:
		rc = ZPC_ERROR_KEYSIZE;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}

	rv = pthread_mutex_lock(&aes_key->lock);
	assert(rv == 0);

	if (aes_key->refcount != 1) {
		rc = ZPC_ERROR_OBJINUSE;
		goto ret;
	}

	if (aes_key->key_set == 1 && aes_key->keysize != keysize) {
		/* Unset key if it does not match the new keysize. */
		DEBUG("aes key at %p: key unset", aes_key);
		memset(&aes_key->cur, 0, sizeof(aes_key->cur));
		memset(&aes_key->old, 0, sizeof(aes_key->old));
		aes_key->key_set = 0;
	}

	DEBUG("aes key at %p: size set to %d", aes_key, keysize);
	aes_key->keysize = keysize;
	aes_key->keysize_set = 1;
	rc = 0;
ret:
	rv = pthread_mutex_unlock(&aes_key->lock);
	assert(rv == 0);
	DEBUG("return %d (%s)", rc, zpc_error_string(rc));
	return rc;
}

int
zpc_aes_key_set_type(struct zpc_aes_key *aes_key, int type)
{
	int rc, rv;

	UNUSED(rv);

	if (pkeyfd < 0) {
		rc = ZPC_ERROR_DEVPKEY;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}
	if (aes_key == NULL) {
		rc = ZPC_ERROR_ARG1NULL;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}

	switch (type) {
	case ZPC_AES_KEY_TYPE_CCA_DATA:        /* fall-through */
	case ZPC_AES_KEY_TYPE_CCA_CIPHER:      /* fall-through */
	case ZPC_AES_KEY_TYPE_EP11:
		break;
	default:
		rc = ZPC_ERROR_KEYTYPE;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}

	rv = pthread_mutex_lock(&aes_key->lock);
	assert(rv == 0);

	if (aes_key->refcount != 1) {
		rc = ZPC_ERROR_OBJINUSE;
		goto ret;
	}

	if (aes_key->type_set == 1 && aes_key->type != type
	    && aes_key->mkvp_set == 1) {
		/* Update mkvp-based apqn choices in case of type change. */
		DEBUG("aes key at %p: update apqns to match type %d", aes_key,
		    type);
		free(aes_key->apqns);
		aes_key->apqns = NULL;
		aes_key->napqns = 0;
		aes_key->apqns_set = 0;

		rc = alloc_apqns_from_mkvp(pkeyfd, &(aes_key->apqns), &(aes_key->napqns),
								aes_key->mkvp, type);
		if (rc != 0)
			goto ret;

		DEBUG("aes key at %p: %lu apqns set", aes_key, aes_key->napqns);
		aes_key->apqns_set = 1;
	}

	DEBUG("aes key at %p: type set to %d", aes_key, type);
	aes_key->type = type;
	aes_key->type_set = 1;
	rc = 0;
ret:
	rv = pthread_mutex_unlock(&aes_key->lock);
	assert(rv == 0);
	DEBUG("return %d (%s)", rc, zpc_error_string(rc));
	return rc;
}

int
zpc_aes_key_set_flags(struct zpc_aes_key *aes_key, unsigned int flags)
{
	int rc, rv;

	UNUSED(rv);

	if (pkeyfd < 0) {
		rc = ZPC_ERROR_DEVPKEY;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}
	if (aes_key == NULL) {
		rc = ZPC_ERROR_ARG1NULL;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}

	rv = pthread_mutex_lock(&aes_key->lock);
	assert(rv == 0);

	if (aes_key->refcount != 1) {
		rc = ZPC_ERROR_OBJINUSE;
		goto ret;
	}

	DEBUG("aes key at %p: flags set to %u", aes_key, flags);
	aes_key->flags = flags;
	aes_key->flags_set = 1;
	rc = 0;
ret:
	rv = pthread_mutex_unlock(&aes_key->lock);
	assert(rv == 0);
	DEBUG("return %d (%s)", rc, zpc_error_string(rc));
	return rc;
}

/*
 * Associate aes_key to all apqns of the given mkvp.
 */
int
zpc_aes_key_set_mkvp(struct zpc_aes_key *aes_key, const char *mkvp)
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
	if (aes_key == NULL) {
		rc = ZPC_ERROR_ARG1NULL;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}

	rv = pthread_mutex_lock(&aes_key->lock);
	assert(rv == 0);

	if (aes_key->refcount != 1) {
		rc = ZPC_ERROR_OBJINUSE;
		goto ret;
	}

	if (mkvp == NULL) {
		DEBUG("aes key at %p: apqns unset", aes_key);
		free(aes_key->apqns);
		aes_key->apqns = NULL;
		aes_key->napqns = 0;
		aes_key->apqns_set = 0;
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

	if (aes_key->type_set != 1) {
		rc = ZPC_ERROR_KEYTYPENOTSET;
		goto ret;
	}

	DEBUG("aes key at %p: apqns unset", aes_key);
	free(aes_key->apqns);
	aes_key->apqns = NULL;
	aes_key->napqns = 0;
	aes_key->apqns_set = 0;

	rc = alloc_apqns_from_mkvp(pkeyfd, &(aes_key->apqns), &(aes_key->napqns),
							mkvpbuf, aes_key->type);
	if (rc != 0)
		goto ret;

	DEBUG("aes key at %p: mkvp and %lu apqns set", aes_key,
	    aes_key->napqns);
	memcpy(aes_key->mkvp, mkvpbuf, mkvpbuflen);
	aes_key->apqns_set = 1;
	aes_key->mkvp_set = 1;
ret:
	rv = pthread_mutex_unlock(&aes_key->lock);
	assert(rv == 0);
	DEBUG("return %d (%s)", rc, zpc_error_string(rc));
	return rc;
}

/*
 * Associate aes_key to a list NULL terminated list of apqns.
 */
int
zpc_aes_key_set_apqns(struct zpc_aes_key *aes_key, const char *apqns[])
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
	if (aes_key == NULL) {
		rc = ZPC_ERROR_ARG1NULL;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}

	rv = pthread_mutex_lock(&aes_key->lock);
	assert(rv == 0);

	if (apqns == NULL) {
		DEBUG("aes key at %p: apqns unset", aes_key);
		free(aes_key->apqns);
		aes_key->apqns = NULL;
		aes_key->napqns = 0;
		aes_key->apqns_set = 0;
		rc = 0;
		goto ret;
	}

	for (napqns = 0; apqns[napqns] != NULL; napqns++);

	if (aes_key->refcount != 1) {
		rc = ZPC_ERROR_OBJINUSE;
		goto ret;
	}

	DEBUG("aes key at %p: apqns unset", aes_key);
	free(aes_key->apqns);
	aes_key->apqns = NULL;
	aes_key->napqns = 0;
	aes_key->apqns_set = 0;

	DEBUG("aes key at %p: mkvp unset", aes_key);
	memset(aes_key->mkvp, 0, sizeof(aes_key->mkvp));
	aes_key->mkvplen = 0;
	aes_key->mkvp_set = 0;

	if (napqns == 0) {
		rc = 0; /* nothing to do */
		goto ret;
	}

	aes_key->apqns = calloc(napqns, sizeof(*(aes_key->apqns)));
	if (aes_key->apqns == NULL)
		return ZPC_ERROR_MALLOC;

	for (i = 0; i < napqns; i++) {
		rc = sscanf(apqns[i], " %x.%x ", &card, &domain);
		if (rc != 2) {
			rc = ZPC_ERROR_PARSE;
			goto ret;
		}
		aes_key->apqns[i].card = card;
		aes_key->apqns[i].domain = domain;
	}

	DEBUG("aes key at %p: %lu apqns set", aes_key, aes_key->napqns);
	aes_key->napqns = napqns;
	aes_key->apqns_set = 1;
	rc = 0;
ret:
	if (rc != 0) {
		free(aes_key->apqns);
		aes_key->apqns = NULL;
		aes_key->napqns = 0;
	}
	rv = pthread_mutex_unlock(&aes_key->lock);
	assert(rv == 0);
	DEBUG("return %d (%s)", rc, zpc_error_string(rc));
	return rc;
}

int
zpc_aes_key_import_clear(struct zpc_aes_key *aes_key, const unsigned char *key)
{
	struct pkey_clr2seck2 clr2seck2;
	unsigned int flags;
	int rc, rv;

	UNUSED(rv);

	if (pkeyfd < 0) {
		rc = ZPC_ERROR_DEVPKEY;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}
	if (aes_key == NULL) {
		rc = ZPC_ERROR_ARG1NULL;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}
	if (key == NULL) {
		rc = ZPC_ERROR_ARG2NULL;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}

	rv = pthread_mutex_lock(&aes_key->lock);
	assert(rv == 0);

	if (aes_key->refcount != 1) {
		rc = ZPC_ERROR_OBJINUSE;
		goto ret;
	}

	if (aes_key->apqns_set != 1) {
		rc = ZPC_ERROR_APQNSNOTSET;
		goto ret;
	}
	if (aes_key->keysize_set != 1) {
		rc = ZPC_ERROR_KEYSIZENOTSET;
		goto ret;
	}
	if (aes_key->type_set != 1) {
		rc = ZPC_ERROR_KEYTYPENOTSET;
		goto ret;
	}
	flags = aes_key->flags_set == 1 ? aes_key->flags : 0;

	memset(&aes_key->cur, 0, sizeof(aes_key->cur));
	memset(&aes_key->old, 0, sizeof(aes_key->old));
	aes_key->key_set = 0;

	memset(&clr2seck2, 0, sizeof(clr2seck2));
	clr2seck2.apqns = aes_key->apqns;
	clr2seck2.apqn_entries = aes_key->napqns;
	clr2seck2.type = aes_key->type;
	clr2seck2.size = aes_key->keysize;
	clr2seck2.keygenflags = flags;
	memcpy(&clr2seck2.clrkey, key, aes_key->keysize / 8);
	clr2seck2.key = aes_key->cur.sec;
	clr2seck2.keylen = sizeof(aes_key->cur.sec);

	rc = ioctl(pkeyfd, PKEY_CLR2SECK2, &clr2seck2);
	if (rc != 0) {
		rc = ZPC_ERROR_IOCTLCLR2SECK2;
		goto ret;
	}

	aes_key->cur.seclen = clr2seck2.keylen;

	rc = aes_key_sec2prot(aes_key, AES_KEY_SEC_CUR);
	if (rc) {
		goto ret;
	}

	if (aes_key->type == ZPC_AES_KEY_TYPE_EP11) {
		rc = aes_key_add_ep11_header(aes_key);
		if (rc)
			goto ret;
	}

	DEBUG("aes key at %p: key set", aes_key);
	aes_key->key_set = 1;
	rc = 0;
ret:
	if (rc != 0)
		memset(&aes_key->cur, 0, sizeof(aes_key->cur));

	rv = pthread_mutex_unlock(&aes_key->lock);
	assert(rv == 0);

	memzero_secure(&clr2seck2.clrkey, sizeof(clr2seck2.clrkey));
	DEBUG("return %d (%s)", rc, zpc_error_string(rc));
	return rc;
}

int
zpc_aes_key_export(struct zpc_aes_key *aes_key, unsigned char *buf,
    size_t *buflen)
{
	int rc, rv;

	UNUSED(rv);

	if (pkeyfd < 0) {
		rc = ZPC_ERROR_DEVPKEY;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}
	if (aes_key == NULL) {
		rc = ZPC_ERROR_ARG1NULL;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}
	if (buflen == NULL) {
		rc = ZPC_ERROR_ARG3NULL;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}

	rv = pthread_mutex_lock(&aes_key->lock);
	assert(rv == 0);

	if (aes_key->rand_protk) {
		rc = ZPC_ERROR_PROTKEYONLY;
		goto ret;
	}

	rc = aes_key_check(aes_key);
	if (rc)
		goto ret;

	if (buf == NULL) {
		*buflen = aes_key->cur.seclen;
		rc = 0;
		goto ret;
	}

	if (*buflen < aes_key->cur.seclen) {
		*buflen = aes_key->cur.seclen;
		rc = ZPC_ERROR_SMALLOUTBUF;
		goto ret;
	}

	*buflen = aes_key->cur.seclen;
	memcpy(buf, aes_key->cur.sec, *buflen);
	rc = 0;
ret:
	rv = pthread_mutex_unlock(&aes_key->lock);
	assert(rv == 0);
	DEBUG("return %d (%s)", rc, zpc_error_string(rc));
	return rc;
}

int
zpc_aes_key_import(struct zpc_aes_key *aes_key, const unsigned char *buf,
    size_t buflen)
{
	int rc, rv;

	UNUSED(rv);

	if (pkeyfd < 0) {
		return ZPC_ERROR_DEVPKEY;
	}
	if (aes_key == NULL) {
		return ZPC_ERROR_ARG1NULL;
	}
	if (buf == NULL) {
		return ZPC_ERROR_ARG2NULL;
	}
	if (buflen < MIN_SECURE_KEY_SIZE || buflen > MAX_SECURE_KEY_SIZE) {
		return ZPC_ERROR_ARG3RANGE;
	}

	rv = pthread_mutex_lock(&aes_key->lock);
	assert(rv == 0);

	if (aes_key->refcount != 1) {
		rc = ZPC_ERROR_OBJINUSE;
		goto ret;
	}

	if (aes_key->keysize_set != 1) {
		rc = ZPC_ERROR_KEYSIZENOTSET;
		goto ret;
	}
	if (aes_key->type_set != 1) {
		rc = ZPC_ERROR_KEYTYPENOTSET;
		goto ret;
	}

	if (aes_key->type == ZPC_AES_KEY_TYPE_EP11 &&
		!is_ep11_aes_key_with_header(buf, buflen) &&
		!is_ep11_aes_key(buf, buflen)) {
		rc = ZPC_ERROR_AES_NO_EP11_SECUREKEY_TOKEN;
		goto ret;
	}

	if (aes_key->type == ZPC_AES_KEY_TYPE_CCA_DATA && !is_cca_aes_data_key(buf, buflen)) {
		rc = ZPC_ERROR_AES_NO_CCA_DATAKEY_TOKEN;
		goto ret;
	}

	if (aes_key->type == ZPC_AES_KEY_TYPE_CCA_CIPHER && !is_cca_aes_cipher_key(buf, buflen)) {
		rc = ZPC_ERROR_AES_NO_CCA_CIPHERKEY_TOKEN;
		goto ret;
	}

	if (!aes_key_blob_has_valid_mkvp(aes_key, buf, buflen)) {
		rc = ZPC_ERROR_WKVPMISMATCH;
		goto ret;
	}

	if (!aes_key_blob_is_pkey_extractable(aes_key, buf, buflen)) {
		rc = ZPC_ERROR_BLOB_NOT_PKEY_EXTRACTABLE;
		goto ret;
	}

	memset(aes_key->cur.sec, 0, sizeof(aes_key->cur.sec));
	memcpy(aes_key->cur.sec, buf, buflen);
	aes_key->cur.seclen = buflen;
	aes_key->key_set = 1;

	if (aes_key->type == ZPC_AES_KEY_TYPE_EP11 && is_ep11_aes_key(buf, buflen)) {
		rc = aes_key_add_ep11_header(aes_key);
		if (rc)
			goto ret;
	}

	rc = 0;
ret:
	rv = pthread_mutex_unlock(&aes_key->lock);
	assert(rv == 0);
	DEBUG("return %d (%s)", rc, zpc_error_string(rc));
	return rc;
}

int
zpc_aes_key_generate(struct zpc_aes_key *aes_key)
{
	struct pkey_genseck2 genseck2;
	struct pkey_genprotk genprotk;
	unsigned int flags;
	int rc, rv;

	UNUSED(rv);

	if (pkeyfd < 0) {
		rc = ZPC_ERROR_DEVPKEY;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}
	if (aes_key == NULL) {
		rc = ZPC_ERROR_ARG1NULL;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}

	rv = pthread_mutex_lock(&aes_key->lock);
	assert(rv == 0);

	if (aes_key->refcount != 1) {
		rc = ZPC_ERROR_OBJINUSE;
		goto ret;
	}

	if (aes_key->keysize_set != 1) {
		rc = ZPC_ERROR_KEYSIZENOTSET;
		goto ret;
	}
	if (aes_key->apqns_set != 1) {
		/* Generate random protected key only. */
		memset(&genprotk, 0, sizeof(genprotk));

		switch (aes_key->keysize) {
		case 128:
			genprotk.keytype = PKEY_KEYTYPE_AES_128;
			break;
		case 192:
			genprotk.keytype = PKEY_KEYTYPE_AES_192;
			break;
		case 256:
			genprotk.keytype = PKEY_KEYTYPE_AES_256;
			break;
		default:
			rc = ZPC_ERROR_KEYSIZE;
			goto ret;
			break;
		}

		rc = ioctl(pkeyfd, PKEY_GENPROTK, &genprotk);
		if (rc != 0) {
			rc = ZPC_ERROR_IOCTLGENPROTK;
			goto ret;
		}

		DEBUG("aes key at %p: key set to generated protected key",
		    aes_key);
		memcpy(&aes_key->prot, &genprotk.protkey,
		    sizeof(aes_key->prot));
		aes_key->rand_protk = 1;
		aes_key->key_set = 1;
		rc = 0;
		goto ret;
	}
	if (aes_key->type_set != 1) {
		rc = ZPC_ERROR_KEYTYPENOTSET;
		goto ret;
	}
	flags = aes_key->flags_set == 1 ? aes_key->flags : 0;

	memset(&aes_key->cur, 0, sizeof(aes_key->cur));
	memset(&aes_key->old, 0, sizeof(aes_key->old));
	aes_key->key_set = 0;

	memset(&genseck2, 0, sizeof(genseck2));
	genseck2.apqns = aes_key->apqns;
	genseck2.apqn_entries = aes_key->napqns;
	genseck2.type = aes_key->type;
	genseck2.size = aes_key->keysize;
	genseck2.keygenflags = flags;
	genseck2.key = aes_key->cur.sec;
	genseck2.keylen = sizeof(aes_key->cur.sec);

	rc = ioctl(pkeyfd, PKEY_GENSECK2, &genseck2);
	if (rc != 0) {
		rc = ZPC_ERROR_IOCTLGENSECK2;
		goto ret;
	}

	aes_key->cur.seclen = genseck2.keylen;

	rc = aes_key_sec2prot(aes_key, AES_KEY_SEC_CUR);
	if (rc)
		goto ret;

	if (aes_key->type == ZPC_AES_KEY_TYPE_EP11) {
		rc = aes_key_add_ep11_header(aes_key);
		if (rc)
			goto ret;
	}

	DEBUG("aes key at %p: key set to generated secure key", aes_key);
	aes_key->key_set = 1;
	rc = 0;
ret:
	if (rc != 0)
		memset(&aes_key->cur, 0, sizeof(aes_key->cur));

	rv = pthread_mutex_unlock(&aes_key->lock);
	assert(rv == 0);
	DEBUG("return %d (%s)", rc, zpc_error_string(rc));
	return rc;
}

int
zpc_aes_key_reencipher(struct zpc_aes_key *aes_key, int method)
{
	struct aes_key reenc;
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
	if (aes_key == NULL) {
		rc = ZPC_ERROR_ARG1NULL;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}

	rv = pthread_mutex_lock(&aes_key->lock);
	assert(rv == 0);

	if (aes_key->rand_protk) {
		rc = ZPC_ERROR_PROTKEYONLY;
		goto ret;
	}

	if (aes_key->key_set == 0) {
		rc = ZPC_ERROR_KEYNOTSET;
		goto ret;
	}
	if (aes_key->keysize_set == 0) {
		rc = ZPC_ERROR_KEYSIZENOTSET;
		goto ret;
	}
	if (aes_key->type_set == 0) {
		rc = ZPC_ERROR_KEYTYPENOTSET;
		goto ret;
	}
	if (aes_key->apqns_set == 0 || aes_key->napqns == 0) {
		rc = ZPC_ERROR_APQNSNOTSET;
		goto ret;
	}

	memcpy(&reenc, &aes_key->cur, sizeof(reenc));

	switch (aes_key->type) {
	case ZPC_AES_KEY_TYPE_CCA_DATA:        /* fall-through */
	case ZPC_AES_KEY_TYPE_CCA_CIPHER:      /* fall-through */
		seckeylen =
		    aes_key->type ==
		    ZPC_AES_KEY_TYPE_CCA_DATA ? AESDATA_KEY_SIZE :
		    AESCIPHER_KEY_SIZE;
		rv = pthread_mutex_lock(&ccalock);
		assert(rv == 0);
		for (i = 0; i < aes_key->napqns; i++) {
			rc = select_cca_adapter(&cca, aes_key->apqns[i].card,
			    aes_key->apqns[i].domain, true);
			if (rc)
				continue;
			rc = key_token_change(&cca, reenc.sec, seckeylen,
			    method ==
			    ZPC_AES_KEY_REENCIPHER_OLD_TO_CURRENT ?
			    METHOD_OLD_TO_CURRENT : METHOD_CURRENT_TO_NEW,
			    true);
			if (rc == 0)
				break;
		}
		rv = pthread_mutex_unlock(&ccalock);
		assert(rv == 0);
		break;
	case ZPC_AES_KEY_TYPE_EP11:
		if (method != ZPC_AES_KEY_REENCIPHER_CURRENT_TO_NEW) {
			rc = ZPC_ERROR_NOTSUP;
			goto ret;
		}

		rv = pthread_mutex_lock(&ep11lock);
		assert(rv == 0);

		for (i = 0; i < aes_key->napqns; i++) {
			rc = get_ep11_target_for_apqn(&ep11,
			    aes_key->apqns[i].card, aes_key->apqns[i].domain,
			    &target, true);
			if (rc)
				continue;

			/* Note that the secure key is a TOKVER_EP11_AES_WITH_HEADER and has a
			 * 16-byte ep11kblob_header prepended before the actual secure key blob.
			 * For reencipher we have to skip this prepended hdr and provide the
			 * key blob directly. */
			rc = reencipher_ep11_key(&ep11, target,
						aes_key->apqns[i].card, aes_key->apqns[i].domain,
						reenc.sec + sizeof(struct ep11kblob_header),
						aes_key->cur.seclen - sizeof(struct ep11kblob_header),
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

	memcpy(&aes_key->old, &aes_key->cur, sizeof(aes_key->old));
	memcpy(&aes_key->cur, &reenc, sizeof(aes_key->cur));
	rc = 0;
ret:
	rv = pthread_mutex_unlock(&aes_key->lock);
	assert(rv == 0);
	DEBUG("return %d (%s)", rc, zpc_error_string(rc));
	return rc;
}

void
zpc_aes_key_free(struct zpc_aes_key **aes_key)
{
	int rv, free_obj = 0;

	UNUSED(rv);

	if (aes_key == NULL)
		return;
	if (*aes_key == NULL)
		return;

	rv = pthread_mutex_lock(&(*aes_key)->lock);
	assert(rv == 0);

	if ((*aes_key)->refcount == 0)
		goto ret;

	(*aes_key)->refcount--;
	DEBUG("aes key at %p: refcount %llu", *aes_key, (*aes_key)->refcount);

	if ((*aes_key)->refcount == 0) {
		free_obj = 1;
		__aes_key_reset(*aes_key);
	}

ret:
	rv = pthread_mutex_unlock(&(*aes_key)->lock);
	assert(rv == 0);

	if (free_obj == 1) {
		rv = pthread_mutex_destroy(&(*aes_key)->lock);
		assert(rv == 0);

		free(*aes_key);
	}
	*aes_key = NULL;
	DEBUG("return");
}

/*
 * Reset everything that was set after allocation.
 * Caller must hold aes_key's wr lock.
 */
static void
__aes_key_reset(struct zpc_aes_key *aes_key)
{

	assert(aes_key != NULL);

	memset(&aes_key->cur, 0, sizeof(aes_key->cur));
	memset(&aes_key->old, 0, sizeof(aes_key->old));
	memset(&aes_key->prot, 0, sizeof(aes_key->prot));
	aes_key->key_set = 0;

	aes_key->keysize = 0;
	aes_key->keysize_set = 0;

	aes_key->flags = 0;
	aes_key->flags_set = 0;

	aes_key->type = 0;
	aes_key->type_set = 0;

	memset(aes_key->mkvp, 0, sizeof(aes_key->mkvp));
	aes_key->mkvplen = 0;
	aes_key->mkvp_set = 0;

	free(aes_key->apqns);
	aes_key->apqns = NULL;
	aes_key->napqns = 0;
	aes_key->apqns_set = 0;

	aes_key->rand_protk = 0;

	aes_key->refcount = 1;
}

/*
 * (Re)derive protected key from a secure key.
 * Caller must hold aes_key's wr lock.
 */
int aes_key_sec2prot_without_header(struct zpc_aes_key *aes_key, enum aes_key_sec sec)
{
	struct pkey_kblob2pkey2 io;
	struct aes_key *key = NULL;
	int rc;

	assert(sec == AES_KEY_SEC_OLD || sec == AES_KEY_SEC_CUR);

	if (sec == AES_KEY_SEC_CUR)
		key = &aes_key->cur;
	else if (sec == AES_KEY_SEC_OLD)
		key = &aes_key->old;
	assert(key != NULL);

	memset(&io, 0, sizeof(io));
	io.key = key->sec;
	io.keylen = key->seclen;
	io.apqns = aes_key->apqns;
	io.apqn_entries = aes_key->napqns;

	rc = ioctl(pkeyfd, PKEY_KBLOB2PROTK2, &io);
	if (rc != 0)
		return ZPC_ERROR_IOCTLBLOB2PROTK2;

	memcpy(&aes_key->prot, &io.protkey, sizeof(aes_key->prot));
	return 0;
}

/*
 * Currently there is no ioctl to convert a TOKVER_EP11_AES_WITH_HEADER. So
 * prepare an overlay over the session id field and convert it as a
 * TOKVER_EP11_AES. Then restore the session id field.
 */
int aes_key_sec2prot_with_header(struct zpc_aes_key *aes_key, enum aes_key_sec sec)
{
	struct pkey_kblob2pkey2 io;
	struct aes_key *key = NULL;
	int rc;
	unsigned char temp[sizeof(struct ep11kblob_header)];
	struct ep11kblob_header *hdr;

	assert(sec == AES_KEY_SEC_OLD || sec == AES_KEY_SEC_CUR);

	if (sec == AES_KEY_SEC_CUR)
		key = &aes_key->cur;
	else if (sec == AES_KEY_SEC_OLD)
		key = &aes_key->old;
	assert(key != NULL);

	memcpy(temp, key->sec + 16, 16); // save first 16 bytes session id
	memcpy(key->sec + 16, key->sec, 16); // overlay hdr in session id
	hdr = (struct ep11kblob_header *)(key->sec + 16);
	hdr->version = TOKEN_VERSION_EP11_AES; // set key type TOKVER_EP11_AES
	hdr->len = key->seclen - 16; // adjust length

	memset(&io, 0, sizeof(io));
	io.key = key->sec + 16;
	io.keylen = key->seclen - 16;
	io.apqns = aes_key->apqns;
	io.apqn_entries = aes_key->napqns;

	rc = ioctl(pkeyfd, PKEY_KBLOB2PROTK2, &io);

	memcpy(key->sec + 16, temp, 16); // restore session id in any case

	if (rc != 0)
		return ZPC_ERROR_IOCTLBLOB2PROTK2;

	memcpy(&aes_key->prot, &io.protkey, sizeof(aes_key->prot));
	return 0;
}

/*
 * (Re)derive protected key from a secure key.
 * Caller must hold aes_key's wr lock.
 */
int aes_key_sec2prot(struct zpc_aes_key *aes_key, enum aes_key_sec sec)
{
	if (aes_key->type == ZPC_AES_KEY_TYPE_EP11) {
		struct aes_key *key = NULL;
		size_t keylen;
		assert(sec == AES_KEY_SEC_OLD || sec == AES_KEY_SEC_CUR);
		if (sec == AES_KEY_SEC_CUR) {
			key = &aes_key->cur;
			keylen = aes_key->cur.seclen;
		} else if (sec == AES_KEY_SEC_OLD) {
			key = &aes_key->old;
			keylen = aes_key->old.seclen;
		}
		assert(key != NULL);
		if (is_ep11_aes_key_with_header(key->sec, keylen))
			return aes_key_sec2prot_with_header(aes_key, sec);
	}

	return aes_key_sec2prot_without_header(aes_key, sec);
}

int
aes_key_check(const struct zpc_aes_key *aes_key)
{
	if (aes_key->key_set != 1)
		return ZPC_ERROR_KEYNOTSET;
	if (aes_key->keysize_set != 1)
		return ZPC_ERROR_KEYSIZENOTSET;
	/* Random protected keys have no type. */
	if (aes_key->rand_protk == 0 && aes_key->type_set != 1)
		return ZPC_ERROR_KEYTYPENOTSET;

	return 0;
}

static int aes_key_blob_has_valid_mkvp(struct zpc_aes_key *aes_key,
				const unsigned char *buf, size_t buflen)
{
	const unsigned char *mkvp, *keytoken;
	unsigned int mkvp_len;
	u64 mkvp_value;

	if (aes_key->mkvp_set == 0)
		return 1; /* cannot judge */

	keytoken = buf;
	if (is_ep11_aes_key_with_header(buf, buflen))
		keytoken += sizeof(struct ep11kblob_header);

	switch (aes_key->type) {
	case ZPC_AES_KEY_TYPE_CCA_DATA:
		mkvp_value = ((struct aesdatakeytoken *)keytoken)->mkvp;
		mkvp = (const unsigned char *)&mkvp_value;
		mkvp_len = MKVP_LEN_CCA;
		break;
	case ZPC_AES_KEY_TYPE_CCA_CIPHER:
		mkvp = ((struct aescipherkeytoken *)keytoken)->kvp;
		mkvp_len = MKVP_LEN_CCA;
		break;
	default:
		mkvp = ((struct ep11keytoken *)keytoken)->wkvp;
		mkvp_len = MKVP_LEN_EP11;
		break;
	}

	if (memcmp(aes_key->mkvp, mkvp, mkvp_len) == 0)
		return 1;

	return 0;
}

static int aes_key_blob_is_pkey_extractable(struct zpc_aes_key *aes_key,
					const unsigned char *buf, size_t buflen)
{
	const unsigned char *keytoken;
	u16 kmf1;
	u64 attr;

	keytoken = buf;
	if (is_ep11_aes_key_with_header(buf, buflen))
		keytoken += sizeof(struct ep11kblob_header);

	switch (aes_key->type) {
	case ZPC_AES_KEY_TYPE_CCA_DATA:
		/* No check possible. The flags field in struct aesdatakeytoken
		 * does not contain a CCA_XPRTCPAC indication. */
		return 1;
	case ZPC_AES_KEY_TYPE_CCA_CIPHER:
		kmf1 = ((struct aescipherkeytoken *)keytoken)->kmf1;
		if (kmf1 & KMF1_XPRT_CPAC)
			return 1;
		break;
	case ZPC_AES_KEY_TYPE_EP11:
		attr = ((struct ep11keytoken *)keytoken)->attr;
		if (attr & XCP_BLOB_PROTKEY_EXTRACTABLE)
			return 1;
		break;
	default:
		break;
	}

	return 0;
}

static int aes_key_add_ep11_header(struct zpc_aes_key *aes_key)
{
	struct ep11kblob_header *ep11hdr;

	if (aes_key->cur.seclen + sizeof(struct ep11kblob_header) > sizeof(aes_key->cur.sec))
		return 1;

	memset(aes_key->cur.sec, 0, sizeof(struct ep11kblob_header));
	memmove(aes_key->cur.sec + sizeof(struct ep11kblob_header), aes_key->cur.sec, aes_key->cur.seclen);
	memset(aes_key->cur.sec + sizeof(struct ep11kblob_header), 0, 32);

	ep11hdr = (struct ep11kblob_header *)aes_key->cur.sec;
	ep11hdr->len = sizeof(struct ep11kblob_header) + aes_key->cur.seclen;
	ep11hdr->version = TOKVER_EP11_AES_WITH_HEADER;
	aes_key->cur.seclen = ep11hdr->len;

	return 0;
}
