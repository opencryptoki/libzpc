/*
 * Copyright IBM Corp. 2025
 *
 * libzpc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>

#include "zpc/hmac_key.h"
#include "zpc/error.h"

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

#include "cpacf.h"
#include "hmac_key_local.h"

static void __hmac_key_reset(struct zpc_hmac_key *);
static int hmac_key_pvsec2prot(struct zpc_hmac_key *hmac_key);
static int hmac_key_blob_is_valid_pvsecret_id(struct zpc_hmac_key *hmac_key,
		const unsigned char *id);
static int hmac_key_generate(struct hmac_genprotk *genprotk);

const size_t hfunc2blksize[] = {
	64, 64, 128, 128,
};

const size_t hfunc2keybitsize[] = {
	512, 512, 1024, 1024,
};

const int hfunc2klmdfc[] = {
	CPACF_KLMD_SHA_256,
	CPACF_KLMD_SHA_256,
	CPACF_KLMD_SHA_512,
	CPACF_KLMD_SHA_512,
};

const char icv_sha_224[] = {
	0xc1, 0x05, 0x9e, 0xd8, 0x36, 0x7c, 0xd5, 0x07, 0x30, 0x70, 0xdd, 0x17,
	0xf7, 0x0e, 0x59, 0x39, 0xff, 0xc0, 0x0b, 0x31, 0x68, 0x58, 0x15, 0x11,
	0x64, 0xf9, 0x8f, 0xa7, 0xbe, 0xfa, 0x4f, 0xa4,
};

const char icv_sha_256[] = {
	0x6a, 0x09, 0xe6, 0x67, 0xbb, 0x67, 0xae, 0x85, 0x3c, 0x6e, 0xf3, 0x72,
	0xa5, 0x4f, 0xf5, 0x3a, 0x51, 0x0e, 0x52, 0x7f, 0x9b, 0x05, 0x68, 0x8c,
	0x1f, 0x83, 0xd9, 0xab, 0x5b, 0xe0, 0xcd, 0x19,
};

const char icv_sha_384[] = {
	0xcb, 0xbb, 0x9d, 0x5d, 0xc1, 0x05, 0x9e, 0xd8, 0x62, 0x9a, 0x29, 0x2a,
	0x36, 0x7c, 0xd5, 0x07, 0x91, 0x59, 0x01, 0x5a, 0x30, 0x70, 0xdd, 0x17,
	0x15, 0x2f, 0xec, 0xd8, 0xf7, 0x0e, 0x59, 0x39, 0x67, 0x33, 0x26, 0x67,
	0xff, 0xc0, 0x0b, 0x31, 0x8e, 0xb4, 0x4a, 0x87, 0x68, 0x58, 0x15, 0x11,
	0xdb, 0x0c, 0x2e, 0x0d, 0x64, 0xf9, 0x8f, 0xa7, 0x47, 0xb5, 0x48, 0x1d,
	0xbe, 0xfa, 0x4f, 0xa4,
};

const char icv_sha_512[] = {
	0x6a, 0x09, 0xe6, 0x67, 0xf3, 0xbc, 0xc9, 0x08, 0xbb, 0x67, 0xae, 0x85,
	0x84, 0xca, 0xa7, 0x3b, 0x3c, 0x6e, 0xf3, 0x72, 0xfe, 0x94, 0xf8, 0x2b,
	0xa5, 0x4f, 0xf5, 0x3a, 0x5f, 0x1d, 0x36, 0xf1, 0x51, 0x0e, 0x52, 0x7f,
	0xad, 0xe6, 0x82, 0xd1, 0x9b, 0x05, 0x68, 0x8c, 0x2b, 0x3e, 0x6c, 0x1f,
	0x1f, 0x83, 0xd9, 0xab, 0xfb, 0x41, 0xbd, 0x6b, 0x5b, 0xe0, 0xcd, 0x19,
	0x13, 0x7e, 0x21, 0x79,
};

#define SHA224_DIGEST_LENGTH          28
#define SHA256_DIGEST_LENGTH          32
#define SHA384_DIGEST_LENGTH          48
#define SHA512_DIGEST_LENGTH          64

int zpc_hmac_key_alloc(struct zpc_hmac_key **hmac_key)
{
	pthread_mutexattr_t attr;
	struct zpc_hmac_key *new_hmac_key = NULL;
	int rc, rv, attr_init = 0;

	UNUSED(rv);

	if (pkeyfd < 0) {
		rc = ZPC_ERROR_DEVPKEY;
		goto ret;
	}
	if (hmac_key == NULL) {
		rc = ZPC_ERROR_ARG1NULL;
		goto ret;
	}

	new_hmac_key = calloc(1, sizeof(*new_hmac_key));
	if (new_hmac_key == NULL) {
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
	rc = pthread_mutex_init(&new_hmac_key->lock, &attr);
	if (rc) {
		rc = ZPC_ERROR_INITLOCK;
		goto ret;
	}
	new_hmac_key->refcount = 1;
	DEBUG("hmac key at %p: refcount %llu", new_hmac_key, new_hmac_key->refcount);

	*hmac_key = new_hmac_key;
	rc = 0;
ret:
	if (attr_init == 1) {
		rv = pthread_mutexattr_destroy(&attr);
		assert(rv == 0);
	}
	if (rc)
		free(new_hmac_key);
	DEBUG("return %d (%s)", rc, zpc_error_string(rc));
	return rc;
}

int zpc_hmac_key_set_type(struct zpc_hmac_key *hmac_key, int type)
{
	int rc, rv;

	UNUSED(rv);

	if (pkeyfd < 0) {
		rc = ZPC_ERROR_DEVPKEY;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}
	if (hmac_key == NULL) {
		rc = ZPC_ERROR_ARG1NULL;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}

	switch (type) {
	case ZPC_HMAC_KEY_TYPE_PVSECRET:
		if (!swcaps.uv_pvsecrets) {
			rc = ZPC_ERROR_UV_PVSECRETS_NOT_AVAILABLE;
			DEBUG("return %d (%s)", rc, zpc_error_string(rc));
			return rc;
		}
		break;
	default:
		rc = ZPC_ERROR_KEYTYPE;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}

	rv = pthread_mutex_lock(&hmac_key->lock);
	assert(rv == 0);

	if (hmac_key->refcount != 1) {
		rc = ZPC_ERROR_OBJINUSE;
		goto ret;
	}

	DEBUG("hmac key at %p: type set to %d", hmac_key, type);
	hmac_key->type = type;
	hmac_key->type_set = 1;
	rc = 0;
ret:
	rv = pthread_mutex_unlock(&hmac_key->lock);
	assert(rv == 0);
	DEBUG("return %d (%s)", rc, zpc_error_string(rc));
	return rc;
}

int zpc_hmac_key_set_hash_function(struct zpc_hmac_key *hmac_key, zpc_hmac_hashfunc_t hfunc)
{
	int rc, rv;

	UNUSED(rv);

	if (pkeyfd < 0) {
		rc = ZPC_ERROR_DEVPKEY;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}
	if (hmac_key == NULL) {
		rc = ZPC_ERROR_ARG1NULL;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}

	switch (hfunc) {
	case ZPC_HMAC_HASHFUNC_SHA_224:
	case ZPC_HMAC_HASHFUNC_SHA_256:
	case ZPC_HMAC_HASHFUNC_SHA_384:
	case ZPC_HMAC_HASHFUNC_SHA_512:
		break;
	default:
		rc = ZPC_ERROR_HMAC_HASH_FUNCTION_INVALID;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
		break;
	}

	rv = pthread_mutex_lock(&hmac_key->lock);
	assert(rv == 0);

	if (hmac_key->refcount != 1) {
		rc = ZPC_ERROR_OBJINUSE;
		goto ret;
	}

	DEBUG("hmac key at %p: hash function set to %d", hmac_key, hfunc);
	hmac_key->hfunc = hfunc;
	hmac_key->hfunc_set = 1;
	hmac_key->keysize = hfunc2keybitsize[hfunc];
	hmac_key->keysize_set = 1;

	rc = 0;
ret:
	rv = pthread_mutex_unlock(&hmac_key->lock);
	assert(rv == 0);
	DEBUG("return %d (%s)", rc, zpc_error_string(rc));
	return rc;
}

/*
 * Perform a sha2 hash op via CPACF with the given sha2 hash function. The
 * keylen cannot be greater than u64.
 */
static int hash(unsigned char key1[128], const unsigned char *key, size_t keylen,
		zpc_hmac_hashfunc_t hfunc)
{
	struct cpacf_klmd_param param = { 0, };
	size_t bytes_processed;

	switch (hfunc) {
	case ZPC_HMAC_HASHFUNC_SHA_224:
		memcpy(&param.klmd_224_256.h, icv_sha_224, sizeof(icv_sha_224));
		param.klmd_224_256.mbl = keylen * 8;
		break;
	case ZPC_HMAC_HASHFUNC_SHA_256:
		memcpy(&param.klmd_224_256.h, icv_sha_256, sizeof(icv_sha_256));
		param.klmd_224_256.mbl = keylen * 8;
		break;
	case ZPC_HMAC_HASHFUNC_SHA_384:
		memcpy(&param.klmd_384_512.h, icv_sha_384, sizeof(icv_sha_384));
		param.klmd_384_512.mbl = keylen * 8;
		break;
	case ZPC_HMAC_HASHFUNC_SHA_512:
		memcpy(&param.klmd_384_512.h, icv_sha_512, sizeof(icv_sha_512));
		param.klmd_384_512.mbl = keylen * 8;
		break;
	default:
		break;
	}

	bytes_processed = cpacf_klmd(hfunc2klmdfc[hfunc], &param, key, keylen);
	if (bytes_processed != keylen) {
		DEBUG("cpacf_klmd processed %ld of %ld bytes", bytes_processed, keylen);
		return -1;
	}

	switch (hfunc) {
	case ZPC_HMAC_HASHFUNC_SHA_224:
		memcpy(key1, &param.klmd_224_256.h, SHA224_DIGEST_LENGTH);
		break;
	case ZPC_HMAC_HASHFUNC_SHA_256:
		memcpy(key1, &param.klmd_224_256.h, SHA256_DIGEST_LENGTH);
		break;
	case ZPC_HMAC_HASHFUNC_SHA_384:
		memcpy(key1, &param.klmd_384_512.h, SHA384_DIGEST_LENGTH);
		break;
	case ZPC_HMAC_HASHFUNC_SHA_512:
		memcpy(key1, &param.klmd_384_512.h, SHA512_DIGEST_LENGTH);
		break;
	default:
		break;
	}

	return 0;
}

/*
 * The key1 buffer is preset with zeroes and the calling function will use
 * the right number of bytes for further processing.
 * The block-sized key is returned in key1.
 */
static int compute_blocksized_key(unsigned char key1[128], const unsigned char *key,
		size_t keylen, zpc_hmac_hashfunc_t hfunc)
{
	/*
	 * Keys longer than the block size of the hash function are first hashed
	 * and then padded with binary zeros up to the block size of the digest.
	 */
	if (keylen > hfunc2blksize[hfunc]) {
		return hash(key1, key, keylen, hfunc);
	}

	/*
	 * Keys shorter than the block size of the hash function are padded to the
	 * right up to the block size. The block size of SHA-224 and SHA-256 is
	 * 512 bits (64 bytes) and the bock size of SHA-384 and SHA-512 is 1024
	 * bits (128 bytes).
	 * Keys equal to the block size of the hash function are just copied
	 * to output parm key1.
	 */
	memcpy(key1, key, keylen);

	return 0;
}

int zpc_hmac_key_import_clear(struct zpc_hmac_key *hmac_key, const unsigned char *key,
		size_t keylen)
{
	int rc, rv;
	unsigned char key1[128] = { 0, };

	UNUSED(rv);

	if (pkeyfd < 0) {
		rc = ZPC_ERROR_DEVPKEY;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}
	if (hmac_key == NULL) {
		rc = ZPC_ERROR_ARG1NULL;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}
	if (key == NULL) {
		rc = ZPC_ERROR_ARG2NULL;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}
	if (keylen == 0) {
		rc = ZPC_ERROR_KEYSIZE;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}

	rv = pthread_mutex_lock(&hmac_key->lock);
	assert(rv == 0);

	if (hmac_key->refcount != 1) {
		rc = ZPC_ERROR_OBJINUSE;
		goto ret;
	}
	if (hmac_key->type_set && hmac_key->type == ZPC_HMAC_KEY_TYPE_PVSECRET) {
		rc = ZPC_ERROR_KEYTYPE;
		goto ret;
	}
	if (hmac_key->hfunc_set != 1) {
		rc = ZPC_ERROR_HMAC_HASH_FUNCTION_NOTSET;
		goto ret;
	}

	memset(&hmac_key->cur, 0, sizeof(hmac_key->cur)); /* no secret ID avail. */

	rc = compute_blocksized_key(key1, key, keylen, hmac_key->hfunc);
	if (rc != 0) {
		rc = ZPC_ERROR_CREATE_BLOCKSIZED_KEY;
		goto ret;
	}

	rc = hmac_key_clr2prot(hmac_key, key1, hmac_key->keysize / 8);
	if (rc)
		goto ret;

	DEBUG("hmac key at %p: key set", hmac_key);
	hmac_key->key_set = 1;
	hmac_key->rand_protk = 1; /* not possible to re-derive */

	rc = 0;

ret:
	rv = pthread_mutex_unlock(&hmac_key->lock);
	assert(rv == 0);

	DEBUG("return %d (%s)", rc, zpc_error_string(rc));
	return rc;
}

int zpc_hmac_key_export(struct zpc_hmac_key *hmac_key, unsigned char *buf,
		size_t *buflen)
{
	int rc, rv;

	UNUSED(rv);

	if (pkeyfd < 0) {
		rc = ZPC_ERROR_DEVPKEY;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}
	if (hmac_key == NULL) {
		rc = ZPC_ERROR_ARG1NULL;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}
	if (buflen == NULL) {
		rc = ZPC_ERROR_ARG3NULL;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}

	rv = pthread_mutex_lock(&hmac_key->lock);
	assert(rv == 0);

	if (hmac_key->rand_protk) {
		rc = ZPC_ERROR_PROTKEYONLY;
		goto ret;
	}

	rc = hmac_key_check(hmac_key);
	if (rc)
		goto ret;

	if (buf == NULL) {
		*buflen = hmac_key->cur.seclen;
		rc = 0;
		goto ret;
	}

	if (*buflen < hmac_key->cur.seclen) {
		*buflen = hmac_key->cur.seclen;
		rc = ZPC_ERROR_SMALLOUTBUF;
		goto ret;
	}

	*buflen = hmac_key->cur.seclen;
	memcpy(buf, hmac_key->cur.sec, *buflen);
	rc = 0;
ret:
	rv = pthread_mutex_unlock(&hmac_key->lock);
	assert(rv == 0);
	DEBUG("return %d (%s)", rc, zpc_error_string(rc));
	return rc;
}

int zpc_hmac_key_import(struct zpc_hmac_key *hmac_key, const unsigned char *buf,
		size_t buflen)
{
	int rc, rv;

	UNUSED(rv);

	if (pkeyfd < 0) {
		return ZPC_ERROR_DEVPKEY;
	}
	if (hmac_key == NULL) {
		return ZPC_ERROR_ARG1NULL;
	}
	if (buf == NULL) {
		return ZPC_ERROR_ARG2NULL;
	}
	if (buflen != UV_SECRET_ID_LEN) {
		return ZPC_ERROR_ARG3RANGE;
	}

	rv = pthread_mutex_lock(&hmac_key->lock);
	assert(rv == 0);

	if (hmac_key->refcount != 1) {
		rc = ZPC_ERROR_OBJINUSE;
		goto ret;
	}
	if (hmac_key->keysize_set != 1) {
		rc = ZPC_ERROR_KEYSIZENOTSET;
		goto ret;
	}
	if (hmac_key->type_set != 1) {
		rc = ZPC_ERROR_KEYTYPENOTSET;
		goto ret;
	}
	if (hmac_key->type != ZPC_HMAC_KEY_TYPE_PVSECRET) {
		rc = ZPC_ERROR_KEYTYPE;
		goto ret;
	}

	if (hmac_key_blob_is_valid_pvsecret_id(hmac_key, buf) != 0) {
		rc = ZPC_ERROR_PVSECRET_ID_NOT_FOUND_IN_UV;
		goto ret;
	}

	memset(hmac_key->cur.sec, 0, sizeof(hmac_key->cur.sec));
	memcpy(hmac_key->cur.sec, buf, buflen);
	hmac_key->cur.seclen = buflen;
	hmac_key->key_set = 1;

	rc = 0;
ret:
	rv = pthread_mutex_unlock(&hmac_key->lock);
	assert(rv == 0);
	DEBUG("return %d (%s)", rc, zpc_error_string(rc));
	return rc;
}

int zpc_hmac_key_generate(struct zpc_hmac_key *hmac_key)
{
	struct hmac_genprotk genprotk;
	int rc, rv;

	UNUSED(rv);

	if (pkeyfd < 0) {
		rc = ZPC_ERROR_DEVPKEY;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}
	if (hmac_key == NULL) {
		rc = ZPC_ERROR_ARG1NULL;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}

	rv = pthread_mutex_lock(&hmac_key->lock);
	assert(rv == 0);

	if (hmac_key->refcount != 1) {
		rc = ZPC_ERROR_OBJINUSE;
		goto ret;
	}
	if (hmac_key->type_set && hmac_key->type == ZPC_HMAC_KEY_TYPE_PVSECRET) {
		rc = ZPC_ERROR_KEYTYPE;
		goto ret;
	}
	if (hmac_key->hfunc_set != 1) {
		rc = ZPC_ERROR_HMAC_HASH_FUNCTION_NOTSET;
		goto ret;
	}

	/* Generate random protected key only. */
	memset(&genprotk, 0, sizeof(genprotk));

	if (hmac_key->keysize == 512)
		genprotk.keytype = PKEY_KEYTYPE_HMAC_512;
	else
		genprotk.keytype = PKEY_KEYTYPE_HMAC_1024;

	rc = hmac_key_generate(&genprotk);
	if (rc != 0) {
		rc = ZPC_ERROR_HMAC_KEYGEN_VIA_SYSFS;
		goto ret;
	}

	DEBUG("hmac key at %p: key set to generated random protected key", hmac_key);
	memcpy(&hmac_key->prot, &genprotk.protkey, sizeof(hmac_key->prot));
	hmac_key->rand_protk = 1;
	hmac_key->key_set = 1;

	rc = 0;

ret:

	rv = pthread_mutex_unlock(&hmac_key->lock);
	assert(rv == 0);
	DEBUG("return %d (%s)", rc, zpc_error_string(rc));
	return rc;
}

void zpc_hmac_key_free(struct zpc_hmac_key **hmac_key)
{
	int rv, free_obj = 0;

	UNUSED(rv);

	if (hmac_key == NULL)
		return;
	if (*hmac_key == NULL)
		return;

	rv = pthread_mutex_lock(&(*hmac_key)->lock);
	assert(rv == 0);

	if ((*hmac_key)->refcount == 0)
		goto ret;

	(*hmac_key)->refcount--;
	DEBUG("hmac key at %p: refcount %llu", *hmac_key, (*hmac_key)->refcount);

	if ((*hmac_key)->refcount == 0) {
		free_obj = 1;
		__hmac_key_reset(*hmac_key);
	}

ret:
	rv = pthread_mutex_unlock(&(*hmac_key)->lock);
	assert(rv == 0);

	if (free_obj == 1) {
		rv = pthread_mutex_destroy(&(*hmac_key)->lock);
		assert(rv == 0);

		free(*hmac_key);
	}
	*hmac_key = NULL;
	DEBUG("return");
}

/*
 * Reset everything that was set after allocation.
 * Caller must hold hmac_key's wr lock.
 */
static void __hmac_key_reset(struct zpc_hmac_key *hmac_key)
{
	assert(hmac_key != NULL);

	memset(&hmac_key->cur, 0, sizeof(hmac_key->cur));
	memset(&hmac_key->prot, 0, sizeof(hmac_key->prot));
	hmac_key->key_set = 0;
	hmac_key->keysize = 0;
	hmac_key->keysize_set = 0;
	hmac_key->type = 0;
	hmac_key->type_set = 0;
	hmac_key->rand_protk = 0;
	hmac_key->refcount = 1;
}

static u16 hmacprotkeylen_from_pvsectype(u16 pvsectype)
{
	switch (pvsectype) {
	case ZPC_HMAC_SECRET_HMAC_SHA_256:
		return 64 + 32;
	case ZPC_HMAC_SECRET_HMAC_SHA_512:
		return 128 + 32;
	default:
		break;
	}

	return 0;
}

static void hmac_key_make_uvrsecrettoken(struct zpc_hmac_key *hmac_key,
		const unsigned char *id, unsigned char *buf)
{
	struct uvrsecrettoken *clrtok = (struct uvrsecrettoken *)buf;

	clrtok->version = TOKVER_UV_SECRET;
	switch (hmac_key->keysize) {
	case 512:
		clrtok->secret_type = ZPC_HMAC_SECRET_HMAC_SHA_256;
		break;
	default:
		clrtok->secret_type = ZPC_HMAC_SECRET_HMAC_SHA_512;
		break;
	}
	clrtok->secret_len = hmacprotkeylen_from_pvsectype(clrtok->secret_type);
	memcpy(clrtok->secret_id, id, UV_SECRET_ID_LEN);
}

/*
 * Verify that a given pvsecret ID is a valid ID on this system, i.e. an UV
 * secret exists with this ID and has the expected key length.
 */
static int hmac_key_blob_is_valid_pvsecret_id(struct zpc_hmac_key *hmac_key,
		const unsigned char *id)
{
	struct pkey_verifykey2 io;
	unsigned char buf[sizeof(struct uvrsecrettoken)] = { 0, };
	int rc;

	hmac_key_make_uvrsecrettoken(hmac_key, id, buf);

	memset(&io, 0, sizeof(io));
	io.key = buf;
	io.keylen = sizeof(struct uvrsecrettoken);

	errno = 0;
	rc = ioctl(pkeyfd, PKEY_VERIFYKEY2, &io);
	if (rc != 0) {
		DEBUG("hmac key at %p: PKEY_VERIFYKEY2 ioctl failed, errno = %d",
			hmac_key, errno);
		return ZPC_ERROR_IOCTLVERIFYKEY2;
	}

	return 0;
}

#define SYSFS_DIR              "/sys/devices/virtual/misc/pkey/protkey"
#define SYSFS_ATTR_HMAC_512    "protkey_hmac_512"
#define SYSFS_ATTR_HMAC_1024   "protkey_hmac_1024"

/*
 * The sysfs attributes contain key tokens consisting of a 16-byte header,
 * the variable length protected key (64 or 128 bytes), and the 32-byte wkvp.
 */
static int read_sysfs_attr(u32 keytype, u8 *key, int *keylen)
{
	char buffer[300] = { 0, };
	char fn[256];
	int fd, rc;

	switch (keytype) {
	case PKEY_KEYTYPE_HMAC_512:
		sprintf(fn, "%s/%s", SYSFS_DIR, SYSFS_ATTR_HMAC_512);
		break;
	case PKEY_KEYTYPE_HMAC_1024:
		sprintf(fn, "%s/%s", SYSFS_DIR, SYSFS_ATTR_HMAC_1024);
		break;
	default:
		return ZPC_ERROR_KEYTYPE;
		break;
	}

	if ((fd = open(fn, O_RDONLY)) < 0)
		return -1;

	if (read(fd, buffer, sizeof(buffer)) < 0) {
		rc = -1;
		goto ret;
	}

	switch (keytype) {
	case  PKEY_KEYTYPE_HMAC_512:
		memcpy(key, buffer + 16, 64 + 32);
		*keylen = 64 + 32;
		break;
	case  PKEY_KEYTYPE_HMAC_1024:
		memcpy(key, buffer + 16, 128 + 32);
		*keylen = 128 + 32;
		break;
	default:
		break;
	}

	rc = 0;

ret:
	close(fd);

	return rc;
}

/*
 * Generation of random protected keys for key types PKEY_KEYTYPE_HMAC_SHA256
 * and PKEY_KEYTYPE_HMAC_SHA512 is currently not supported via ioctl.
 * But such random keys can be created via sysfs attributes protkey_hmac_512
 * and protkey_hmac_1024 in /sys/devices/virtual/misc/pkey/protkey.
 * Reading an attribute causes a new random key to be generated.
 */
static int hmac_key_generate(struct hmac_genprotk *genprotk)
{
	u8 buf[MAXHMACPROTKEYSIZE];
	int buflen, rc;

	rc = read_sysfs_attr(genprotk->keytype, buf, &buflen);
	if (rc != 0)
		return rc;

	memcpy(&genprotk->protkey.protkey, buf, buflen);

	return 0;
}

/*
 * (Re)derive protected key from a retrievable secret ID.
 * Caller must hold hmac_key's wr lock.
 */
static int hmac_key_pvsec2prot(struct zpc_hmac_key *hmac_key)
{
	struct pkey_kblob2pkey3 io;
	unsigned char buf[sizeof(struct uvrsecrettoken)] = { 0, };
	int rc;

	hmac_key_make_uvrsecrettoken(hmac_key, hmac_key->cur.sec, buf);

	memset(&io, 0, sizeof(io));
	io.key = buf;
	io.keylen = sizeof(struct uvrsecrettoken);
	io.pkeytype = hmac_key->type;
	io.pkeylen = sizeof(hmac_key->prot.protkey);
	io.pkey = (unsigned char *)&hmac_key->prot.protkey;

	errno = 0;
	rc = ioctl(pkeyfd, PKEY_KBLOB2PROTK3, &io);
	if (rc != 0) {
		DEBUG("hmac key at %p: PKEY_KBLOB2PROTK3 ioctl failed, errno = %d",
			hmac_key, errno);
		return ZPC_ERROR_IOCTLBLOB2PROTK3;
	}

	return 0;
}

/*
 * (Re)derive protected key from a secure key or pvsecret ID.
 * Caller must hold hmac_key's wr lock.
 */
int hmac_key_sec2prot(struct zpc_hmac_key *hmac_key)
{
	switch (hmac_key->type) {
	case ZPC_HMAC_KEY_TYPE_PVSECRET:
		return hmac_key_pvsec2prot(hmac_key);
	default:
		break;
	}

	return ZPC_ERROR_KEYTYPE;
}

int hmac_key_clr2prot(struct zpc_hmac_key *hmac_key,
		const unsigned char *key, size_t keylen)
{
	struct pkey_kblob2pkey3 io;
	unsigned char buf[sizeof(struct clearkeytoken) + 128];
	struct clearkeytoken *clrtok = (struct clearkeytoken *)&buf;
	int rc;

	memset(buf, 0, sizeof(buf));
	clrtok->version = 0x02; /* clear key token */
	switch (keylen) {
	case 64:
		clrtok->keytype = PKEY_KEYTYPE_HMAC_512;
		break;
	case 128:
		clrtok->keytype = PKEY_KEYTYPE_HMAC_1024;
		break;
	default:
		return ZPC_ERROR_KEYSIZE;
	}
	memcpy(clrtok->clearkey, key, keylen);
	clrtok->len = keylen;

	memset(&io, 0, sizeof(io));
	io.key = buf;
	io.keylen = sizeof(struct clearkeytoken) + keylen;
	io.pkeylen = sizeof(hmac_key->prot.protkey);
	io.pkey = (unsigned char *)&hmac_key->prot.protkey;

	errno = 0;
	rc = ioctl(pkeyfd, PKEY_KBLOB2PROTK3, &io);
	if (rc != 0) {
		DEBUG("hmac key at %p: PKEY_KBLOB2PROTK3 ioctl failed, errno = %d",
			hmac_key, errno);
		return ZPC_ERROR_IOCTLBLOB2PROTK3;
	}

	if (io.pkeytype != clrtok->keytype) {
		DEBUG("hmac key at %p: PKEY_KBLOB2PROTK3 ioctl returned unexpected "
			"protected key type %d. Expected %d.",
			hmac_key, io.pkeytype, clrtok->keytype);
		return ZPC_ERROR_IOCTLBLOB2PROTK3;
	}

	return 0;
}

int hmac_key_check(const struct zpc_hmac_key *hmac_key)
{
	if (hmac_key->key_set != 1)
		return ZPC_ERROR_KEYNOTSET;
	if (hmac_key->hfunc_set != 1)
		return ZPC_ERROR_HMAC_HASH_FUNCTION_NOTSET;
	/* Random protected keys have no type. */
	if (hmac_key->rand_protk == 0 && hmac_key->type_set != 1)
		return ZPC_ERROR_KEYTYPENOTSET;

	return 0;
}
