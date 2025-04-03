/*
 * Copyright IBM Corp. 2025
 *
 * libzpc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>

#include "zpc/aes_xts_key.h"
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

#include "aes_xts_key_local.h"

static void __aes_xts_key_reset(struct zpc_aes_xts_key *);
static int aes_xts_key_pvsec2prot(struct zpc_aes_xts_key *xts_key);
static int aes_xts_key_blob_is_valid_pvsecret_id(struct zpc_aes_xts_key *xts_key,
		const unsigned char *id);
static int aes_xts_key_generate(struct pkey_genfxtsprotk *genprotk);
static void aes_xts_key_make_uvrsecrettoken(struct zpc_aes_xts_key *xts_key,
		const unsigned char *id, unsigned char *buf);

int zpc_aes_xts_key_alloc(struct zpc_aes_xts_key **xts_key)
{
	pthread_mutexattr_t attr;
	struct zpc_aes_xts_key *new_xts_key = NULL;
	int rc, rv, attr_init = 0;

	UNUSED(rv);

	if (pkeyfd < 0) {
		rc = ZPC_ERROR_DEVPKEY;
		goto ret;
	}
	if (xts_key == NULL) {
		rc = ZPC_ERROR_ARG1NULL;
		goto ret;
	}

	new_xts_key = calloc(1, sizeof(*new_xts_key));
	if (new_xts_key == NULL) {
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
	rc = pthread_mutex_init(&new_xts_key->lock, &attr);
	if (rc) {
		rc = ZPC_ERROR_INITLOCK;
		goto ret;
	}
	new_xts_key->refcount = 1;
	DEBUG("aes-xts key at %p: refcount %llu", new_xts_key, new_xts_key->refcount);

	*xts_key = new_xts_key;
	rc = 0;
ret:
	if (attr_init == 1) {
		rv = pthread_mutexattr_destroy(&attr);
		assert(rv == 0);
	}
	if (rc)
		free(new_xts_key);
	DEBUG("return %d (%s)", rc, zpc_error_string(rc));
	return rc;
}

int zpc_aes_xts_key_set_size(struct zpc_aes_xts_key *xts_key, int keysize)
{
	int rc, rv;

	UNUSED(rv);

	if (pkeyfd < 0) {
		rc = ZPC_ERROR_DEVPKEY;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}
	if (xts_key == NULL) {
		rc = ZPC_ERROR_ARG1NULL;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}

	switch (keysize) {
	case 128:      /* fall-through */
	case 256:
		break;
	default:
		rc = ZPC_ERROR_KEYSIZE;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}

	rv = pthread_mutex_lock(&xts_key->lock);
	assert(rv == 0);

	if (xts_key->refcount != 1) {
		rc = ZPC_ERROR_OBJINUSE;
		goto ret;
	}

	if (xts_key->key_set == 1 && xts_key->keysize != keysize) {
		/* Unset key if it does not match the new keysize. */
		DEBUG("aes-xts key at %p: key unset", xts_key);
		memset(&xts_key->cur, 0, sizeof(xts_key->cur));
		xts_key->key_set = 0;
	}

	DEBUG("aes-xts key at %p: size set to %d", xts_key, keysize);
	xts_key->keysize = keysize;
	xts_key->keysize_set = 1;
	rc = 0;
ret:
	rv = pthread_mutex_unlock(&xts_key->lock);
	assert(rv == 0);
	DEBUG("return %d (%s)", rc, zpc_error_string(rc));
	return rc;
}

int zpc_aes_xts_key_set_type(struct zpc_aes_xts_key *xts_key, int type)
{
	int rc, rv;

	UNUSED(rv);

	if (pkeyfd < 0) {
		rc = ZPC_ERROR_DEVPKEY;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}
	if (xts_key == NULL) {
		rc = ZPC_ERROR_ARG1NULL;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}

	switch (type) {
	case ZPC_AES_XTS_KEY_TYPE_PVSECRET:
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

	rv = pthread_mutex_lock(&xts_key->lock);
	assert(rv == 0);

	if (xts_key->refcount != 1) {
		rc = ZPC_ERROR_OBJINUSE;
		goto ret;
	}

	DEBUG("aes-xts key at %p: type set to %d", xts_key, type);
	xts_key->type = type;
	xts_key->type_set = 1;
	rc = 0;
ret:
	rv = pthread_mutex_unlock(&xts_key->lock);
	assert(rv == 0);
	DEBUG("return %d (%s)", rc, zpc_error_string(rc));
	return rc;
}

int zpc_aes_xts_key_import_clear(struct zpc_aes_xts_key *xts_key,
		const unsigned char *key)
{
	int rc, rv;

	UNUSED(rv);

	if (pkeyfd < 0) {
		rc = ZPC_ERROR_DEVPKEY;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}
	if (xts_key == NULL) {
		rc = ZPC_ERROR_ARG1NULL;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}
	if (key == NULL) {
		rc = ZPC_ERROR_ARG2NULL;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}

	rv = pthread_mutex_lock(&xts_key->lock);
	assert(rv == 0);

	if (xts_key->refcount != 1) {
		rc = ZPC_ERROR_OBJINUSE;
		goto ret;
	}

	if (xts_key->type_set && xts_key->type == ZPC_AES_XTS_KEY_TYPE_PVSECRET) {
		rc = ZPC_ERROR_KEYTYPE;
		goto ret;
	}

	if (xts_key->keysize_set != 1) {
		rc = ZPC_ERROR_KEYSIZENOTSET;
		goto ret;
	}

	memset(&xts_key->cur, 0, sizeof(xts_key->cur));

	rc = aes_xts_key_clr2prot(xts_key, key, (xts_key->keysize / 8) * 2);
	if (rc) {
		goto ret;
	}

	DEBUG("aes-xts key at %p: key set", xts_key);
	xts_key->key_set = 1;
	xts_key->rand_protk = 1;

	rc = 0;

ret:
	rv = pthread_mutex_unlock(&xts_key->lock);
	assert(rv == 0);

	DEBUG("return %d (%s)", rc, zpc_error_string(rc));
	return rc;
}

int zpc_aes_xts_key_export(struct zpc_aes_xts_key *xts_key, unsigned char *buf,
		size_t *buflen)
{
	int rc, rv;

	UNUSED(rv);

	if (pkeyfd < 0) {
		rc = ZPC_ERROR_DEVPKEY;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}
	if (xts_key == NULL) {
		rc = ZPC_ERROR_ARG1NULL;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}
	if (buflen == NULL) {
		rc = ZPC_ERROR_ARG3NULL;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}

	rv = pthread_mutex_lock(&xts_key->lock);
	assert(rv == 0);

	if (xts_key->rand_protk) {
		rc = ZPC_ERROR_PROTKEYONLY;
		goto ret;
	}

	rc = aes_xts_key_check(xts_key);
	if (rc)
		goto ret;

	if (buf == NULL) {
		*buflen = xts_key->cur.seclen;
		rc = 0;
		goto ret;
	}

	if (*buflen < xts_key->cur.seclen) {
		*buflen = xts_key->cur.seclen;
		rc = ZPC_ERROR_SMALLOUTBUF;
		goto ret;
	}

	*buflen = xts_key->cur.seclen;
	memcpy(buf, xts_key->cur.sec, *buflen);
	rc = 0;
ret:
	rv = pthread_mutex_unlock(&xts_key->lock);
	assert(rv == 0);
	DEBUG("return %d (%s)", rc, zpc_error_string(rc));
	return rc;
}

int zpc_aes_xts_key_import(struct zpc_aes_xts_key *xts_key, const unsigned char *buf,
		size_t buflen)
{
	int rc, rv;

	UNUSED(rv);

	if (pkeyfd < 0) {
		return ZPC_ERROR_DEVPKEY;
	}
	if (xts_key == NULL) {
		return ZPC_ERROR_ARG1NULL;
	}
	if (buf == NULL) {
		return ZPC_ERROR_ARG2NULL;
	}
	if (buflen != UV_SECRET_ID_LEN) {
		return ZPC_ERROR_ARG3RANGE;
	}

	rv = pthread_mutex_lock(&xts_key->lock);
	assert(rv == 0);

	if (xts_key->refcount != 1) {
		rc = ZPC_ERROR_OBJINUSE;
		goto ret;
	}
	if (xts_key->keysize_set != 1) {
		rc = ZPC_ERROR_KEYSIZENOTSET;
		goto ret;
	}
	if (xts_key->type_set != 1) {
		rc = ZPC_ERROR_KEYTYPENOTSET;
		goto ret;
	}
	if (xts_key->type != ZPC_AES_XTS_KEY_TYPE_PVSECRET) {
		rc = ZPC_ERROR_KEYTYPE;
		goto ret;
	}

	if (aes_xts_key_blob_is_valid_pvsecret_id(xts_key, buf) != 0) {
		rc = ZPC_ERROR_PVSECRET_ID_NOT_FOUND_IN_UV_OR_INVALID_TYPE;
		goto ret;
	}

	memset(xts_key->cur.sec, 0, sizeof(xts_key->cur.sec));
	memcpy(xts_key->cur.sec, buf, buflen);
	xts_key->cur.seclen = buflen;
	xts_key->key_set = 1;

	rc = 0;
ret:
	rv = pthread_mutex_unlock(&xts_key->lock);
	assert(rv == 0);
	DEBUG("return %d (%s)", rc, zpc_error_string(rc));
	return rc;
}

int zpc_aes_xts_key_generate(struct zpc_aes_xts_key *xts_key)
{
	struct pkey_genfxtsprotk genprotk;
	int rc, rv;

	UNUSED(rv);

	if (pkeyfd < 0) {
		rc = ZPC_ERROR_DEVPKEY;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}
	if (xts_key == NULL) {
		rc = ZPC_ERROR_ARG1NULL;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}

	rv = pthread_mutex_lock(&xts_key->lock);
	assert(rv == 0);

	if (xts_key->refcount != 1) {
		rc = ZPC_ERROR_OBJINUSE;
		goto ret;
	}

	if (xts_key->type_set && xts_key->type == ZPC_AES_XTS_KEY_TYPE_PVSECRET) {
		rc = ZPC_ERROR_KEYTYPE;
		goto ret;
	}

	if (xts_key->keysize_set != 1) {
		rc = ZPC_ERROR_KEYSIZENOTSET;
		goto ret;
	}

	/* Generate random protected key only. */
	memset(&genprotk, 0, sizeof(genprotk));

	if (xts_key->keysize == 128)
		genprotk.keytype = PKEY_KEYTYPE_AES_XTS_128;
	else
		genprotk.keytype = PKEY_KEYTYPE_AES_XTS_256;

	rc = aes_xts_key_generate(&genprotk);
	if (rc != 0) {
		rc = ZPC_ERROR_XTS_KEYGEN_VIA_SYSFS;
		goto ret;
	}

	DEBUG("aes-xts key at %p: key set to generated protected key", xts_key);
	memcpy(&xts_key->prot, &genprotk.protkey, sizeof(xts_key->prot));
	xts_key->rand_protk = 1;
	xts_key->key_set = 1;

	memset(&xts_key->cur, 0, sizeof(xts_key->cur));

	rc = 0;

ret:
	rv = pthread_mutex_unlock(&xts_key->lock);
	assert(rv == 0);
	DEBUG("return %d (%s)", rc, zpc_error_string(rc));
	return rc;
}

void zpc_aes_xts_key_free(struct zpc_aes_xts_key **xts_key)
{
	int rv, free_obj = 0;

	UNUSED(rv);

	if (xts_key == NULL)
		return;
	if (*xts_key == NULL)
		return;

	rv = pthread_mutex_lock(&(*xts_key)->lock);
	assert(rv == 0);

	if ((*xts_key)->refcount == 0)
		goto ret;

	(*xts_key)->refcount--;
	DEBUG("aes-xts key at %p: refcount %llu", *xts_key, (*xts_key)->refcount);

	if ((*xts_key)->refcount == 0) {
		free_obj = 1;
		__aes_xts_key_reset(*xts_key);
	}

ret:
	rv = pthread_mutex_unlock(&(*xts_key)->lock);
	assert(rv == 0);

	if (free_obj == 1) {
		rv = pthread_mutex_destroy(&(*xts_key)->lock);
		assert(rv == 0);

		free(*xts_key);
	}
	*xts_key = NULL;
	DEBUG("return");
}

/*
 * Reset everything that was set after allocation.
 * Caller must hold xts_key's wr lock.
 */
static void __aes_xts_key_reset(struct zpc_aes_xts_key *xts_key)
{

	assert(xts_key != NULL);

	memset(&xts_key->cur, 0, sizeof(xts_key->cur));
	memset(&xts_key->prot, 0, sizeof(xts_key->prot));
	xts_key->key_set = 0;

	xts_key->keysize = 0;
	xts_key->keysize_set = 0;

	xts_key->type = 0;
	xts_key->type_set = 0;

	xts_key->rand_protk = 0;

	xts_key->refcount = 1;
}

#define SYSFS_DIR             "/sys/devices/virtual/misc/pkey/protkey"
#define SYSFS_ATTR_XTS_128    "protkey_aes_xts_128"
#define SYSFS_ATTR_XTS_256    "protkey_aes_xts_256"

/*
 * The sysfs attributes contain key tokens consisting of a 16-byte header,
 * the variable length protected key (32 or 64 bytes), and the 32-byte wkvp.
 */
static int read_sysfs_attr(u32 keytype, u8 *key, int *keylen)
{
	char buffer[300] = { 0, };
	char fn[256];
	int fd, rc;

	switch (keytype) {
	case PKEY_KEYTYPE_AES_XTS_128:
		sprintf(fn, "%s/%s", SYSFS_DIR, SYSFS_ATTR_XTS_128);
		break;
	case PKEY_KEYTYPE_AES_XTS_256:
		sprintf(fn, "%s/%s", SYSFS_DIR, SYSFS_ATTR_XTS_256);
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
	case  PKEY_KEYTYPE_AES_XTS_128:
		memcpy(key, buffer + 16, 32 + 32);
		*keylen = 32 + 32;
		break;
	case  PKEY_KEYTYPE_AES_XTS_256:
		memcpy(key, buffer + 16, 64 + 32);
		*keylen = 64 + 32;
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
 * Generation of random protected keys for key types PKEY_KEYTYPE_AES_XTS_128
 * and PKEY_KEYTYPE_AES_XTS_256 is currently not supported via ioctl.
 * But such random keys can be created via sysfs attributes protkey_aes_xts_128
 * and protkey_aes_xts_256 in /sys/devices/virtual/misc/pkey/protkey.
 * Reading an attribute causes a new random key to be generated.
 */
static int aes_xts_key_generate(struct pkey_genfxtsprotk *genprotk)
{
	u8 buf[MAXXTSFULLPROTKEYSIZE];
	int buflen, rc;

	rc = read_sysfs_attr(genprotk->keytype, buf, &buflen);
	if (rc != 0)
		return rc;

	memcpy(&genprotk->protkey.protkey, buf, buflen);

	return 0;
}

static u16 xtsprotkeylen_from_pvsectype(u16 pvsectype)
{
	switch (pvsectype) {
	case ZPC_XTS_SECRET_AES_XTS_128:
		return 32 + 32;
	case ZPC_XTS_SECRET_AES_XTS_256:
		return 64 + 32;
	default:
		break;
	}

	return 0;
}

void aes_xts_key_make_uvrsecrettoken(struct zpc_aes_xts_key *xts_key,
		const unsigned char *id, unsigned char *buf)
{
	struct uvrsecrettoken *clrtok = (struct uvrsecrettoken *)buf;

	clrtok->version = TOKVER_UV_SECRET;
	switch (xts_key->keysize) {
	case 128:
		clrtok->secret_type = ZPC_XTS_SECRET_AES_XTS_128;
		break;
	default:
		clrtok->secret_type = ZPC_XTS_SECRET_AES_XTS_256;
		break;
	}
	clrtok->secret_len = xtsprotkeylen_from_pvsectype(clrtok->secret_type);
	memcpy(clrtok->secret_id, id, UV_SECRET_ID_LEN);
}

/*
 * Verify that a given pvsecret ID is a valid ID on this system, i.e. an UV
 * secret exists with this ID and has the expected key length.
 */
static int aes_xts_key_blob_is_valid_pvsecret_id(struct zpc_aes_xts_key *xts_key,
		const unsigned char *id)
{
	struct pkey_verifykey2 io;
	unsigned char buf[sizeof(struct uvrsecrettoken)] = { 0, };
	int rc;

	aes_xts_key_make_uvrsecrettoken(xts_key, id, buf);

	memset(&io, 0, sizeof(io));
	io.key = buf;
	io.keylen = sizeof(struct uvrsecrettoken);

	errno = 0;
	rc = ioctl(pkeyfd, PKEY_VERIFYKEY2, &io);
	if (rc != 0) {
		DEBUG("aes-xts key at %p: PKEY_VERIFYKEY2 ioctl failed, errno = %d",
			xts_key, errno);
		return ZPC_ERROR_IOCTLVERIFYKEY2;
	}

	return 0;
}

/*
 * (Re)derive protected key from a retrievable secret ID.
 * Caller must hold xts_key's wr lock.
 */
static int aes_xts_key_pvsec2prot(struct zpc_aes_xts_key *xts_key)
{
	struct pkey_kblob2pkey3 io;
	unsigned char buf[sizeof(struct uvrsecrettoken)] = { 0, };
	int rc;

	aes_xts_key_make_uvrsecrettoken(xts_key, xts_key->cur.sec, buf);

	memset(&io, 0, sizeof(io));
	io.key = buf;
	io.keylen = sizeof(struct uvrsecrettoken);
	io.pkeytype = xts_key->type;
	io.pkeylen = sizeof(xts_key->prot.protkey);
	io.pkey = (unsigned char *)&xts_key->prot.protkey;

	errno = 0;
	rc = ioctl(pkeyfd, PKEY_KBLOB2PROTK3, &io);
	if (rc != 0) {
		DEBUG("aes-xts key at %p: PKEY_KBLOB2PROTK3 ioctl failed, errno = %d",
			xts_key, errno);
		return ZPC_ERROR_IOCTLBLOB2PROTK3;
	}

	return 0;
}

/*
 * (Re)derive protected key from a secure key or pvsecret ID.
 * Caller must hold xts_key's wr lock.
 */
int aes_xts_key_sec2prot(struct zpc_aes_xts_key *xts_key)
{
	switch (xts_key->type) {
	case ZPC_AES_XTS_KEY_TYPE_PVSECRET:
		return aes_xts_key_pvsec2prot(xts_key);
	default:
		break;
	}

	return ZPC_ERROR_KEYTYPE;
}

int aes_xts_key_clr2prot(struct zpc_aes_xts_key *xts_key, const unsigned char *key,
		unsigned int keylen)
{
	struct pkey_kblob2pkey3 io;
	unsigned char buf[sizeof(struct clearkeytoken) + 64];
	struct clearkeytoken *clrtok = (struct clearkeytoken *)&buf;
	int rc;

	memset(buf, 0, sizeof(buf));
	clrtok->version = 0x02;
	switch (keylen) {
	case 32:
		clrtok->keytype = PKEY_KEYTYPE_AES_XTS_128;
		break;
	case 64:
		clrtok->keytype = PKEY_KEYTYPE_AES_XTS_256;
		break;
	default:
		return ZPC_ERROR_KEYSIZE;
	}
	memcpy(clrtok->clearkey, key, keylen);
	clrtok->len = keylen;

	memset(&io, 0, sizeof(io));
	io.key = buf;
	io.keylen = sizeof(struct clearkeytoken) + keylen;
	io.pkeylen = sizeof(xts_key->prot.protkey);
	io.pkey = (unsigned char *)&xts_key->prot.protkey;

	errno = 0;
	rc = ioctl(pkeyfd, PKEY_KBLOB2PROTK3, &io);
	if (rc != 0) {
		DEBUG("aes-xts key at %p: PKEY_KBLOB2PROTK3 ioctl failed, errno = %d",
			xts_key, errno);
		return ZPC_ERROR_IOCTLBLOB2PROTK3;
	}

	if (io.pkeytype != clrtok->keytype) {
		DEBUG("aes-xts key at %p: PKEY_KBLOB2PROTK3 ioctl returned unexpected "
			"protected key type %d. Expected %d.",
			xts_key, io.pkeytype, clrtok->keytype);
		return ZPC_ERROR_IOCTLBLOB2PROTK3;
	}

	return 0;
}

int aes_xts_key_check(const struct zpc_aes_xts_key *xts_key)
{
	if (xts_key->key_set != 1)
		return ZPC_ERROR_KEYNOTSET;
	if (xts_key->keysize_set != 1)
		return ZPC_ERROR_KEYSIZENOTSET;
	/* Random protected keys have no type. */
	if (xts_key->rand_protk == 0 && xts_key->type_set != 1)
		return ZPC_ERROR_KEYTYPENOTSET;

	return 0;
}
