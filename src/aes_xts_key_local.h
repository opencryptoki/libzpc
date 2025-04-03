#ifndef AES_XTS_KEY_LOCAL_H
# define AES_XTS_KEY_LOCAL_H

/*
 * Copyright IBM Corp. 2025
 *
 * libzpc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "misc.h"
#include "zpc/aes_xts_key.h"

#include <zkey/pkey.h>
#include <pthread.h>

/*
 * Internal aes_xts_key interface.
 */

struct aes_xts_key {
	unsigned char sec[UV_SECRET_ID_LEN];
	size_t seclen;  /* byte-length of secret ID */
};

struct zpc_aes_xts_key {
	struct aes_xts_key cur; /* current pvsecret ID */
	struct pkey_xts_full_protkey prot;
	int key_set;

	int keysize;
	int keysize_set;

	int type;
	int type_set;

	int rand_protk;

	unsigned long long refcount;
	pthread_mutex_t lock;
};

int aes_xts_key_sec2prot(struct zpc_aes_xts_key *);
int aes_xts_key_check(const struct zpc_aes_xts_key *);
int aes_xts_key_clr2prot(struct zpc_aes_xts_key *, const unsigned char *key,
		unsigned int keylen);

#endif
