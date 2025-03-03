#ifndef HMAC_KEY_LOCAL_H
# define HMAC_KEY_LOCAL_H

/*
 * Copyright IBM Corp. 2025
 *
 * libzpc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "misc.h"
#include "zpc/hmac_key.h"

#include <zkey/pkey.h>
#include <pthread.h>

/*
 * Internal hmac_key interface.
 */

struct hmac_key {
	unsigned char sec[UV_SECRET_ID_LEN];
	size_t seclen; /* byte-length of secret ID */
};

struct zpc_hmac_key {
	struct hmac_key cur; /* current pvsecret ID */
	struct hmac_protkey prot;
	int key_set;

	int keysize;
	int keysize_set;

	int type;
	int type_set;

	int hfunc;
	int hfunc_set;

	int rand_protk;

	unsigned long long refcount;
	pthread_mutex_t lock;
};

int hmac_key_sec2prot(struct zpc_hmac_key *);
int hmac_key_check(const struct zpc_hmac_key *);
int hmac_key_clr2prot(struct zpc_hmac_key *hmac_key, const unsigned char *key,
		size_t keylen);

#endif
