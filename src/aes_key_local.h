#ifndef AES_KEY_LOCAL_H
# define AES_KEY_LOCAL_H

/*
 * Copyright IBM Corp. 2021
 *
 * libzpc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

# include "misc.h"
# include "zpc/aes_key.h"

# include <zkey/pkey.h>
# include <pthread.h>

/*
 * Internal aes_key interface.
 */

/* Maximum size of secure key blob. */
# define MAX_AESKEYBLOBSIZE	512

enum aes_key_sec {
	AES_KEY_SEC_CUR = 0,
	AES_KEY_SEC_OLD = 1,
};

struct aes_key {
	unsigned char sec[MAX_AESKEYBLOBSIZE];
	size_t seclen;  /* byte-length of secure key blob */
};

struct zpc_aes_key {
	struct aes_key cur;     /* old secure key is needed when */
	struct aes_key old;     /* current is not usable yet */
	struct pkey_protkey prot;       /* protected key derived from sec */
	int key_set;

	int keysize;
	int keysize_set;

	unsigned int flags;
	int flags_set;

	int type;
	int type_set;

	u8 mkvp[MAX_MKVPLEN];
	size_t mkvplen; /* byte-length of mkvp */
	int mkvp_set;

	struct pkey_apqn *apqns;
	size_t napqns;  /* elements in apqns */
	int apqns_set;

	int rand_protk;

	unsigned long long refcount;
	pthread_mutex_t lock;
};

int aes_key_sec2prot(struct zpc_aes_key *, enum aes_key_sec sec);
int aes_key_check(const struct zpc_aes_key *);

#endif
