#ifndef ECC_KEY_LOCAL_H
# define ECC_KEY_LOCAL_H

/*
 * Copyright IBM Corp. 2022
 *
 * libzpc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

# include "misc.h"
# include "zpc/ecc_key.h"

# include <zkey/pkey.h>
# include <pthread.h>

/*
 * Internal ecc_key interface.
 */

enum ec_key_sec {
	EC_KEY_SEC_CUR = 0,
	EC_KEY_SEC_OLD = 1,
};

struct ec_key {
	u32 seclen;  /* byte-length of secure key blob */
	unsigned char sec[MAX_EC_BLOB_SIZE];
};

struct zpc_ec_key {
	struct ec_key cur;     /* old secure key is needed when */
	struct ec_key old;     /* current is not usable yet */
	struct pkey_ecprotkey prot;     /* EC protected key derived from sec */
	struct pkey_ecpubkey pub;       /* EC public key in clear form */

	int key_set;
	int pubkey_set;

	int curve;
	int curve_set;

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

	unsigned long long refcount;
	pthread_mutex_t lock;
};

int ec_key_clr2sec(struct zpc_ec_key *ec_key, unsigned int flags,
			const unsigned char *pubkey, unsigned int publen,
			const unsigned char *privkey, unsigned int privlen);
int ec_key_sec2prot(struct zpc_ec_key *, enum ec_key_sec sec);
int ec_key_check(const struct zpc_ec_key *);
#endif
