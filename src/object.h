// SPDX-License-Identifier: MIT
// Copyright contributors to the libzpc project
#ifndef _OBJECT_H
#define _OBJECT_H

#include <stdbool.h>

#include "provider.h"
#include "zpc/ecc_key.h"

struct data {
	size_t plen;
	unsigned char *p;
};

struct obj {
	/* common */
	unsigned int refcnt;
	struct provider_ctx *pctx;

	/* zpc keys */
	struct zpc_ec_key *ec_key;

	/* origin path attrs */
	char *origin_type;
	char *origin_alg;
	struct data origin_blob;
	struct data origin_pubkey;

	/* origin qeuery attrs */
	char *apqns;
	char *mkvp;

	bool public_only;
};

struct obj *obj_new(struct provider_ctx *pctx);
struct obj *obj_get(struct obj *obj);
struct obj *obj_dup(const struct obj *obj);
void obj_free(struct obj *obj);
bool obj_cmp(const struct obj *obj1, const struct obj *obj2);

#endif /* _OBJECT_H */
