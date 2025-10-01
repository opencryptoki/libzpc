// SPDX-License-Identifier: MIT
// Copyright contributors to the libzpc project
#ifndef _OBJECT_H
#define _OBJECT_H

#include "provider.h"

struct obj {
	/* common */
	unsigned int refcnt;
	struct provider_ctx *pctx;
	char *id;

	struct zpc_aes_key *aes_key;
};

struct obj *obj_new(struct provider_ctx *pctx);
struct obj *obj_get(struct obj *obj);
void obj_free(struct obj *obj);

#endif /* _OBJECT_H */
