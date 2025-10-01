// SPDX-License-Identifier: MIT
// Copyright contributors to the libzpc project
#include <openssl/crypto.h>

#include <zpc/aes_key.h>

#include "object.h"

static void _obj_free(struct obj *obj)
{
	zpc_aes_key_free(&obj->aes_key);

	OPENSSL_free(obj->id);
	OPENSSL_free(obj);
}

void obj_free(struct obj *obj)
{
	if (!obj)
		return;

	if (__atomic_sub_fetch(&obj->refcnt, 1, __ATOMIC_SEQ_CST))
		return;

	_obj_free(obj);
}

struct obj *obj_get(struct obj *obj)
{
	if (!obj)
		return NULL;

	__atomic_fetch_add(&obj->refcnt, 1, __ATOMIC_SEQ_CST);
	return obj;
}

struct obj *obj_new(struct provider_ctx *pctx)
{
	struct obj *obj;

	obj = OPENSSL_zalloc(sizeof(struct obj));
	if (!obj)
		return NULL;

	obj->pctx = pctx;

	return obj_get(obj);
}
