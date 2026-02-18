// SPDX-License-Identifier: MIT
// Copyright contributors to the libzpc project
#include <string.h>
#include <openssl/crypto.h>

#include "object.h"
#include "zpc/ecc_key.h"

static void _obj_free(struct obj *obj)
{
	zpc_ec_key_free(&obj->ec_key);

	OPENSSL_free(obj->origin_type);
	OPENSSL_free(obj->origin_alg);
	OPENSSL_free(obj->origin_blob.p);
	OPENSSL_free(obj->origin_pubkey.p);
	OPENSSL_free(obj->apqns);
	OPENSSL_free(obj->mkvp);

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

struct obj *obj_dup(const struct obj *osrc)
{
	struct obj *odst;

	if (!osrc ||
	    !(odst = obj_new(osrc->pctx)))
		return NULL;

	if (osrc->origin_type &&
	    !(odst->origin_type = OPENSSL_strdup(osrc->origin_type)))
		goto err;

	if (osrc->origin_alg &&
	    !(odst->origin_alg = OPENSSL_strdup(osrc->origin_alg)))
		goto err;

	if (osrc->apqns &&
	    !(odst->apqns = OPENSSL_strdup(osrc->apqns)))
		goto err;

	if (osrc->mkvp &&
	    !(odst->mkvp = OPENSSL_strdup(osrc->mkvp)))
		goto err;

	if (osrc->origin_blob.p &&
	    !(odst->origin_blob.p = OPENSSL_memdup(osrc->origin_blob.p,
						   osrc->origin_blob.plen)))
		goto err;
	odst->origin_blob.plen = osrc->origin_blob.plen;

	if (osrc->origin_pubkey.p &&
	    !(odst->origin_pubkey.p = OPENSSL_memdup(osrc->origin_pubkey.p,
						     osrc->origin_pubkey.plen)))
		goto err;
	odst->origin_pubkey.plen = osrc->origin_pubkey.plen;

	return odst;
err:
	obj_free(odst);
	return NULL;
}

bool obj_cmp(const struct obj *obj1, const struct obj *obj2)
{
	if ((!!obj1 != !!obj2) ||
	    (OPENSSL_strcasecmp(obj1->origin_alg, obj2->origin_alg) != 0))
		return false;

	if ((!!obj1->origin_pubkey.p == !!obj2->origin_pubkey.p) &&
	    (obj1->origin_pubkey.plen == obj2->origin_pubkey.plen))
		return (memcmp(obj1->origin_blob.p,
			       obj2->origin_blob.p,
			       obj1->origin_blob.plen) == 0)
			? true
			: false;

	return false;
}
