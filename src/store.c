// SPDX-License-Identifier: MIT
// Copyright contributors to the libzpc project
#include <openssl/store.h>
#include <openssl/core_names.h>
#include <openssl/core_object.h>

#include "provider.h"
#include "object.h"
#include "ossl.h"
#include "uri.h"
#include "map.h"
#include "store_local.h"

struct store_ctx {
	struct provider_ctx *pctx;
	struct parsed_uri *puri;

	int type_exp;
	bool eof;
};

#define DISP_STORE_FN(tname, name) DECL_DISPATCH_FUNC(store, tname, name)
DISP_STORE_FN(open, store_open);
#ifdef OSSL_FUNC_STORE_OPEN_EX
DISP_STORE_FN(open_ex, store_open_ex);
#endif
DISP_STORE_FN(load, store_load);
DISP_STORE_FN(eof, store_eof);
DISP_STORE_FN(close, store_close);
DISP_STORE_FN(set_ctx_params, store_set_ctx_params);
DISP_STORE_FN(settable_ctx_params, store_settable_ctx_params);
#undef DISP_STORE_FN

static struct store_ctx *store_ctx_init(struct provider_ctx *pctx)
{
	struct store_ctx *sctx;

	sctx = OPENSSL_zalloc(sizeof(struct store_ctx));
	if (!sctx)
		return NULL;

	sctx->pctx = pctx;
	sctx->eof = false;

	return sctx;
}

static void store_ctx_free(struct store_ctx *sctx)
{
	if (!sctx)
		return;

	parsed_uri_free(sctx->puri);
	OPENSSL_free(sctx);

	return;
}

static int store_ctx_expect(struct store_ctx *sctx, int type_exp)
{
	int rv = OSSL_RV_OK;

	switch (type_exp) {
	case OSSL_STORE_INFO_PUBKEY:
	case OSSL_STORE_INFO_PKEY:
		sctx->type_exp = type_exp;
		break;
	default:
		rv = OSSL_RV_ERR;
		break;
	}

	return rv;
}

static void *store_open(void *vpctx, const char *uri)
{
	struct store_ctx *sctx;

	sctx = store_ctx_init(vpctx);
	if (!sctx)
		return NULL;

	sctx->puri = parsed_uri_new(uri);
	if (!sctx->puri)
		goto err;

	return sctx;
err:
	store_ctx_free(sctx);
	return NULL;
}

#ifdef OSSL_FUNC_STORE_OPEN_EX
static void *store_open_ex(void *vpctx, const char *uri,
			   const OSSL_PARAM params[],
			   OSSL_PASSPHRASE_CALLBACK *pw_cb __unused,
			   void *pw_cbarg __unused)
{
	struct store_ctx *sctx;

	sctx = store_open(vpctx, uri);
	if (!sctx)
		return NULL;

	if (store_set_ctx_params(sctx, params) != OSSL_RV_OK)
		goto err;

	return sctx;
err:
	store_ctx_free(sctx);
	return NULL;

}
#endif

static int attr2str(const struct attr *attr, char **str)
{
	if (!attr->value)
		return OSSL_RV_OK;

	if (*str)
		return OSSL_RV_ERR;

	*str = OPENSSL_strdup(attr->value);
	return (*str) ?  OSSL_RV_OK : OSSL_RV_ERR;
}

static int attr2data(const struct attr *attr, struct data *data)
{
	size_t plen;

	if (!attr || !data)
		return OSSL_RV_ERR;

	/* data already set */
	if (data->p || data->plen)
		return OSSL_RV_ERR;

	if (!attr->value)
		return OSSL_RV_OK;
	plen = strlen(attr->value);

	if (OPENSSL_hexstr2buf_ex(NULL, 0, &plen,
				  attr->value, '\0') != 1)
		return OSSL_RV_ERR;

	data->p = OPENSSL_zalloc(plen);
	if (!data->p)
		return OSSL_RV_ERR;
	data->plen = plen;

	if (OPENSSL_hexstr2buf_ex(data->p, data->plen, &data->plen,
				  attr->value, '\0') != 1) {
		OPENSSL_free(data->p);
		data->p = NULL;
		data->plen = 0;
		return OSSL_RV_ERR;
	}

	return OSSL_RV_OK;
}

static struct obj *uri2obj(struct provider_ctx *pctx, const struct parsed_uri *puri)
{
	struct obj *obj;

	obj = obj_new(pctx);
	if (!obj)
		return NULL;

	if (attr2str(&puri->origin_type, &obj->origin_type) != OSSL_RV_OK)
		goto err;
	if (attr2str(&puri->origin_alg, &obj->origin_alg) != OSSL_RV_OK)
		goto err;
	if (attr2data(&puri->origin_blob, &obj->origin_blob) != OSSL_RV_OK)
		goto err;
	if (attr2data(&puri->origin_pubkey, &obj->origin_pubkey) != OSSL_RV_OK)
		goto err;
	if (attr2str(&puri->mkvp, &obj->mkvp) != OSSL_RV_OK)
		goto err;
	if (attr2str(&puri->apqns, &obj->apqns) != OSSL_RV_OK)
		goto err;

	return obj;
err:
	obj_free(obj);
	return NULL;
}

static int store_load(void *vsctx,
		      OSSL_CALLBACK *object_cb, void *object_cbarg,
		      OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)
{
	struct store_ctx *sctx = (struct store_ctx *)vsctx;
	bool public_only = false;
	struct parsed_uri *puri;
	int object_type;

	if (!sctx)
		return OSSL_RV_ERR;
	puri = sctx->puri;
	sctx->eof = true;

	object_type = alg2object_type(puri->origin_alg.value);
	if (object_type == OSSL_OBJECT_UNKNOWN)
		return OSSL_RV_ERR;

	/* early checks */
	switch (sctx->type_exp) {
	case OSSL_STORE_INFO_PKEY:
		if (object_type != OSSL_OBJECT_PKEY)
			return OSSL_RV_ERR;
		break;
	case OSSL_STORE_INFO_PUBKEY:
		if (object_type != OSSL_OBJECT_PKEY)
			return OSSL_RV_ERR;
		public_only = true;
		break;
	case 0:
		/* no expected type */
		break;
	default:
		return OSSL_RV_ERR;
	}

	return store_load_uri(sctx->pctx, puri, public_only,
			      object_cb, object_cbarg, pw_cb, pw_cbarg);
}

static int store_eof(void *vsctx)
{
	struct store_ctx *sctx = (struct store_ctx *)vsctx;

	if (!sctx)
		return OSSL_RV_TRUE;

	return sctx->eof ? OSSL_RV_TRUE : OSSL_RV_FALSE;
}

static int store_close(void *vsctx)
{
	store_ctx_free((struct store_ctx *)vsctx);
	return OSSL_RV_OK;
}

static int store_set_ctx_params(void *vsctx, const OSSL_PARAM params[])
{
	struct store_ctx *sctx = (struct store_ctx *)vsctx;
	const OSSL_PARAM *p;
	int type_exp;

	if (!sctx)
		return OSSL_RV_ERR;

	if (!params)
		return OSSL_RV_OK;

	p = OSSL_PARAM_locate_const(params, OSSL_STORE_PARAM_EXPECT);
	if (p) {
		if ((OSSL_PARAM_get_int(p, &type_exp) != OSSL_RV_OK) ||
		    (store_ctx_expect(sctx, type_exp) != OSSL_RV_OK))
			return OSSL_RV_ERR;
	}

	return OSSL_RV_OK;
}

static const OSSL_PARAM *store_settable_ctx_params(void *pctx __unused)
{
	static const OSSL_PARAM known_settable_ctx_params[] = {
		OSSL_PARAM_int(OSSL_STORE_PARAM_EXPECT, NULL),
		OSSL_PARAM_END,
	};
	return known_settable_ctx_params;
}

int store_load_uri(struct provider_ctx *pctx, struct parsed_uri *puri,
		   bool public_only,
		   OSSL_CALLBACK *object_cb, void *object_cbarg,
		   OSSL_PASSPHRASE_CALLBACK *pw_cb __unused,
		   void *pw_cbarg __unused)
{
	OSSL_PARAM params[4];
	struct obj *obj;
	char *data_type;
	int object_type;
	int rv;

	if (!pctx || !puri)
		return OSSL_RV_ERR;

	object_type = alg2object_type(puri->origin_alg.value);
	if (object_type == OSSL_OBJECT_UNKNOWN)
		return OSSL_RV_ERR;

	data_type = alg2data_type(puri->origin_alg.value);
	if (!data_type)
		return OSSL_RV_ERR;

	obj = uri2obj(pctx, puri);
	if (!obj)
		return OSSL_RV_ERR;
	obj->public_only = public_only;

	params[0] = OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE,
					     &object_type);
	params[1] = OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_TYPE,
						     data_type, 0);
	params[2] = OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_REFERENCE,
						      obj, sizeof(struct obj));
	params[3] = OSSL_PARAM_construct_end();

	rv = object_cb(params, object_cbarg);
	obj_free(obj);
	return rv;
}

static const OSSL_DISPATCH store_functions[] = {
	DISPATCH_DEFN(STORE, OPEN, store_open),
#ifdef OSSL_FUNC_STORE_OPEN_EX
	DISPATCH_DEFN(STORE, OPEN_EX, store_open_ex),
#endif
	DISPATCH_DEFN(STORE, LOAD, store_load),
	DISPATCH_DEFN(STORE, EOF, store_eof),
	DISPATCH_DEFN(STORE, CLOSE, store_close),
	DISPATCH_DEFN(STORE, SET_CTX_PARAMS, store_set_ctx_params),
	DISPATCH_DEFN(STORE, SETTABLE_CTX_PARAMS, store_settable_ctx_params),
	DISPATCH_END
};

const OSSL_ALGORITHM store_ops[] = {
	{ URI_PROTOCOL_PREFIX, "provider=" PROV_NAME, store_functions, "HBKZPC URI Store" },
	{ NULL, NULL, NULL, NULL },
};
