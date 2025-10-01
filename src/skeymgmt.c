// SPDX-License-Identifier: MIT
// Copyright contributors to the libzpc project
#include <string.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>

#include <zpc/aes_key.h>
#include <zkey/pkey.h>

#include "provider.h"
#include "object.h"
#include "ossl.h"

#include "zpc_params.h"

struct tokhdr {
	u8  type;
	u8  res0[3];
	u8  version;
	u8  res1[3];
};

#define DECL_SKEYMGMT_FUNC(name) \
	static OSSL_FUNC_skeymgmt_##name##_fn aes_##name
DECL_SKEYMGMT_FUNC(free);
DECL_SKEYMGMT_FUNC(import);
DECL_SKEYMGMT_FUNC(export);
DECL_SKEYMGMT_FUNC(get_key_id);
DECL_SKEYMGMT_FUNC(imp_settable_params);
#undef DECL_SKEYMGMT_FUNC

static void aes_free(void *vpkey)
{
	struct obj *obj = vpkey;

	zpc_aes_key_free(&obj->aes_key);
	obj_free(obj);
}

static void *aes_import_uv(struct provider_ctx *pctx, const OSSL_PARAM params[])
{
	struct zpc_aes_key *aes_key;
	size_t secretidlen, keylen;
	const void *secretid;
	const OSSL_PARAM *p;
	const char *alg;
	struct obj *obj;

	p = OSSL_PARAM_locate_const(params, ZPC_PARAM_ORIGIN_ALG);
	if (!p)
		return NULL;

	if (OSSL_PARAM_get_utf8_string_ptr(p, &alg) != OSSL_RV_OK)
		return NULL;

	p = OSSL_PARAM_locate_const(params, ZPC_PARAM_UVSECRET_ID);
	if (!p)
		return NULL;

	if (OSSL_PARAM_get_octet_string_ptr(p, &secretid, &secretidlen) != OSSL_RV_OK)
		return NULL;

	if (strcmp(alg, "aes-128") == 0) {
		keylen = 128;
	} else if (strcmp(alg, "aes-192") == 0) {
		keylen = 192;
	} else if (strcmp(alg, "aes-256") == 0) {
		keylen = 256;
	} else {
		return NULL;
	}

	obj = obj_new(pctx);
	if (!obj)
		return NULL;

	if (zpc_aes_key_alloc(&aes_key))
		goto err;

	if (zpc_aes_key_set_type(aes_key, ZPC_AES_KEY_TYPE_PVSECRET))
		goto err;

	if (zpc_aes_key_set_size(aes_key, keylen))
		goto err;

	if (zpc_aes_key_import(aes_key, secretid, secretidlen))
		goto err;

	obj->aes_key = aes_key;
	obj->id = OPENSSL_buf2hexstr(secretid, secretidlen);

	return obj;
err:
	zpc_aes_key_free(&aes_key);
	obj_free(obj);
	return NULL;
}

static void *aes_import(void *vpctx,
			int selection __unused,
			const OSSL_PARAM params[])
{
	struct provider_ctx *pctx = vpctx;
	const OSSL_PARAM *p;
	const char *type;

	if (!pctx)
		return NULL;

	p = OSSL_PARAM_locate_const(params, ZPC_PARAM_ORIGIN_TYPE);
	if (!p)
		return NULL;

	if (OSSL_PARAM_get_utf8_string_ptr(p, &type) != OSSL_RV_OK)
		return NULL;

	if (strcmp(type, "uv") == 0)
		return aes_import_uv(pctx, params);

	/* only uv retrievable secrets are supported at the moment */
	return NULL;
}

static int aes_export(void *vpkey __unused,
		      int selection __unused,
		      OSSL_CALLBACK *param_cb __unused,
		      void *cbarg __unused)
{
	/* secret key export is not yet supported */
	return OSSL_RV_ERR;
}

static const char *aes_get_key_id(void *vpkey)
{
	struct obj *obj = vpkey;

	if (!obj)
		return NULL;

	return obj->id;
}

static const OSSL_PARAM aes_import_params[] = {
	OSSL_PARAM_octet_string(OSSL_SKEY_PARAM_RAW_BYTES, NULL, 0),
	OSSL_PARAM_utf8_string(ZPC_PARAM_ORIGIN_ALG, NULL, 0),
	OSSL_PARAM_utf8_string(ZPC_PARAM_ORIGIN_TYPE, NULL, 0),
	OSSL_PARAM_octet_string(ZPC_PARAM_UVSECRET_ID, NULL, 0),
	OSSL_PARAM_END
};

static const OSSL_PARAM *aes_imp_settable_params(void *vpctx __unused)
{
    return aes_import_params;
}

static const OSSL_DISPATCH skeymgmt_aes_functions[] = {
	DISPATCH_DEFN(SKEYMGMT, FREE, aes_free),
	DISPATCH_DEFN(SKEYMGMT, IMPORT, aes_import),
	DISPATCH_DEFN(SKEYMGMT, EXPORT, aes_export),
	DISPATCH_DEFN(SKEYMGMT, GET_KEY_ID, aes_get_key_id),
	DISPATCH_DEFN(SKEYMGMT, IMP_SETTABLE_PARAMS, aes_imp_settable_params),
	DISPATCH_END,
};

const OSSL_ALGORITHM skeymgmt_ops[] = {
	ALGORITHM_DEFN("AES", PROV_PROP, skeymgmt_aes_functions, NULL),
	ALGORITHM_END,
};
