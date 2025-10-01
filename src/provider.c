// SPDX-License-Identifier: MIT
// Copyright contributors to the libzpc project
#include <string.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>

#include "ossl.h"
#include "provider.h"

static const OSSL_ITEM reason_strings[] = {
	{ 0, NULL },
};

static const OSSL_PARAM prov_param_types[] = {
	OSSL_PARAM_DEFN(OSSL_PROV_PARAM_NAME, OSSL_PARAM_UTF8_PTR, NULL, 0),
	OSSL_PARAM_DEFN(OSSL_PROV_PARAM_VERSION, OSSL_PARAM_UTF8_PTR, NULL, 0),
	OSSL_PARAM_DEFN(OSSL_PROV_PARAM_BUILDINFO, OSSL_PARAM_UTF8_PTR, NULL, 0),
	OSSL_PARAM_DEFN(OSSL_PROV_PARAM_STATUS, OSSL_PARAM_INTEGER, NULL, 0),
	OSSL_PARAM_END,
};

static int prov_ctx_init(struct provider_ctx *pctx, const OSSL_CORE_HANDLE *handle,
			 const OSSL_DISPATCH *in)
{
	OSSL_LIB_CTX *libctx;

	if (!pctx)
		return OSSL_RV_ERR;

	libctx = OSSL_LIB_CTX_new_from_dispatch(handle, in);
	if (!libctx)
		return OSSL_RV_ERR;

	pctx->libctx = libctx;
	pctx->handle = handle;
	pctx->state = PROVIDER_INITIALIZED;

	return OSSL_RV_OK;
}

static void prov_teardown(void *vpctx)
{
	OPENSSL_free(vpctx);
}

static const OSSL_PARAM *prov_gettable_params(void *vpctx __unused)
{
	return prov_param_types;
}

static int prov_get_params(void *vpctx, OSSL_PARAM params[])
{
	struct provider_ctx *pctx = vpctx;
	OSSL_PARAM *p;

	if (!pctx)
		return OSSL_RV_ERR;

	p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
	if (p && (OSSL_PARAM_set_utf8_ptr(p, PROV_NAME) != OSSL_RV_OK))
		return OSSL_RV_ERR;

	p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
	if (p && (OSSL_PARAM_set_utf8_ptr(p, PROV_VERSION) != OSSL_RV_OK))
		return OSSL_RV_ERR;

	p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_BUILDINFO);
	if (p && (OSSL_PARAM_set_utf8_ptr(p, PROV_VERSION) != OSSL_RV_OK))
		return OSSL_RV_ERR;

	p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_STATUS);
	if (p && (OSSL_PARAM_set_int(p, pctx->state) != OSSL_RV_OK))
		return OSSL_RV_ERR;

	return OSSL_RV_OK;
}

static const OSSL_ALGORITHM *prov_query_operation(void *vpctx, int operation_id, int *no_cache)
{
	struct provider_ctx *pctx = vpctx;
	const OSSL_ALGORITHM *ops;

	if (!pctx || pctx->state == PROVIDER_UNINITIALIZED)
		return NULL;

	switch (operation_id) {
	default:
		ops = NULL;
		break;
	}

	*no_cache = 1;
	return ops;
}

static const OSSL_ITEM *prov_get_reason_strings(void *vpctx __unused)
{
	return reason_strings;
}

static const OSSL_DISPATCH provider_dispatch_table[] = {
#define FUNC(func)	(void (*)(void))(func)
	{ OSSL_FUNC_PROVIDER_TEARDOWN, FUNC(prov_teardown) },
	{ OSSL_FUNC_PROVIDER_GETTABLE_PARAMS, FUNC(prov_gettable_params) },
	{ OSSL_FUNC_PROVIDER_GET_PARAMS, FUNC(prov_get_params) },
	{ OSSL_FUNC_PROVIDER_QUERY_OPERATION, FUNC(prov_query_operation) },
	{ OSSL_FUNC_PROVIDER_GET_REASON_STRINGS, FUNC(prov_get_reason_strings) },
	{ 0, NULL }
#undef FUNC
};

static int prov_init(const OSSL_CORE_HANDLE *handle,
		     const OSSL_DISPATCH *in,
		     const OSSL_DISPATCH **out,
		     void **vpctx)
{
	struct provider_ctx *pctx;
	int rv = OSSL_RV_ERR;

	if (!handle || !in || !out || !vpctx)
		return OSSL_RV_ERR;

	pctx = OPENSSL_zalloc(sizeof(*pctx));
	if (!pctx)
		return OSSL_RV_ERR;

	if (!prov_ctx_init(pctx, handle, in))
		goto err;

	*vpctx = pctx;
	*out = provider_dispatch_table;
	return OSSL_RV_OK;

err:
	OPENSSL_free(pctx);
	return rv;
}

int OSSL_provider_init(const OSSL_CORE_HANDLE *handle,
		       const OSSL_DISPATCH *in,
		       const OSSL_DISPATCH **out,
		       void **provctx)
{
	return prov_init(handle, in, out, provctx);
}
