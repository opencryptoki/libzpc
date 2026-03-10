// SPDX-License-Identifier: MIT
// Copyright contributors to the libzpc project
#include <string.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/params.h>

#include <zpc/error.h>
#include <zpc/init.h>

#include "ossl.h"
#include "provider.h"
#include "store.h"
#include "keymgmt.h"
#include "signature.h"
#include "tls.h"

#define C(str)	(void *)(str)
static const OSSL_ITEM reason_strings[] = {
	{ ZPC_ERROR_ARG1NULL,
		C("argument 1 NULL") },
	{ ZPC_ERROR_ARG2NULL,
		C("argument 2 NULL") },
	{ ZPC_ERROR_ARG3NULL,
		C("argument 3 NULL") },
	{ ZPC_ERROR_ARG4NULL,
		C("argument 4 NULL") },
	{ ZPC_ERROR_ARG5NULL,
		C("argument 5 NULL") },
	{ ZPC_ERROR_ARG6NULL,
		C("argument 6 NULL") },
	{ ZPC_ERROR_ARG7NULL,
		C("argument 7 NULL") },
	{ ZPC_ERROR_ARG8NULL,
		C("argument 8 NULL") },
	{ ZPC_ERROR_ARG1RANGE,
		C("argument 1 out of range") },
	{ ZPC_ERROR_ARG2RANGE,
		C("argument 2 out of range") },
	{ ZPC_ERROR_ARG3RANGE,
		C("argument 3 out of range") },
	{ ZPC_ERROR_ARG4RANGE,
		C("argument 4 out of range") },
	{ ZPC_ERROR_ARG5RANGE,
		C("argument 5 out of range") },
	{ ZPC_ERROR_ARG6RANGE,
		C("argument 6 out of range") },
	{ ZPC_ERROR_ARG7RANGE,
		C("argument 7 out of range") },
	{ ZPC_ERROR_ARG8RANGE,
		C("argument 8 out of range") },
	{ ZPC_ERROR_MALLOC,
		C("malloc failed") },
	{ ZPC_ERROR_KEYNOTSET,
		C("no key is set") },
	{ ZPC_ERROR_KEYSIZE,
		C("invalid key size") },
	{ ZPC_ERROR_IVNOTSET,
		C("IV not set") },
	{ ZPC_ERROR_IVSIZE,
		C("invalid IV size") },
	{ ZPC_ERROR_TAGSIZE,
		C("invalid tag size") },
	{ ZPC_ERROR_TAGMISMATCH,
		C("tag mismatch") },
	{ ZPC_ERROR_HWCAPS,
		C("function not supported") },
	{ ZPC_ERROR_SMALLOUTBUF,
		C("output buffer too small") },
	{ ZPC_ERROR_APQNSNOTSET,
		C("APQNs not set") },
	{ ZPC_ERROR_KEYTYPE,
		C("invalid key type") },
	{ ZPC_ERROR_KEYTYPENOTSET,
		C("key type not set") },
	{ ZPC_ERROR_IOCTLGENSECK2,
		C("PKEY_GENSECK2 ioctl failed") },
	{ ZPC_ERROR_IOCTLCLR2SECK2,
		C("PKEY_CLR2SECK2 ioctl failed") },
	{ ZPC_ERROR_IOCTLBLOB2PROTK2,
		C("PKEY_BLOB2PROTK2 ioctl failed") },
	{ ZPC_ERROR_WKVPMISMATCH,
		C("wrapping key verification pattern mismatch") },
	{ ZPC_ERROR_DEVPKEY,
		C("opening /dev/pkey failed") },
	{ ZPC_ERROR_CLEN,
		C("ciphertext too long") },
	{ ZPC_ERROR_MLEN,
		C("message too long") },
	{ ZPC_ERROR_AADLEN,
		C("additional authenticated data too long") },
	{ ZPC_ERROR_PARSE,
		C("parse error") },
	{ ZPC_ERROR_APQNNOTFOUND,
		C("APQN not found in APQN list") },
	{ ZPC_ERROR_MKVPLEN,
		C("MKVP too long") },
	{ ZPC_ERROR_INITLOCK,
		C("initializing a lock failed") },
	{ ZPC_ERROR_OBJINUSE,
		C("object is in use") },
	{ ZPC_ERROR_IOCTLAPQNS4KT,
		C("PKEY_APQNS4KT ioctl failed") },
	{ ZPC_ERROR_KEYSIZENOTSET,
		C("key-size not set") },
	{ ZPC_ERROR_IOCTLGENPROTK,
		C("PKEY_GENPROTK ioctl failed") },
	{ ZPC_ERROR_PROTKEYONLY,
		C("protected-key only") },
	{ ZPC_ERROR_KEYSEQUAL,
		C("keys are equal") },
	{ ZPC_ERROR_NOTSUP,
		C("not supported") },
	{ ZPC_ERROR_EC_INVALID_CURVE,
		C("Invalid EC curve") },
	{ ZPC_ERROR_EC_CURVE_NOTSET,
		C("EC curve not set") },
	{ ZPC_ERROR_EC_PRIVKEY_NOTSET,
		C("EC private key not set") },
	{ ZPC_ERROR_EC_PUBKEY_NOTSET,
		C("EC public key not set") },
	{ ZPC_ERROR_EC_NO_KEY_PARTS,
		C("No EC key parts given") },
	{ ZPC_ERROR_EC_SIGNATURE_INVALID,
		C("signature invalid") },
	{ ZPC_ERROR_IOCTLBLOB2PROTK3,
		C("PKEY_BLOB2PROTK3 ioctl failed") },
	{ ZPC_ERROR_IOCTLCLR2SECK3,
		C("PKEY_CLR2SECK3 ioctl failed") },
	{ ZPC_ERROR_APQNS_NOTSET,
		C("No APQNs set for this key, but required for this operation") },
	{ ZPC_ERROR_EC_SIGNATURE_LENGTH,
		C("Signature length is invalid for this EC key") },
	{ ZPC_ERROR_EC_KEY_PARTS_INCONSISTENT,
		C("Given public/private key parts are inconsistent") },
	{ ZPC_ERROR_CCA_HOST_LIB_NOT_AVAILABLE,
		C("CCA host library not available, but required for this operation") },
	{ ZPC_ERROR_EP11_HOST_LIB_NOT_AVAILABLE,
		C("EP11 host library not available, but required for this operation") },
	{ ZPC_ERROR_EC_PUBKEY_LENGTH,
		C("The given EC public key length is invalid") },
	{ ZPC_ERROR_EC_PRIVKEY_LENGTH,
		C("The given EC private key length is invalid") },
	{ ZPC_ERROR_EC_NO_CCA_SECUREKEY_TOKEN,
		C("The given buffer does not contain a valid CCA secure key token") },
	{ ZPC_ERROR_EC_NO_EP11_SECUREKEY_TOKEN,
		C("The given buffer does not contain a valid EP11 secure key token") },
	{ ZPC_ERROR_EC_EP11_SPKI_INVALID_LENGTH,
		C("The imported buffer contains an EP11 SPKI with an invalid length") },
	{ ZPC_ERROR_EC_EP11_SPKI_INVALID_CURVE,
		C("The imported buffer contains an EP11 SPKI with an invalid EC curve") },
	{ ZPC_ERROR_EC_EP11_SPKI_INVALID_PUBKEY,
		C("The imported buffer contains an EP11 SPKI with an invalid public key") },
	{ ZPC_ERROR_EC_EP11_SPKI_INVALID_MKVP,
		C("The imported buffer contains an EP11 MACed SPKI with an invalid MKVP") },
	{ ZPC_ERROR_BLOB_NOT_PKEY_EXTRACTABLE,
		C("The imported buffer contains a key blob that cannot be transformed into a protected key.") },
	{ ZPC_ERROR_APQNS_INVALID_VERSION,
		C("At least one APQN version is invalid for this function.") },
	{ ZPC_ERROR_AES_NO_EP11_SECUREKEY_TOKEN,
		C("The given buffer does not contain a valid EP11 AES secure key token.") },
	{ ZPC_ERROR_AES_NO_CCA_DATAKEY_TOKEN,
		C("The given buffer does not contain a valid CCA datakey token") },
	{ ZPC_ERROR_AES_NO_CCA_CIPHERKEY_TOKEN,
		C("The given buffer does not contain a valid CCA cipherkey token") },
	{ ZPC_ERROR_RNDGEN,
		C("Error creating random bytes") },
	{ ZPC_ERROR_GCM_IV_CREATED_INTERNALLY,
		C("Invalid usage of a gcm context with an internally created iv") },
	{ ZPC_ERROR_UV_PVSECRETS_NOT_AVAILABLE,
		C("Support for UV retrievable secrets is not available, but required for this function.") },
	{ ZPC_ERROR_PVSECRET_TYPE_NOT_SUPPORTED,
		C("The given pvsecret type is not supported by libzpc.") },
	{ ZPC_ERROR_PVSECRET_ID_NOT_FOUND_IN_UV_OR_INVALID_TYPE,
		C("The given pvsecret ID does either not exist or belongs to a different secret type.") },
	{ ZPC_ERROR_IOCTLVERIFYKEY2,
		C("PKEY_VERIFYKEY2 ioctl failed.") },
	{ ZPC_ERROR_HMAC_HASH_FUNCTION_NOTSET,
		C("HMAC hash function not set.") },
	{ ZPC_ERROR_HMAC_HASH_FUNCTION_INVALID,
		C("HMAC hash function invalid.") },
	{ ZPC_ERROR_HMAC_KEYGEN_VIA_SYSFS,
		C("HMAC key generation via sysfs attributes failed.") },
	{ ZPC_ERROR_CREATE_BLOCKSIZED_KEY,
		C("Creating a block-sized HMAC key failed.") },
	{ ZPC_ERROR_XTS_KEYGEN_VIA_SYSFS,
		C("Creating a full-xts key via sysfs attributes failed") },
	{ ZPC_ERROR_EC_KEY_MISMATCH,
		C("EC key compare mismatch") },
	{ 0, NULL },
};
#undef C

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
	const OSSL_DISPATCH *iter_in;
	OSSL_LIB_CTX *libctx;

	if (!pctx)
		return OSSL_RV_ERR;

	libctx = OSSL_LIB_CTX_new_from_dispatch(handle, in);
	if (!libctx)
		return OSSL_RV_ERR;

	pctx->libctx = libctx;
	pctx->handle = handle;
	pctx->state = PROVIDER_INITIALIZED;

	for (iter_in = in; iter_in->function_id != 0; iter_in++) {
		switch (iter_in->function_id) {
		case OSSL_FUNC_CORE_NEW_ERROR:
			pctx->core_new_error = OSSL_FUNC_core_new_error(iter_in);
			break;
		case OSSL_FUNC_CORE_SET_ERROR_DEBUG:
			pctx->core_set_error_debug = OSSL_FUNC_core_set_error_debug(iter_in);
			break;
		case OSSL_FUNC_CORE_VSET_ERROR:
			pctx->core_vset_error = OSSL_FUNC_core_vset_error(iter_in);
			break;
		default:
			continue;
		}
	}
	return OSSL_RV_OK;
}

static void prov_teardown(void *vpctx)
{
	struct provider_ctx *pctx = (struct provider_ctx *)vpctx;

	if (pctx)
		OSSL_LIB_CTX_free(pctx->libctx);
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
	case OSSL_OP_STORE:
		ops = store_ops;
		break;
	case OSSL_OP_KEYMGMT:
		ops = keymgmt_ops;
		break;
	case OSSL_OP_SIGNATURE:
		ops = signature_ops;
		break;
	default:
		ops = NULL;
		goto out;
	}

	if (no_cache)
		*no_cache = OSSL_RV_FALSE;
out:
	return ops;
}

static int prov_get_capabilities(void *vpctx __unused, const char *capability,
				 OSSL_CALLBACK *cb, void *arg)
{
	int rv = OSSL_RV_OK;

	if (OPENSSL_strcasecmp(capability, "TLS-GROUP") == 0)
		rv = tls_group_capabilities(cb, arg);

	return rv;
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
	{ OSSL_FUNC_PROVIDER_GET_CAPABILITIES, FUNC(prov_get_capabilities) },
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
	prov_teardown(pctx);
	return rv;
}

void prov_err_raise(struct provider_ctx *pctx, const char *file, int line,
		    const char *func, int reason, const char *fmt, ...)
{
	va_list args;

	if (!pctx || !pctx->core_new_error ||
	    !pctx->core_set_error_debug || !pctx->core_vset_error)
		return ERR_raise(ERR_LIB_PROV, reason);

	va_start(args, fmt);
	pctx->core_new_error(pctx->handle);
	pctx->core_set_error_debug(pctx->handle, file, line, func);
	pctx->core_vset_error(pctx->handle, reason, fmt, args);
	va_end(args);
}

int OSSL_provider_init(const OSSL_CORE_HANDLE *handle,
		       const OSSL_DISPATCH *in,
		       const OSSL_DISPATCH **out,
		       void **provctx)
{
	return prov_init(handle, in, out, provctx);
}

__attribute__((constructor)) static void prov_module_init(void)
{
	zpc_init();
}

__attribute__((destructor)) static void prov_module_fini(void)
{
	zpc_fini();
}
