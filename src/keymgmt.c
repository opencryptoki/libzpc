// SPDX-License-Identifier: MIT
// Copyright contributors to the libzpc project
#include <string.h>
#include <openssl/bn.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/params.h>
#include <openssl/param_build.h>

#include "provider.h"
#include "object.h"
#include "ossl.h"
#include "map.h"
#include "zpc/ecc_key.h"
#include "zpc/ecdsa_ctx.h"
#include "zpc/error.h"

#define ASN1_SIG_HDR	8

static struct {
	const char *str;
	int type;
} type_map[] = {
	{ .str = "uv", .type = ZPC_EC_KEY_TYPE_PVSECRET, },
	{ .str = "cca", .type = ZPC_EC_KEY_TYPE_CCA, },
	{ .str = "ep11", .type = ZPC_EC_KEY_TYPE_EP11, },
	{ 0 },
};

static int str2type(const char *str)
{
	for (int i = 0; type_map[i].str; i++) {
		if (OPENSSL_strcasecmp(type_map[i].str, str) == 0)
			return type_map[i].type;
	}
	return 0;
}

static struct {
	const char *alg;
	int bits;
	int secbits;
	int sigsz;
} alg_param_map[] = {
	{
		.alg = SN_X9_62_prime256v1,
		.bits = 256, .secbits = 128, .sigsz = 64 + ASN1_SIG_HDR,
	}, {
		.alg = SN_secp384r1,
		.bits = 384, .secbits = 192, .sigsz = 96 + ASN1_SIG_HDR,
	}, {
		.alg = SN_secp521r1,
		.bits = 521, .secbits = 256, .sigsz = 132 + ASN1_SIG_HDR,
	}, {
		.alg = SN_ED25519,
		.bits = 256, .secbits = 128, .sigsz = 64
	}, {
		.alg = SN_ED448,
		.bits = 456, .secbits = 224, .sigsz = 114},
	{ 0 },
};

static int alg2param(const char *alg, int *bits, int *secbits, int *sigsz)
{
	int i;

	if (!alg)
		return OSSL_RV_ERR;

	for (i = 0; alg_param_map[i].alg; i++) {
		if (OPENSSL_strcasecmp(alg_param_map[i].alg, alg) == 0)
			goto found;
	}
	/* not found */
	return OSSL_RV_ERR;
found:
	if (bits)
		*bits = alg_param_map[i].bits;
	if (secbits)
		*secbits = alg_param_map[i].secbits;
	if (sigsz)
		*sigsz = alg_param_map[i].sigsz;

	return OSSL_RV_OK;
}

#define HASHSZ	32
#define SIGSZ	140
static int zpc_key_check(const struct obj *obj)
{
	const unsigned char hash[HASHSZ] = { 0 };
	struct zpc_ecdsa_ctx *ctx = NULL;
	unsigned char sig[SIGSZ];
	size_t siglen = SIGSZ;
	int rc, rv = OSSL_RV_ERR;

	if (!obj->ec_key || !obj->origin_pubkey.p)
		return OSSL_RV_OK;

	if ((rc = zpc_ecdsa_ctx_alloc(&ctx)) ||
	    (rc = zpc_ecdsa_ctx_set_key(ctx, obj->ec_key)) ||
	    (rc = zpc_ecdsa_sign(ctx, hash, HASHSZ, sig, &siglen)) ||
	    (rc = zpc_ecdsa_verify(ctx, hash, HASHSZ, sig, siglen))) {
		PROV_ERR_raise(obj->pctx, rc);
		goto out;
	}

	rv = OSSL_RV_OK;
out:
	zpc_ecdsa_ctx_free(&ctx);
	return rv;
}
#undef HASHLEN
#undef SIGLEN

static int zpc_key_update(struct obj *obj)
{
	struct zpc_ec_key *key = NULL;
	int rc;

	if ((rc = zpc_ec_key_alloc(&key)))
		goto err;

	if ((rc = zpc_ec_key_set_type(key, str2type(obj->origin_type))))
		goto err;

	if ((rc = zpc_ec_key_set_curve(key, obj_key_curve(obj))))
		goto err;

	if ((rc = zpc_ec_key_import(key, obj->origin_blob.p,
				    obj->origin_blob.plen)))
		goto err;

	if (strcmp(obj->origin_type, "uv") == 0 &&
	    obj->origin_pubkey.p) {
		/* uv only: import pubkey */
		if ((rc = zpc_ec_key_import_clear(key, obj->origin_pubkey.p,
						  obj->origin_pubkey.plen,
						  NULL, 0)))
			goto err;
	} else {
		if (obj->mkvp && (rc = zpc_ec_key_set_mkvp(key, obj->mkvp)))
			goto err;
		/* TODO: apqns */
	}

	obj->ec_key = key;
	return OSSL_RV_OK;
err:
	PROV_ERR_raise(obj->pctx, rc);
	zpc_ec_key_free(&key);
	return OSSL_RV_ERR;
}

static int ec_pub_uncomp(unsigned char *raw, size_t rawlen,
			 unsigned char **pub, size_t *publen)
{
	unsigned char *p;
	size_t plen;

	if (!raw || !rawlen)
		return OSSL_RV_ERR;

	plen = rawlen + 1;
	p = OPENSSL_malloc(plen);
	if (!p)
		return OSSL_RV_ERR;

	p[0] = POINT_CONVERSION_UNCOMPRESSED;
	memcpy(&p[1], raw, rawlen);

	if (pub)
		*pub = p;
	else
		OPENSSL_free(p);

	if (publen)
		*publen = plen;

	return OSSL_RV_OK;
}

static int ec_enc_pubkey_param(struct obj *obj, OSSL_PARAM *p)
{
	unsigned char *pub = NULL;
	size_t publen;
	int rv;

	if (!obj || !obj->origin_pubkey.p)
		return OSSL_RV_ERR;

	if (ec_pub_uncomp(obj->origin_pubkey.p, obj->origin_pubkey.plen,
			  &pub, &publen) != OSSL_RV_OK)
		return OSSL_RV_ERR;

	rv = OSSL_PARAM_set_octet_string(p, pub, publen);
	OPENSSL_free(pub);
	return rv;
}

enum ec_coord {
	EC_X,
	EC_Y,
};

static int ec_pubkey_coord_param(struct obj *obj, enum ec_coord coord,
				 OSSL_PARAM *p)
{
	const unsigned char *raw;
	size_t rawlen;
	BIGNUM *c;
	int rv;

	if (!obj ||
	    !obj->origin_pubkey.p)
		return OSSL_RV_ERR;

	rawlen = obj->origin_pubkey.plen / 2;
	switch (coord) {
	case EC_X:
		raw = obj->origin_pubkey.p;
		break;
	case EC_Y:
		raw = obj->origin_pubkey.p + rawlen;
		break;
	default:
		return OSSL_RV_ERR;
	}

	if (!(c = BN_bin2bn(raw, rawlen, NULL)))
		return OSSL_RV_ERR;

	rv = OSSL_PARAM_set_BN(p, c);
	BN_free(c);
	return rv;
}

static int kmgmt_get_params(struct obj *obj, OSSL_PARAM params[])
{
	int bits, secbits, sigsz;
	OSSL_PARAM *p;

	if (!obj ||
	    alg2param(obj->origin_alg, &bits, &secbits, &sigsz) != OSSL_RV_OK)
		return OSSL_RV_ERR;

	p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS);
	if (p) {
		if (OSSL_PARAM_set_int(p, bits) != OSSL_RV_OK)
			return OSSL_RV_ERR;
	}

	p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS);
	if (p) {
		if (OSSL_PARAM_set_int(p, secbits) != OSSL_RV_OK)
			return OSSL_RV_ERR;
	}

	p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE);
	if (p) {
		if (OSSL_PARAM_set_int(p, sigsz) != OSSL_RV_OK)
			return OSSL_RV_ERR;
	}

	p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_GROUP_NAME);
	if (p) {
		if(OSSL_PARAM_set_utf8_string(p, obj->origin_alg) != OSSL_RV_OK)
			return OSSL_RV_ERR;
	}

	return OSSL_RV_OK;
}

static int kmgmt_export(struct obj *obj, int selection,
			OSSL_CALLBACK *param_cb, void *cbarg,
			bool raw)
{
	int bits, secbits, sigsz, rv = OSSL_RV_ERR;
	OSSL_PARAM_BLD *param_bld = NULL;
	unsigned char *pub, *p = NULL;
	OSSL_PARAM *params = NULL;
	size_t publen;

	if (!obj ||
	    (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY))
		return OSSL_RV_ERR;

	if (alg2param(obj->origin_alg, &bits, &secbits, &sigsz) != OSSL_RV_OK)
		goto out;

	if (!(param_bld = OSSL_PARAM_BLD_new()))
		goto out;

	if (raw) {
		publen = obj->origin_pubkey.plen;
		pub = obj->origin_pubkey.p;
	} else {
		if (ec_pub_uncomp(obj->origin_pubkey.p,
				  obj->origin_pubkey.plen,
				  &p, &publen) != OSSL_RV_OK)
			goto out;
		pub = p;
	}

	if (selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) {
		if (OSSL_PARAM_BLD_push_utf8_string(param_bld, OSSL_PKEY_PARAM_GROUP_NAME,
						    obj->origin_alg, strlen(obj->origin_alg)) != OSSL_RV_OK)
			goto out;

		if (OSSL_PARAM_BLD_push_int(param_bld, OSSL_PKEY_PARAM_BITS, bits) != OSSL_RV_OK)
			goto out;

		if (OSSL_PARAM_BLD_push_int(param_bld, OSSL_PKEY_PARAM_SECURITY_BITS, secbits) != OSSL_RV_OK)
			goto out;

		if (OSSL_PARAM_BLD_push_int(param_bld, OSSL_PKEY_PARAM_MAX_SIZE, sigsz) != OSSL_RV_OK)
			goto out;
	}

	if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
		if (OSSL_PARAM_BLD_push_octet_string(param_bld, OSSL_PKEY_PARAM_PUB_KEY,
						     pub, publen) != OSSL_RV_OK)
			goto out;
	}

	if (!(params = OSSL_PARAM_BLD_to_param(param_bld)))
		goto out;

	rv = param_cb(params, cbarg);
out:
	OSSL_PARAM_free(params);
	OSSL_PARAM_BLD_free(param_bld);
	OPENSSL_free(p);
	return rv;
}

#define DECL_KMGMT_FN(tname, name) DECL_DISPATCH_FUNC(keymgmt, tname, name)
DECL_KMGMT_FN(new, kmgmt_new);
DECL_KMGMT_FN(dup, kmgmt_dup);
DECL_KMGMT_FN(free, kmgmt_free);
DECL_KMGMT_FN(load, kmgmt_load);
DECL_KMGMT_FN(has, kmgmt_has);
DECL_KMGMT_FN(export, ec_export);
DECL_KMGMT_FN(export, ed_export);
DECL_KMGMT_FN(export_types, kmgmt_export_types);
#ifdef OSSL_FUNC_KEYMGMT_EXPORT_TYPES_EX
DECL_KMGMT_FN(export_types_ex, kmgmt_export_types_ex);
#endif
DECL_KMGMT_FN(query_operation_name, ec_query_operation_name);
DECL_KMGMT_FN(query_operation_name, ed25519_query_operation_name);
DECL_KMGMT_FN(query_operation_name, ed448_query_operation_name);
DECL_KMGMT_FN(gettable_params, ec_gettable_params);
DECL_KMGMT_FN(gettable_params, ed_gettable_params);
DECL_KMGMT_FN(get_params, ec_get_params);
DECL_KMGMT_FN(get_params, ed_get_params);
DECL_KMGMT_FN(settable_params, kmgmt_settable_params);
DECL_KMGMT_FN(set_params, kmgmt_set_params);
#undef DECL_SKMGMT_FN

static void *kmgmt_new(void *provctx)
{
	return obj_new((struct provider_ctx *)provctx);
}

static void *kmgmt_dup(const void *keydata_from, int selection)
{
	const struct obj *obj_src = (struct obj *)keydata_from;
	struct obj *obj_dst = NULL;

	if (!obj_src ||
	    !(obj_dst = obj_dup(obj_src)))
		return NULL;

	obj_dst->public_only = selection && !(selection &
					      OSSL_KEYMGMT_SELECT_PRIVATE_KEY);
	if (obj_src->public_only && !obj_dst->public_only)
		goto err;

	if (zpc_key_update(obj_dst) != OSSL_RV_OK)
		goto err;

	return obj_dst;
err:
	obj_free(obj_dst);
	return NULL;
}

static void kmgmt_free(void *keydata)
{
	obj_free((struct obj *)keydata);
}

static void *kmgmt_load(const void *reference, size_t reference_sz)
{
	struct obj *obj;

	if (!reference || reference_sz != sizeof(struct obj))
		return NULL;
	obj = (struct obj *)reference;

	if (zpc_key_update(obj) != OSSL_RV_OK ||
	    zpc_key_check(obj) != OSSL_RV_OK)
		return NULL;

	return obj_get(obj);
}

static int kmgmt_has(const void *keydata, int selection)
{
	struct obj *obj = (struct obj *)keydata;
	int rv = OSSL_RV_TRUE;

	if (!obj)
		return OSSL_RV_FALSE;

	if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) {
		if (obj->public_only || !obj->origin_blob.p || !obj->ec_key)
			rv = OSSL_RV_FALSE;
	}

	if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
		if (!obj->origin_pubkey.p)
			rv = OSSL_RV_FALSE;
	}

	return rv;
}

static int kmgmt_match(const void *keydata1, const void *keydata2,
		       int selection __unused)
{
	const struct obj *obj1 = (struct obj *)keydata1;
	const struct obj *obj2 = (struct obj *)keydata2;
	int rc;

	if (!obj1 || !obj2)
		return OSSL_RV_FALSE;

	if (obj_cmp(obj1, obj2))
		goto match;

	if ((rc = zpc_ec_key_compare(obj1->ec_key, obj2->ec_key))) {
		PROV_ERR_raise(obj1->pctx, rc);
		return OSSL_RV_FALSE;
	}
match:
	return OSSL_RV_TRUE;
}

static int ec_export(void *keydata, int selection,
			OSSL_CALLBACK *param_cb, void *cbarg)
{
	return kmgmt_export(keydata, selection, param_cb, cbarg, false);
}

static int ed_export(void *keydata, int selection,
			OSSL_CALLBACK *param_cb, void *cbarg)
{
	return kmgmt_export(keydata, selection, param_cb, cbarg, true);
}

const OSSL_PARAM *kmgmt_export_types(int selection)
{
	static const OSSL_PARAM params[] = {
		OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
		OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
		OSSL_PARAM_END,
	};
	int idx = 2; /* none */

	if (selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS)
		idx = 1; /* dom-param only */
	if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY)
		idx = 0; /* dom-param  + pubkey */

	return &params[idx];
}

#ifdef OSSL_FUNC_KEYMGMT_EXPORT_TYPES_EX
const OSSL_PARAM *kmgmt_export_types_ex(void *provctx __unused, int selection)
{
	return kmgmt_export_types(selection);
}
#endif

static const char *ec_query_operation_name(int operation_id)
{
	return (operation_id == OSSL_OP_SIGNATURE) ?
		PROV_NAME_ECDSA : NULL;
}

static const char *ed25519_query_operation_name(int operation_id)
{
	return (operation_id == OSSL_OP_SIGNATURE) ?
		PROV_NAME_ED25519 : NULL;
}

static const char *ed448_query_operation_name(int operation_id)
{
	return (operation_id == OSSL_OP_SIGNATURE) ?
		PROV_NAME_ED448 : NULL;
}

static const OSSL_PARAM *ec_gettable_params(void *vpctx __unused)
{
	static const OSSL_PARAM params[] = {
		/* common */
		OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
		OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
		OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
		OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
		/* ec-specific */
		OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT, NULL, 0),
		OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
		OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),
		OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_PUB_X, NULL, 0),
		OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_PUB_Y, NULL, 0),
		OSSL_PARAM_END,
	};
	return params;
}

static int ec_get_params(void *keydata, OSSL_PARAM params[])
{
	struct obj *obj = (struct obj *)keydata;
	OSSL_PARAM *p;

	if (!obj)
		return OSSL_RV_ERR;

	p = OSSL_PARAM_locate(params,
			      OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT);
	if (p) {
		if (OSSL_PARAM_set_utf8_string(p, "uncompressed") != OSSL_RV_OK)
			return OSSL_RV_ERR;
	}

	p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PUB_KEY);
	if (p) {
		if (ec_enc_pubkey_param(obj, p) != OSSL_RV_OK)
			return OSSL_RV_ERR;
	}

	p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY);
	if (p) {
		if (ec_enc_pubkey_param(obj, p) != OSSL_RV_OK)
			return OSSL_RV_ERR;
	}

	p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_EC_PUB_X);
	if (p) {
		if (ec_pubkey_coord_param(obj, EC_X, p) != OSSL_RV_OK)
			return OSSL_RV_ERR;
	}

	p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_EC_PUB_Y);
	if (p) {
		if (ec_pubkey_coord_param(obj, EC_Y, p) != OSSL_RV_OK)
			return OSSL_RV_ERR;
	}

	return kmgmt_get_params(obj, params);
}

static const OSSL_PARAM *ed_gettable_params(void *vpctx __unused)
{
	static const OSSL_PARAM params[] = {
		/* common */
		OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
		OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
		OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
		OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
		/* ed-specific */
		OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
		OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_MANDATORY_DIGEST, NULL, 0),
		OSSL_PARAM_END,
	};
	return params;
}

static int ed_get_params(void *keydata, OSSL_PARAM params[])
{
	struct obj *obj = (struct obj *)keydata;
	OSSL_PARAM *p;

	if (!obj)
		return OSSL_RV_ERR;

	p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PUB_KEY);
	if (p) {
		if (!obj->origin_pubkey.p ||
		    OSSL_PARAM_set_octet_string(p, obj->origin_pubkey.p,
						obj->origin_pubkey.plen) != OSSL_RV_OK)
			return OSSL_RV_ERR;
	}

	p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MANDATORY_DIGEST);
	if (p) {
		if (OSSL_PARAM_set_utf8_string(p, "") != OSSL_RV_OK)
			return OSSL_RV_ERR;
	}

	return kmgmt_get_params(obj, params);
}

static const OSSL_PARAM *kmgmt_settable_params(void *vpctx __unused)
{
	static const OSSL_PARAM params[] = {
		/* none */
		OSSL_PARAM_END,
	};
	return params;
}

static int kmgmt_set_params(void *keydata __unused,
			    const OSSL_PARAM params[])
{
	const char *fmt = NULL;
	const OSSL_PARAM *p;
	int include_public;

	p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_EC_INCLUDE_PUBLIC);
	if (p) {
		if (OSSL_PARAM_get_int(p, &include_public) != OSSL_RV_OK ||
		    !include_public)
			return OSSL_RV_ERR;
	}

	p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT);
	if (p) {
		if (OSSL_PARAM_get_utf8_string_ptr(p, &fmt) != OSSL_RV_OK ||
		    !fmt ||
		    OPENSSL_strcasecmp(fmt, OSSL_PKEY_EC_POINT_CONVERSION_FORMAT_UNCOMPRESSED) != 0)
			return OSSL_RV_ERR;
	}

	return OSSL_RV_OK;
}

static const OSSL_DISPATCH kmgmt_ecdsa_functions[] = {
	DISPATCH_DEFN(KEYMGMT, NEW, kmgmt_new),
	DISPATCH_DEFN(KEYMGMT, DUP, kmgmt_dup),
	DISPATCH_DEFN(KEYMGMT, FREE, kmgmt_free),
	DISPATCH_DEFN(KEYMGMT, LOAD, kmgmt_load),
	DISPATCH_DEFN(KEYMGMT, HAS, kmgmt_has),
	DISPATCH_DEFN(KEYMGMT, MATCH, kmgmt_match),
	DISPATCH_DEFN(KEYMGMT, EXPORT, ec_export),
	DISPATCH_DEFN(KEYMGMT, EXPORT_TYPES, kmgmt_export_types),
#ifdef OSSL_FUNC_KEYMGMT_EXPORT_TYPES_EX
	DISPATCH_DEFN(KEYMGMT, EXPORT_TYPES_EX, kmgmt_export_types_ex),
#endif
	DISPATCH_DEFN(KEYMGMT, QUERY_OPERATION_NAME, ec_query_operation_name),
	DISPATCH_DEFN(KEYMGMT, GETTABLE_PARAMS, ec_gettable_params),
	DISPATCH_DEFN(KEYMGMT, GET_PARAMS, ec_get_params),
	DISPATCH_DEFN(KEYMGMT, SETTABLE_PARAMS, kmgmt_settable_params),
	DISPATCH_DEFN(KEYMGMT, SET_PARAMS, kmgmt_set_params),
	DISPATCH_END,
};

static const OSSL_DISPATCH kmgmt_ed25519_functions[] = {
	DISPATCH_DEFN(KEYMGMT, NEW, kmgmt_new),
	DISPATCH_DEFN(KEYMGMT, DUP, kmgmt_dup),
	DISPATCH_DEFN(KEYMGMT, FREE, kmgmt_free),
	DISPATCH_DEFN(KEYMGMT, LOAD, kmgmt_load),
	DISPATCH_DEFN(KEYMGMT, HAS, kmgmt_has),
	DISPATCH_DEFN(KEYMGMT, MATCH, kmgmt_match),
	DISPATCH_DEFN(KEYMGMT, EXPORT, ed_export),
	DISPATCH_DEFN(KEYMGMT, EXPORT_TYPES, kmgmt_export_types),
#ifdef OSSL_FUNC_KEYMGMT_EXPORT_TYPES_EX
	DISPATCH_DEFN(KEYMGMT, EXPORT_TYPES_EX, kmgmt_export_types_ex),
#endif
	DISPATCH_DEFN(KEYMGMT, QUERY_OPERATION_NAME, ed25519_query_operation_name),
	DISPATCH_DEFN(KEYMGMT, GETTABLE_PARAMS, ed_gettable_params),
	DISPATCH_DEFN(KEYMGMT, GET_PARAMS, ed_get_params),
	DISPATCH_DEFN(KEYMGMT, SETTABLE_PARAMS, kmgmt_settable_params),
	DISPATCH_DEFN(KEYMGMT, SET_PARAMS, kmgmt_set_params),
	DISPATCH_END,
};

static const OSSL_DISPATCH kmgmt_ed448_functions[] = {
	DISPATCH_DEFN(KEYMGMT, NEW, kmgmt_new),
	DISPATCH_DEFN(KEYMGMT, DUP, kmgmt_dup),
	DISPATCH_DEFN(KEYMGMT, FREE, kmgmt_free),
	DISPATCH_DEFN(KEYMGMT, LOAD, kmgmt_load),
	DISPATCH_DEFN(KEYMGMT, HAS, kmgmt_has),
	DISPATCH_DEFN(KEYMGMT, MATCH, kmgmt_match),
	DISPATCH_DEFN(KEYMGMT, EXPORT, ed_export),
	DISPATCH_DEFN(KEYMGMT, EXPORT_TYPES, kmgmt_export_types),
#ifdef OSSL_FUNC_KEYMGMT_EXPORT_TYPES_EX
	DISPATCH_DEFN(KEYMGMT, EXPORT_TYPES_EX, kmgmt_export_types_ex),
#endif
	DISPATCH_DEFN(KEYMGMT, QUERY_OPERATION_NAME, ed448_query_operation_name),
	DISPATCH_DEFN(KEYMGMT, GETTABLE_PARAMS, ed_gettable_params),
	DISPATCH_DEFN(KEYMGMT, GET_PARAMS, ed_get_params),
	DISPATCH_DEFN(KEYMGMT, SETTABLE_PARAMS, kmgmt_settable_params),
	DISPATCH_DEFN(KEYMGMT, SET_PARAMS, kmgmt_set_params),
	DISPATCH_END,
};

const OSSL_ALGORITHM keymgmt_ops[] = {
	ALGORITHM_DEFN(PROV_NAME_EC, PROV_PROP, kmgmt_ecdsa_functions,
		       PROV_DESC_EC),
	ALGORITHM_DEFN(PROV_NAME_ED25519, PROV_PROP, kmgmt_ed25519_functions,
		       PROV_DESC_ED25519),
	ALGORITHM_DEFN(PROV_NAME_ED448, PROV_PROP, kmgmt_ed448_functions,
		       PROV_DESC_ED448),
	ALGORITHM_END,
};
