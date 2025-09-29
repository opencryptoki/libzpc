// SPDX-License-Identifier: MIT
// Copyright contributors to the libzpc project
#include <stdbool.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>

#include <zpc/aes_cbc.h>

#include "cipher.h"
#include "object.h"
#include "ossl.h"

#define AES_BLOCK_SIZE	16

struct cipher_ctx {
	struct prov_ctx *pctx;

	union {
		struct zpc_aes_cbc *aescbc_ctx;
	};

	size_t keylen;
	bool encrypt;
};

static const OSSL_PARAM cipher_gettable_params[] = {
	OSSL_PARAM_uint(OSSL_CIPHER_PARAM_MODE, NULL),
	OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
	OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_BLOCK_SIZE, NULL),
	OSSL_PARAM_END
};

static const OSSL_PARAM *aes_gettable_params(void)
{
	return cipher_gettable_params;
}

static void *aescbc_newctx(void *vpctx, size_t keylen)
{
	struct prov_ctx *pctx = (struct prov_ctx *)vpctx;
	struct cipher_ctx *cctx;

	cctx = OPENSSL_zalloc(sizeof (*cctx));
	if (!cctx)
		return NULL;

	if (zpc_aes_cbc_alloc(&cctx->aescbc_ctx)) {
		OPENSSL_free(cctx);
		return NULL;
	}

	cctx->pctx = pctx;
	cctx->keylen = keylen;

	return cctx;
}

static void aescbc_freectx(void *vcctx)
{
	struct cipher_ctx *cctx = (struct cipher_ctx *)vcctx;

	if (!cctx)
		return;

	zpc_aes_cbc_free(&cctx->aescbc_ctx);
	OPENSSL_free(cctx);
}

static int aes_get_params(OSSL_PARAM params[],
			  uint mode, size_t keylen,
			  size_t ivlen, size_t block_size)
{
	OSSL_PARAM *p;

	if (!params)
		return OSSL_RV_ERR;

	p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_MODE);
	if (p && (OSSL_PARAM_set_uint(p, mode) != OSSL_RV_OK))
		return OSSL_RV_ERR;

	p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
	if (p && (OSSL_PARAM_set_size_t(p, keylen) != OSSL_RV_OK))
		return OSSL_RV_ERR;

	p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
	if (p && (OSSL_PARAM_set_size_t(p, ivlen) != OSSL_RV_OK))
		return OSSL_RV_ERR;

	p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_BLOCK_SIZE);
	if (p && (OSSL_PARAM_set_size_t(p, block_size) != OSSL_RV_OK))
		return OSSL_RV_ERR;

	return OSSL_RV_OK;
}

static int aescbc_init(void *vcctx, void *keydata,
		       const unsigned char *iv, size_t ivlen,
		       const OSSL_PARAM params[] __unused, bool encrypt)
{
	struct cipher_ctx *cctx = (struct cipher_ctx *)vcctx;
	struct obj *obj = keydata;

	if (!cctx->aescbc_ctx)
		return OSSL_RV_ERR;

	if (ivlen < AES_BLOCK_SIZE)
		return OSSL_RV_ERR;

	if (obj && zpc_aes_cbc_set_key(cctx->aescbc_ctx, obj->aes_key))
		return OSSL_RV_ERR;

	if (iv && zpc_aes_cbc_set_iv(cctx->aescbc_ctx, iv))
		return OSSL_RV_ERR;

	cctx->encrypt = encrypt;

	return OSSL_RV_OK;
}

static int aescbc_encrypt_init(void *vcctx, void *keydata,
			       const unsigned char *iv, size_t ivlen,
			       const OSSL_PARAM params[] __unused)
{
	return aescbc_init(vcctx, keydata, iv, ivlen, params, true);
}

static int aescbc_decrypt_init(void *vcctx, void *keydata,
			       const unsigned char *iv, size_t ivlen,
			       const OSSL_PARAM params[] __unused)
{
	return aescbc_init(vcctx, keydata, iv, ivlen, params, false);
}

static int aescbc_update(void *vcctx,
			 unsigned char *out, size_t *outl, size_t outsize,
			 const unsigned char *in, size_t inl)
{
	struct cipher_ctx *cctx = (struct cipher_ctx *)vcctx;
	int err;

	if (!cctx)
		return OSSL_RV_ERR;

	if (outsize < inl)
		return OSSL_RV_ERR;

	err = cctx->encrypt ?
		zpc_aes_cbc_encrypt(cctx->aescbc_ctx, out, in, inl) :
		zpc_aes_cbc_decrypt(cctx->aescbc_ctx, out, in, inl);
	if (err)
		return OSSL_RV_ERR;

	if (outl)
		*outl = inl;

	return OSSL_RV_OK;
}

static int aescbc_final(void *vcctx,
			unsigned char *out, size_t *outl, size_t outsize __unused)
{
	struct cipher_ctx *cctx = (struct cipher_ctx *)vcctx;

	if (!cctx || !out)
		return OSSL_RV_ERR;

	if (outl)
		*outl = 0;

	return OSSL_RV_OK;
}

static void *aes_128_cbc_newctx(void *vpctx)
{
	return aescbc_newctx(vpctx, 16);
}

static void *aes_192_cbc_newctx(void *vpctx)
{
	return aescbc_newctx(vpctx, 24);
}

static void *aes_256_cbc_newctx(void *vpctx)
{
	return aescbc_newctx(vpctx, 32);
}

static int aes_128_cbc_get_params(OSSL_PARAM params[])
{
	return aes_get_params(params, EVP_CIPH_CBC_MODE, 16, AES_BLOCK_SIZE, AES_BLOCK_SIZE);
}

static int aes_192_cbc_get_params(OSSL_PARAM params[])
{
	return aes_get_params(params, EVP_CIPH_CBC_MODE, 24, AES_BLOCK_SIZE, AES_BLOCK_SIZE);
}

static int aes_256_cbc_get_params(OSSL_PARAM params[])
{
	return aes_get_params(params, EVP_CIPH_CBC_MODE, 32, AES_BLOCK_SIZE, AES_BLOCK_SIZE);
}

static const OSSL_DISPATCH aes_128_cbc_functions[] = {
	DISPATCH_DEFN(CIPHER, NEWCTX,             aes_128_cbc_newctx),
	DISPATCH_DEFN(CIPHER, FREECTX,            aescbc_freectx),
	DISPATCH_DEFN(CIPHER, GETTABLE_PARAMS,    aes_gettable_params),
	DISPATCH_DEFN(CIPHER, GET_PARAMS,         aes_128_cbc_get_params),
	DISPATCH_DEFN(CIPHER, ENCRYPT_SKEY_INIT,  aescbc_encrypt_init),
	DISPATCH_DEFN(CIPHER, DECRYPT_SKEY_INIT,  aescbc_decrypt_init),
	DISPATCH_DEFN(CIPHER, UPDATE,             aescbc_update),
	DISPATCH_DEFN(CIPHER, FINAL,              aescbc_final),
	DISPATCH_END,
};

static const OSSL_DISPATCH aes_192_cbc_functions[] = {
	DISPATCH_DEFN(CIPHER, NEWCTX,             aes_192_cbc_newctx),
	DISPATCH_DEFN(CIPHER, FREECTX,            aescbc_freectx),
	DISPATCH_DEFN(CIPHER, GETTABLE_PARAMS,    aes_gettable_params),
	DISPATCH_DEFN(CIPHER, GET_PARAMS,         aes_192_cbc_get_params),
	DISPATCH_DEFN(CIPHER, ENCRYPT_SKEY_INIT,  aescbc_encrypt_init),
	DISPATCH_DEFN(CIPHER, DECRYPT_SKEY_INIT,  aescbc_decrypt_init),
	DISPATCH_DEFN(CIPHER, UPDATE,             aescbc_update),
	DISPATCH_DEFN(CIPHER, FINAL,              aescbc_final),
	DISPATCH_END,
};

static const OSSL_DISPATCH aes_256_cbc_functions[] = {
	DISPATCH_DEFN(CIPHER, NEWCTX,             aes_256_cbc_newctx),
	DISPATCH_DEFN(CIPHER, FREECTX,            aescbc_freectx),
	DISPATCH_DEFN(CIPHER, GETTABLE_PARAMS,    aes_gettable_params),
	DISPATCH_DEFN(CIPHER, GET_PARAMS,         aes_256_cbc_get_params),
	DISPATCH_DEFN(CIPHER, ENCRYPT_SKEY_INIT,  aescbc_encrypt_init),
	DISPATCH_DEFN(CIPHER, DECRYPT_SKEY_INIT,  aescbc_decrypt_init),
	DISPATCH_DEFN(CIPHER, UPDATE,             aescbc_update),
	DISPATCH_DEFN(CIPHER, FINAL,              aescbc_final),
	DISPATCH_END,
};

const OSSL_ALGORITHM cipher_ops[] = {
	ALGORITHM_DEFN("AES-128-CBC", PROV_PROP, aes_128_cbc_functions, NULL),
	ALGORITHM_DEFN("AES-192-CBC", PROV_PROP, aes_192_cbc_functions, NULL),
	ALGORITHM_DEFN("AES-256-CBC", PROV_PROP, aes_256_cbc_functions, NULL),
	ALGORITHM_END,
};
