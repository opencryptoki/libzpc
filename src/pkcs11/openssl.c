// SPDX-License-Identifier: MIT
// Copyright contributors to the libzpc project
#include <stdbool.h>

#include <openssl/crypto.h>
#include <openssl/provider.h>
#include <openssl/err.h>
#include <openssl/store.h>
#include <openssl/core_names.h>

#include "openssl.h"
#include "object.h"

#define DEFAULT_PROVIDER_NAME	"default"
#define BASE_PROVIDER_NAME	"base"
#define ZPC_PROVIDER_NAME	"zpcprovider"

static OSSL_LIB_CTX *ossl_lib_context = NULL;
static OSSL_PROVIDER *ossl_default_provider = NULL;
static OSSL_PROVIDER *ossl_base_provider = NULL;
static OSSL_PROVIDER *ossl_hbkzpc_provider = NULL;

static const unsigned char oid_p256[] = {
	0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07
};

static const unsigned char oid_p384[] = {
	0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22
};

static const unsigned char oid_p521[] = {
	0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x23
};

static const unsigned char oid_ed25519[] = {
	0x06, 0x03, 0x2B, 0x65, 0x70
};

static const unsigned char oid_ed448[] = {
	0x06, 0x03, 0x2B, 0x65, 0x71
};

int openssl_init(void)
{
	OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL);

	ossl_lib_context = OSSL_LIB_CTX_new();
	if (!ossl_lib_context)
		return 0;

	ossl_default_provider = OSSL_PROVIDER_load(ossl_lib_context,
						   DEFAULT_PROVIDER_NAME);
	if (!ossl_default_provider) {
		ERR_print_errors_fp(stderr);
		openssl_term();
		return 0;
	}

	ossl_base_provider = OSSL_PROVIDER_load(ossl_lib_context,
						BASE_PROVIDER_NAME);
	if (!ossl_base_provider) {
		ERR_print_errors_fp(stderr);
		openssl_term();
		return 0;
	}

	ossl_hbkzpc_provider = OSSL_PROVIDER_load(ossl_lib_context,
						  ZPC_PROVIDER_NAME);
	if (!ossl_hbkzpc_provider) {
		ERR_print_errors_fp(stderr);
		openssl_term();
		return 0;
	}

	return 1;
}

void openssl_term(void)
{
	if (ossl_hbkzpc_provider)
		OSSL_PROVIDER_unload(ossl_hbkzpc_provider);
	ossl_hbkzpc_provider = NULL;

	if (ossl_base_provider)
		OSSL_PROVIDER_unload(ossl_base_provider);
	ossl_base_provider = NULL;

	if (ossl_default_provider)
		OSSL_PROVIDER_unload(ossl_default_provider);
	ossl_default_provider = NULL;

	if (ossl_lib_context)
		OSSL_LIB_CTX_free(ossl_lib_context);
	ossl_lib_context = NULL;
}

static int openssl_process_ec_key(const char *label, EVP_PKEY *pkey,
				  size_t lineno, bool keypair, bool is_hbk)
{
	char group[200] = { 0 };
	const unsigned char *ec_params = NULL;
	size_t ec_params_len = 0;
	unsigned char point[200] = { 0 };
	size_t ec_point_len = 0;
	unsigned char *ec_point = NULL;
	unsigned char *spki = NULL;
	int spki_len = 0;
	size_t prime_len = 0;
	int rc = 0;

	if (!EVP_PKEY_get_utf8_string_param(pkey, OSSL_PKEY_PARAM_GROUP_NAME,
					    group, sizeof(group), NULL))
		return 0;

	switch (OBJ_sn2nid(group)) {
	case NID_X9_62_prime256v1:
		ec_params = oid_p256;
		ec_params_len = sizeof(oid_p256);
		prime_len = 256 / 8;
		break;
	case NID_secp384r1:
		ec_params = oid_p384;
		ec_params_len = sizeof(oid_p384);
		prime_len = 384 / 8;
		break;
	case NID_secp521r1:
		ec_params = oid_p521;
		ec_params_len = sizeof(oid_p521);
		prime_len = 521 / 8 + 1;
		break;
	}
	if (!ec_params)
		return 0;

	if (EVP_PKEY_get_octet_string_param(pkey,
					    OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY,
					    point + 3, sizeof(point) - 3,
					    &ec_point_len) == 1) {
		/* CKA_EC_POINT needs DER encoded EC point */
		if (ec_point_len < 0x80) {
			point[1] = 0x04; /* OCTET-STRING */
			point[2] = ec_point_len & 0x7f;
			ec_point_len += 2;
			ec_point = &point[1];
		} else if (ec_point_len < 0x0100) {
			point[0] = 0x04; /* OCTET-STRING */
			point[1] = 0x81; /* 1 byte length field */
			point[2] = ec_point_len & 0xff;
			ec_point_len += 3;
			ec_point = &point[0];
		} else {
			return 0;
		}

		spki_len = i2d_PUBKEY(pkey, &spki);
		if (spki_len <= 0 || !spki)
			return 0;
	}

	if (keypair &&
	    !object_add_ec_ed_private_key(label, lineno, CKK_EC,
					  ec_params, ec_params_len,
					  spki, spki_len, prime_len, pkey,
					  is_hbk))
		goto out;

	if (ec_point &&
	    !object_add_ec_ed_public_key(label, lineno, CKK_EC,
					 ec_params, ec_params_len,
					 ec_point, ec_point_len,
					 spki, spki_len, prime_len, pkey,
					 is_hbk))
		goto out;

	rc = 1;

out:
	if (spki)
		OPENSSL_free(spki);

	return rc;
}

static int openssl_process_ed_key(const char *label, EVP_PKEY *pkey,
				  size_t lineno, bool keypair, bool is_hbk)
{
	const unsigned char *ec_params = NULL;
	size_t ec_params_len = 0;
	unsigned char ec_point[200] = { 0 };
	size_t ec_point_len = 0;
	unsigned char *spki = NULL;
	int spki_len = 0;
	int rc = 0;

	if (EVP_PKEY_is_a(pkey, "ED25519")) {
		ec_params = oid_ed25519;
		ec_params_len = sizeof(oid_ed25519);
	} else if (EVP_PKEY_is_a(pkey, "ED448")) {
		ec_params = oid_ed448;
		ec_params_len = sizeof(oid_ed448);
	}
	if (!ec_params)
		return 0;

	if (EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY,
					    ec_point, sizeof(ec_point),
					    &ec_point_len)) {
		spki_len = i2d_PUBKEY(pkey, &spki);
		if (spki_len <= 0 || !spki)
			return 0;
	}

	if (keypair &&
	    !object_add_ec_ed_private_key(label, lineno, CKK_EC_EDWARDS,
					  ec_params, ec_params_len,
					  spki, spki_len, 0, pkey,
					  is_hbk))
		goto out;

	if (ec_point_len > 0 &&
	    !object_add_ec_ed_public_key(label, lineno, CKK_EC_EDWARDS,
					 ec_params, ec_params_len,
					 ec_point, ec_point_len,
					 spki, spki_len, 0, pkey,
					 is_hbk))
		goto out;

	rc = 1;

out:
	if (spki)
		OPENSSL_free(spki);

	return rc;
}

static int openssl_process_pkey(const char *label, EVP_PKEY *pkey,
				size_t lineno, bool keypair)
{
	const OSSL_PROVIDER *prov = EVP_PKEY_get0_provider(pkey);
	const char *prov_name = prov ? OSSL_PROVIDER_get0_name(prov) : NULL;
	bool is_hbk = (prov_name != NULL && strcmp(prov_name, "hbkzpc") == 0);

	if (EVP_PKEY_is_a(pkey, "EC"))
		return openssl_process_ec_key(label, pkey, lineno, keypair, is_hbk);
	if (EVP_PKEY_is_a(pkey, "ED25519"))
		return openssl_process_ed_key(label, pkey, lineno, keypair, is_hbk);
	if (EVP_PKEY_is_a(pkey, "ED448"))
		return openssl_process_ed_key(label, pkey, lineno, keypair, is_hbk);

	fprintf(stderr, "zpcpkcs11: Unsupported key type [label=%s]\n", label);
	return 0;
}

int openssl_process_config(const char *label, const char *uri, size_t lineno)
{
	OSSL_STORE_CTX *sctx;
	EVP_PKEY *pkey;
	int rc = 0;
	int found = 0;

	sctx = OSSL_STORE_open_ex(uri, ossl_lib_context, NULL, NULL, NULL,
				  NULL, NULL, NULL);
	if (!sctx) {
		fprintf(stderr, "zpcpkcs11: OSSL_STORE_open() [uri=%s]\n", uri);
		ERR_print_errors_fp(stderr);
		goto out;
	}

	while (!OSSL_STORE_eof(sctx)) {
		OSSL_STORE_INFO *info = OSSL_STORE_load(sctx);
		if (!info) {
			fprintf(stderr,
				"zpcpkcs11: OSSL_STORE_load() [uri=%s]\n", uri);
			ERR_print_errors_fp(stderr);
			goto out_close;
		}

		switch (OSSL_STORE_INFO_get_type(info)) {
		case OSSL_STORE_INFO_PKEY:
			pkey = OSSL_STORE_INFO_get1_PKEY(info);
			rc = openssl_process_pkey(label, pkey, lineno, true);
			EVP_PKEY_free(pkey);
			found = 1;
			break;
		case OSSL_STORE_INFO_PUBKEY:
			pkey = OSSL_STORE_INFO_get1_PUBKEY(info);
			rc = openssl_process_pkey(label, pkey, lineno, false);
			EVP_PKEY_free(pkey);
			found = 1;
			break;
		default:
			OSSL_STORE_INFO_free(info);
			continue;
		}

		OSSL_STORE_INFO_free(info);
		break;
	}

	if (!found) {
		fprintf(stderr,
			"zpcpkcs11: No key found in store [uri=%s]\n", uri);
		goto out_close;
	}

out_close:
	OSSL_STORE_close(sctx);
out:
	return rc;
}

EVP_PKEY_CTX *openssl_get_pkey_context(EVP_PKEY *pkey)
{
	EVP_PKEY_CTX *ctx;

	ctx = EVP_PKEY_CTX_new_from_pkey(ossl_lib_context, pkey, NULL);
	if (!ctx) {
		fprintf(stderr,
			"zpcpkcs11: EVP_PKEY_CTX_new_from_pkey failed\n");
		ERR_print_errors_fp(stderr);
		return NULL;
	}

	return ctx;
}

EVP_MD_CTX *openssl_get_digest_sign_context(EVP_PKEY *pkey,
					    const char *mdname)
{
	EVP_MD_CTX *ctx;

	ctx = EVP_MD_CTX_new();
	if (!ctx)
		return NULL;

	if (EVP_DigestSignInit_ex(ctx, NULL, mdname, ossl_lib_context, NULL,
				  pkey, NULL) != 1) {
		fprintf(stderr,
			"zpcpkcs11: EVP_DigestSignInit_ex failed\n");
		ERR_print_errors_fp(stderr);
		EVP_MD_CTX_free(ctx);
		return NULL;
	}

	return ctx;
}

EVP_MD_CTX *openssl_get_digest_verify_context(EVP_PKEY *pkey,
					      const char *mdname)
{
	EVP_MD_CTX *ctx = NULL;

	ctx = EVP_MD_CTX_new();
	if (!ctx)
		return NULL;

	if (EVP_DigestVerifyInit_ex(ctx, NULL, mdname, ossl_lib_context, NULL,
				    pkey, NULL) != 1) {
		fprintf(stderr,
			"zpcpkcs11: EVP_DigestVerifyInit_ex failed\n");
		ERR_print_errors_fp(stderr);
		EVP_MD_CTX_free(ctx);
		return NULL;
	}

	return ctx;
}
