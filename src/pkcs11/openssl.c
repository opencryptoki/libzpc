// SPDX-License-Identifier: MIT
// Copyright contributors to the libzpc project
#include <openssl/crypto.h>
#include <openssl/provider.h>
#include <openssl/err.h>

#include "openssl.h"

#define DEFAULT_PROVIDER_NAME	"default"
#define BASE_PROVIDER_NAME	"base"
#define ZPC_PROVIDER_NAME	"zpcprovider"

static OSSL_LIB_CTX *ossl_lib_context = NULL;
static OSSL_PROVIDER *ossl_default_provider = NULL;
static OSSL_PROVIDER *ossl_base_provider = NULL;
static OSSL_PROVIDER *ossl_hbkzpc_provider = NULL;

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

