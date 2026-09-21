// SPDX-License-Identifier: MIT
// Copyright contributors to the libzpc project
#ifndef _PROVIDER_H
#define _PROVIDER_H

#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/types.h>

#define PROV_NAME	"hbkzpc"
#define PROV_PROP	"provider="PROV_NAME
#define PROV_PROP_FWD	"provider!="PROV_NAME

#define PROV_NAME_EC		"EC"
#define PROV_NAMES_EC		"EC:id-ecPublicKey:1.2.840.10045.2.1"
#define PROV_DESC_EC		"hbkzpc EC implementation"

#define PROV_NAME_ECDSA		"ECDSA"
#define PROV_NAMES_ECDSA	PROV_NAME_ECDSA
#define PROV_DESC_ECDSA		"hbkzpc ECDSA Implementation"

#define PROV_NAME_ED25519	"ED25519"
#define PROV_NAMES_ED25519	"ED25519:1.3.101.112"
#define PROV_DESC_ED25519	"hbkzpc ED25519 Implementation"

#define PROV_NAME_ED448		"ED448"
#define PROV_NAMES_ED448	"ED448:1.3.101.113"
#define PROV_DESC_ED448		"hbkzpc ED448 Implementation"

#define __unused	__attribute__((unused))

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x)	(sizeof(x) / sizeof(*(x)))
#endif

#ifndef MIN
#define MIN(a, b)	((a) < (b) ? (a) : (b))
#endif

#ifndef MAX
#define MAX(a, b)	((a) > (b) ? (a) : (b))
#endif

enum provider_state {
	PROVIDER_UNINITIALIZED = 0,
	PROVIDER_INITIALIZED,
};

struct provider_ctx {
	const OSSL_CORE_HANDLE *handle;
	OSSL_LIB_CTX *libctx;

	enum provider_state state;

	OSSL_FUNC_core_new_error_fn *core_new_error;
	OSSL_FUNC_core_set_error_debug_fn *core_set_error_debug;
	OSSL_FUNC_core_vset_error_fn *core_vset_error;
};

void prov_err_raise(struct provider_ctx *pctx, const char *file, int line,
		    const char *func, int reason, const char *fmt, ...);
#define PROV_ERR_raise(pctx, reason) \
	prov_err_raise(pctx, OPENSSL_FILE, OPENSSL_LINE, OPENSSL_FUNC, reason, NULL)

#endif /* _PROVIDER_H */
