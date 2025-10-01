// SPDX-License-Identifier: MIT
// Copyright contributors to the libzpc project
#ifndef _PROVIDER_H
#define _PROVIDER_H

#include <openssl/core.h>
#include <openssl/types.h>

#define PROV_NAME	"hbkzpc"
#define PROV_VERSION	"2.0.0"
#define PROV_PROP	"provider="PROV_NAME

#define __unused	__attribute__((unused))

enum provider_state {
	PROVIDER_UNINITIALIZED = 0,
	PROVIDER_INITIALIZED,
};

struct provider_ctx {
	const OSSL_CORE_HANDLE *handle;
	OSSL_LIB_CTX *libctx;

	enum provider_state state;
};

#endif /* _PROVIDER_H */
