// SPDX-License-Identifier: MIT
// Copyright contributors to the libzpc project
#ifndef _OSSL_H
#define _OSSL_H

#include <openssl/types.h>

#define OSSL_RV_TRUE		(1)
#define OSSL_RV_FALSE		(0)
#define OSSL_RV_OK		(1)
#define OSSL_RV_ERR		(0)

#define ALGORITHM_DEFN(name, prop, fn, desc)	{ name, prop, fn, desc }
#define ALGORITHM_END				{ NULL, NULL, NULL, NULL }

#define DISPATCH_DEFN(MODULE, NAME, name)	{ OSSL_FUNC_##MODULE##_##NAME, (void (*)(void))name }
#define DISPATCH_END				{ 0, NULL }

#endif /* _OSSL_H */
