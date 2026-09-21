// SPDX-License-Identifier: MIT
// Copyright contributors to the libzpc project
#ifndef _OSSL_CORE_H
#define _OSSL_CORE_H

#define ALGORITHM_DEFN(name, prop, fn, desc)	{ name, prop, fn, desc }
#define ALGORITHM_END				{ NULL, NULL, NULL, NULL }

#define DISPATCH_DEFN(MODULE, NAME, name)	{ OSSL_FUNC_##MODULE##_##NAME, (void (*)(void))name }
#define DISPATCH_END				{ 0, NULL }

#define DECL_DISPATCH_FUNC(MODULE, NAME, name) \
	static OSSL_FUNC_##MODULE##_##NAME##_fn name

#endif /* _OSSL_CORE_H */
