// SPDX-License-Identifier: MIT
// Copyright contributors to the libzpc project
#ifndef _STORE_LOCAL_H
#define _STORE_LOCAL_H

#include <stdbool.h>
#include <openssl/core.h>

#include "provider.h"
#include "uri.h"

int store_load_uri(struct provider_ctx *pctx, struct parsed_uri *puri,
		   bool public_only,
		   OSSL_CALLBACK *object_cb, void *object_cbarg,
		   OSSL_PASSPHRASE_CALLBACK *pw_cb , void *pw_cbarg);

#endif /* _STORE_LOCAL_H */
