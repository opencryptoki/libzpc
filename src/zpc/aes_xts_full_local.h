/*
 * Copyright IBM Corp. 2025
 *
 * libzpc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef AES_XTS_FULL_LOCAL_H
# define AES_XTS_FULL_LOCAL_H

#include "zpc/aes_xts_key.h"

# include "misc.h"
# include "cpacf.h"

/*
 * Internal aes-xts-full interface.
 */

/* compute full-xts protected key length [bytes] without wkvp from key-size [bits] */
# define AES_FXTS_PROTKEYLEN(size)     (32 * (size) / 128 )

/* compute offsets [bytes] in KM param structure for full-xts keys */
# define AES_FXTS_TWEAK_OFFSET(size)   AES_FXTS_PROTKEYLEN(size) + 0 * 16
# define AES_FXTS_NAP_OFFSET(size)     AES_FXTS_PROTKEYLEN(size) + 1 * 16
# define AES_FXTS_WKVP_OFFSET(size)    AES_FXTS_PROTKEYLEN(size) + 2 * 16

struct zpc_aes_xts_full {
	u8 param_km[sizeof(struct cpacf_km_xts_full_aes_256_param)];
	struct zpc_aes_xts_key *xts_key;

	unsigned int fc;

	int key_set;
	int iv_set;
};

#endif
