/*
 * Copyright IBM Corp. 2021
 *
 * libzpc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef AES_XTS_LOCAL_H
# define AES_XTS_LOCAL_H

# include "zpc/aes_key.h"

# include "misc.h"
# include "cpacf.h"

/*
 * Internal aes_xts interface.
 */

/* compute protected key length [bytes] from key-size [bits] */
# define AES_XTS_PROTKEYLEN(size)	(32 + 16 * (size) / 128 )
/* compute offsets [bytes] in PCC param structure from key-size [bits] */
# define AES_XTS_PCC_I(size)		AES_XTS_PROTKEYLEN(size) + 0 * 16
# define AES_XTS_PCC_J(size)		AES_XTS_PROTKEYLEN(size) + 1 * 16
# define AES_XTS_PCC_T(size)		AES_XTS_PROTKEYLEN(size) + 2 * 16
# define AES_XTS_PCC_XTSPARAM(size)	AES_XTS_PROTKEYLEN(size) + 3 * 16
/* compute offsets [bytes] in KM param structure from key-size [bits] */
# define AES_XTS_KM_XTSPARAM(size)	AES_XTS_PROTKEYLEN(size) + 0 * 16

struct zpc_aes_xts {
	u8 param_km[sizeof(struct cpacf_km_xts_aes_256_param)];
	u8 param_pcc[sizeof(struct cpacf_pcc_xts_aes_256_param)];
	struct zpc_aes_key *aes_key1;
	struct zpc_aes_key *aes_key2;

	unsigned int fc;

	int key_set;
	int iv_set;
};

#endif
