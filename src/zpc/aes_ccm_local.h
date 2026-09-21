/*
 * Copyright IBM Corp. 2021
 *
 * libzpc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef AES_CCM_LOCAL_H
# define AES_CCM_LOCAL_H

# include "zpc/aes_key.h"

# include "misc.h"
# include "cpacf.h"

/*
 * Internal aes_ccm interface.
 */

struct zpc_aes_ccm {
	struct cpacf_kma_gcm_aes_param param_kma;
	struct cpacf_kmac_aes_param param_kmac;
	struct zpc_aes_key *aes_key;

	unsigned int fc;

	u8 iv[16];
	size_t ivlen;

	int key_set;
	int iv_set;
};

#endif
