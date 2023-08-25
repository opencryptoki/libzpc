/*
 * Copyright IBM Corp. 2021
 *
 * libzpc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef AES_GCM_LOCAL_H
# define AES_GCM_LOCAL_H

# include "zpc/aes_key.h"

# include "misc.h"
# include "cpacf.h"

/*
 * Internal aes_gcm interface.
 */

#define GCM_RECOMMENDED_IV_LENGTH           12

struct zpc_aes_gcm {
	struct cpacf_kma_gcm_aes_param param;
	struct zpc_aes_key *aes_key;

	unsigned int fc;

	int key_set;
	int iv_set;
	int iv_created;
};

#endif
