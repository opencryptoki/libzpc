/*
 * Copyright IBM Corp. 2021
 *
 * libzpc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef AES_ECB_LOCAL_H
# define AES_ECB_LOCAL_H

# include "zpc/aes_key.h"

# include "misc.h"
# include "cpacf.h"

/*
 * Internal aes_ecb interface.
 */

struct zpc_aes_ecb {
	struct cpacf_km_aes_param param;
	struct zpc_aes_key *aes_key;

	unsigned int fc;

	int key_set;
};

#endif
