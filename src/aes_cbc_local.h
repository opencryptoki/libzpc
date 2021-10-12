/*
 * Copyright IBM Corp. 2021
 *
 * libzpc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef AES_CBC_LOCAL_H
# define AES_CBC_LOCAL_H

# include "zpc/aes_key.h"

# include "misc.h"
# include "cpacf.h"

/*
 * Internal aes_cbc interface.
 */

struct zpc_aes_cbc {
	struct cpacf_kmc_aes_param param;
	struct zpc_aes_key *aes_key;

	unsigned int fc;

	int key_set;
	int iv_set;
};

#endif
