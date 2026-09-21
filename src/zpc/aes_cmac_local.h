/*
 * Copyright IBM Corp. 2021
 *
 * libzpc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef AES_CMAC_LOCAL_H
# define AES_CMAC_LOCAL_H

# include "zpc/aes_key.h"

# include "misc.h"
# include "cpacf.h"

/*
 * Internal aes_cmac interface.
 */

struct zpc_aes_cmac {
	struct cpacf_kmac_aes_param param_kmac;
	struct cpacf_pcc_cmac_aes_param param_pcc;
	struct zpc_aes_key *aes_key;

	unsigned int fc;

	int key_set;
};

#endif
