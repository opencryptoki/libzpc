/*
 * Copyright IBM Corp. 2025
 *
 * libzpc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef AES_HMAC_LOCAL_H
# define AES_HMAC_LOCAL_H

# include "zpc/hmac_key.h"

# include "misc.h"
# include "cpacf.h"

/*
 * Internal hmac interface.
 */

struct zpc_hmac {
	struct cpacf_kmac_hmac_param param_kmac;
	struct zpc_hmac_key *hmac_key;

	unsigned int fc;
	int ikp;

	int key_set;

	int initialized;

	int blksize;
};

#endif
