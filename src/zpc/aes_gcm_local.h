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

/*
 * NIST SP 800-38d: 1 <= bitlen(iv) <= 2^64 - 1
 *   => 1 <= bytelen(iv) <= 2^61 - 1
 */
#define GCM_MAX_IV_LENGTH                   ((2ULL << 61) - 1)

/*
 * NIST SP 800-38d: bitlen(A) <= 2^64 - 1
 *   => 0 <= bytelen(A) <= 2^61 - 1
 */
#define GCM_MAX_TOTAL_AAD_LENGTH            ((2ULL << 61) - 1)

/*
 * NIST SP 800-38d: bitlen(P) <= 2^39 - 256;
 *   => 0 <= bytelen(P) <= 2^36 - 32
 */
#define GCM_MAX_TOTAL_PLAINTEXT_LENGTH      ((2ULL << 36) - 32)


struct zpc_aes_gcm {
	struct cpacf_kma_gcm_aes_param param;
	struct zpc_aes_key *aes_key;

	unsigned int fc;

	int key_set;
	int iv_set;
	int iv_created;
};

#endif
