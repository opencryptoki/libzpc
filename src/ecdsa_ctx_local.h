/*
 * Copyright IBM Corp. 2022
 *
 * libzpc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef ECDSA_CTX_LOCAL_H
# define ECDSA_CTX_LOCAL_H

# include "zpc/ecc_key.h"

# include "misc.h"
# include "cpacf.h"

/*
 * Internal ecc_ctx interfaces.
 */

struct zpc_ecdsa_ctx {
	union {
		unsigned char signbuf[4096];
		struct cpacf_ecp256_sign_param p256_sign_param;
		struct cpacf_ecp384_sign_param p384_sign_param;
		struct cpacf_ecp521_sign_param p521_sign_param;
		struct cpacf_ed25519_sign_param ed25519_sign_param;
		struct cpacf_ed448_sign_param ed448_sign_param;
	};

	union {
		unsigned char verifybuf[4096];
		struct cpacf_ecp256_verify_param p256_verify_param;
		struct cpacf_ecp384_verify_param p384_verify_param;
		struct cpacf_ecp521_verify_param p521_verify_param;
		struct cpacf_ed25519_verify_param ed25519_verify_param;
		struct cpacf_ed448_verify_param ed448_verify_param;
	};

	struct zpc_ec_key *ec_key;
	int key_set;

	unsigned int fc_sign;
	unsigned int fc_verify;
};
#endif
