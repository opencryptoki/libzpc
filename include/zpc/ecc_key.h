/*
 * Copyright IBM Corp. 2022
 *
 * libzpc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef ZPC_ECC_KEY_H
# define ZPC_ECC_KEY_H
# ifdef __cplusplus
/* *INDENT-OFF* */
extern "C" {
/* *INDENT-ON* */
# endif

/**
 * \file zpc/ecc_key.h
 * \brief ECC key API.
 * 
 * Manage elliptic curve cryptography (ECC) cipher
 * \cite EC keys.
 */

#include <stddef.h>

/*
 * These constants match with kernel's pkey.h, enum pkey_key_type.
 */
#define ZPC_EC_KEY_TYPE_CCA                       0x1f
#define ZPC_EC_KEY_TYPE_EP11                      7

#define ZPC_EC_KEY_REENCIPHER_OLD_TO_CURRENT      1
#define ZPC_EC_KEY_REENCIPHER_CURRENT_TO_NEW      2

typedef enum {
	ZPC_EC_CURVE_NOT_SET = -2,
	ZPC_EC_CURVE_INVALID = -1,
	ZPC_EC_CURVE_P256 = 0,
	ZPC_EC_CURVE_P384,
	ZPC_EC_CURVE_P521,
	ZPC_EC_CURVE_ED25519,
	ZPC_EC_CURVE_ED448
} zpc_ec_curve_t;

struct zpc_ec_key;

/**
 * Allocate a new EC key object with reference count 1.
 * \param[in,out] key EC key
 * \return 0 on success. Otherwise, a non-zero error code is returned.
 */
__attribute__((visibility("default")))
int zpc_ec_key_alloc(struct zpc_ec_key **key);

/**
 * Set the EC curve.
 * \param[in,out] key EC key
 * \param[in] curve  EC curve
 * \return 0 on success. Otherwise, a non-zero error code is returned.
 */
__attribute__((visibility("default")))
int zpc_ec_key_set_curve(struct zpc_ec_key *key, zpc_ec_curve_t curve);

/**
 * Set the EC key type.
 * \param[in,out] key EC key
 * \param[in] type ZPC_EC_KEY_TYPE_CCA or  ZPC_EC_KEY_TYPE_EP11
 * \return 0 on success. Otherwise, a non-zero error code is returned.
 */
__attribute__((visibility("default")))
int zpc_ec_key_set_type(struct zpc_ec_key *key, int type);

/**
 * Set the EC key flags.
 * \param[in,out] key EC key
 * \param[in] flags key flags
 * \return 0 on success. Otherwise, a non-zero error code is returned.
 */
__attribute__((visibility("default")))
int zpc_ec_key_set_flags(struct zpc_ec_key *key, unsigned int flags);

/**
 * Set the EC key Master Key Verification Pattern.
 * \param[in,out] key EC key
 * \param[in] mkvp master key verification pattern (8 bytes for CCA keys, 16
 * or 32 bytes for EP11 keys, only the first 16 bytes are relevant)
 * \return 0 on success. Otherwise, a non-zero error code is returned.
 */
__attribute__((visibility("default")))
int zpc_ec_key_set_mkvp(struct zpc_ec_key *key, const char *mkvp);

/**
 * Set the EC key APQNs
 * \param[in,out] key EC key
 * \param[in] apqns NULL-terminated APQN list
 * \return 0 on success. Otherwise, a non-zero error code is returned.
 */
__attribute__((visibility("default")))
int zpc_ec_key_set_apqns(struct zpc_ec_key *key, const char *apqns[]);

/**
 * Import an EC secure-key. Depending on the key type (CCA or EP11), the secure
 * key buffer must contain either a CCA secure key token or an EP11 secure key
 * structure. For EP11 type keys, a SubjectPublicKeyInfo encoding (SPKI) of
 * the related public EC key may be appended to the secure key data.
 *
 * \param[in,out] key EC key
 * \param[in] seckey EC secure-key
 * \param[in] seckeylen EC key secure-length [bytes]
 * \return 0 on success. Otherwise, a non-zero error code is returned.
 */
__attribute__((visibility("default")))
int zpc_ec_key_import(struct zpc_ec_key *key, const unsigned char *seckey,
					unsigned int seckeylen);

/**
 * Import an EC clear-key pair. At least one of the key parts must be non-NULL.
 * A NULL key part leaves a previously set key part untouched, so it is e.g.
 * possible to first import a secure key using the zpc_ec_key_import()
 * function, and then adding the corresponding public key with a subsequent
 * zpc_ec_import_clear() call.
 * No integrity check is performed on the imported key material, except of a
 * plausibility check on the length of the provided key parts. The
 * application is responsible for providing valid key parts or pairs.
 * Public keys are considered to be the concatenated X and Y values without
 * a leading 0x04 byte that would indicate an uncompressed public key.
 * \param[in,out] key EC key
 * \param[in] pubkey an uncompressed EC public key (can be NULL)
 * \param[in] publen EC public key length [bytes]
 * \param[in] privkey EC private key (can be NULL)
 * \param[in] privlen EC private key length [bytes]
 * \return 0 on success. Otherwise, a non-zero error code is returned.
 */
__attribute__((visibility("default")))
int zpc_ec_key_import_clear(struct zpc_ec_key *key,
					const unsigned char *pubkey, unsigned int publen,
					const unsigned char *privkey, unsigned int privlen);

/**
 * Export an EC secure-key. Depending on the key type (CCA or EP11), the secure
 * key is either a CCA secure key token or an EP11 secure key structure. For
 * EP11 type keys, a SubjectPublicKeyInfo encoding (SPKI) of the related public
 * EC key is appended to the secure key data if the key object has a public key.
 *
 * \param[in,out] key EC key
 * \param[out] seckey EC secure-key
 * \param[in,out] seckeylen secure EC secure-key length [bytes]
 * \return 0 on success. Otherwise, a non-zero error code is returned.
 */
__attribute__((visibility("default")))
int zpc_ec_key_export(struct zpc_ec_key *key, unsigned char *seckey,
					unsigned int *seckeylen);

/**
 * Export an EC public-key.
 * \param[in,out] key EC key
 * \param[out] pubkey uncompressed EC public-key (can be NULL to obtain
 *             the length only)
 * The output buffer contains the concatenated X and Y values of the public key
 * without a leading byte indicating an uncompressed key.
 * \param[in,out] pubkeylen EC public-key length [bytes]
 * \return 0 on success. Otherwise, a non-zero error code is returned.
 */
__attribute__((visibility("default")))
int zpc_ec_key_export_public(struct zpc_ec_key *key, unsigned char *pubkey,
					unsigned int *pubkeylen);

/**
 * Generate an EC secure-key.
 * \param[in,out] key EC key
 * \return 0 on success. Otherwise, a non-zero error code is returned.
 */
__attribute__((visibility("default")))
int zpc_ec_key_generate(struct zpc_ec_key *key);

/**
 * Reencipher an EC secure-key.
 * \param[in,out] key EC key
 * \param[in] reenc ZPC_EC_KEY_REENCIPHER_OLD_TO_CURRENT
 *     or ZPC_EC_KEY_REENCIPHER_CURRENT_TO_NEW
 * \return 0 on success. Otherwise, a non-zero error code is returned.
 */
__attribute__((visibility("default")))
int zpc_ec_key_reencipher(struct zpc_ec_key *key, unsigned int reenc);

/**
 * Decrease the reference count of an EC key object
 * and free it the count reaches 0.
 * \param[in,out] key EC key
 */
__attribute__((visibility("default")))
void zpc_ec_key_free(struct zpc_ec_key **key);

# ifdef __cplusplus
/* *INDENT-OFF* */
}
/* *INDENT-ON* */
# endif
#endif
