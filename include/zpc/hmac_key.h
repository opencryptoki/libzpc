/*
 * Copyright IBM Corp. 2025
 *
 * libzpc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef ZPC_HMAC_KEY_H
# define ZPC_HMAC_KEY_H
# ifdef __cplusplus
/* *INDENT-OFF* */
extern "C" {
/* *INDENT-ON* */
# endif

/**
 * \file zpc/hmac_key.h
 * \brief HMAC key API.
 * 
 * Manage
 * \cite HMAC keys.
 */

# include <stddef.h>

/*
 * These constants match with kernel's pkey.h, enum pkey_key_type.
 */
# define ZPC_HMAC_KEY_TYPE_PVSECRET        9

typedef enum {
	ZPC_HMAC_SECRET_TYPE_NOT_SET = -2,
	ZPC_HMAC_SECRET_TYPE_INVALID = -1,
	ZPC_HMAC_SECRET_HMAC_SHA_256 = 0x09, /* architected key types, also below */
	ZPC_HMAC_SECRET_HMAC_SHA_512 = 0x0a,
} zpc_hmacsecret_type_t;

typedef enum {
	ZPC_HMAC_HASHFUNC_NOT_SET = -2,
	ZPC_HMAC_HASHFUNC_INVALID = -1,
	ZPC_HMAC_HASHFUNC_SHA_224 = 0,
	ZPC_HMAC_HASHFUNC_SHA_256,
	ZPC_HMAC_HASHFUNC_SHA_384,
	ZPC_HMAC_HASHFUNC_SHA_512,
} zpc_hmac_hashfunc_t;

struct zpc_hmac_key;

/**
 * Allocate a new HMAC key object with reference count 1.
 * \param[in,out] key HMAC key
 * \return 0 on success. Otherwise, a non-zero error code is returned.
 */
__attribute__((visibility("default")))
int zpc_hmac_key_alloc(struct zpc_hmac_key **key);
/**
 * Set the HMAC key type.
 * \param[in,out] key HMAC key
 * \param[in] type currently only one type ZPC_HMAC_KEY_TYPE_PVSECRET is
 * supported.
 * \return 0 on success. Otherwise, a non-zero error code is returned.
 */
__attribute__((visibility("default")))
int zpc_hmac_key_set_type(struct zpc_hmac_key *key, int type);
/**
 * Set the hash function to be used in the context of an HMAC operation.
 * \param[in,out] key HMAC key
 * \param[in] func HMAC hash function
 * The size of the HMAC key (64 bytes or 128 bytes) is given by the block size
 * of the hash function: for sha224 and sha256, the key size is set to 64 bytes,
 * for sha384 and sha512, the key size is set to 128 bytes.
 * \return 0 on success. Otherwise, a non-zero error code is returned.
 */
__attribute__((visibility("default")))
int zpc_hmac_key_set_hash_function(struct zpc_hmac_key *key, zpc_hmac_hashfunc_t func);
/**
 * Import an HMAC protected key origin (secure key or retrievable secret ID).
 * \param[in,out] key HMAC key
 * \param[in] origin HMAC protected key origin
 * \param[in] originlen HMAC key origin length [bytes]
 * \return 0 on success. Otherwise, a non-zero error code is returned.
 */
__attribute__((visibility("default")))
int zpc_hmac_key_import(struct zpc_hmac_key *key, const unsigned char *origin,
    size_t originlen);
/**
 * Import an HMAC clear-key.
 * \param[in,out] key HMAC key
 * \param[in] clrkey HMAC clear-key
 * \param[in] keylen HMAC clear-key size [bytes]
 * \return 0 on success. Otherwise, a non-zero error code is returned.
 */
__attribute__((visibility("default")))
int zpc_hmac_key_import_clear(struct zpc_hmac_key *key,
    const unsigned char *clrkey, size_t keylen);
/**
 * Export an HMAC protected key origin (secure key or retrievable secret ID).
 * \param[in,out] key HMAC key
 * \param[out] origin HMAC protected key origin
 * \param[in,out] originlen origin length [bytes]
 * \return 0 on success. Otherwise, a non-zero error code is returned.
 */
__attribute__((visibility("default")))
int zpc_hmac_key_export(struct zpc_hmac_key *key, unsigned char *origin,
    size_t *originlen);
/**
 * Generate a random HMAC protected-key.
 * \param[in,out] key HMAC key
 * \return 0 on success. Otherwise, a non-zero error code is returned.
 */
__attribute__((visibility("default")))
int zpc_hmac_key_generate(struct zpc_hmac_key *key);
/**
 * Decrease the reference count of an HMAC key object
 * and free it the count reaches 0.
 * \param[in,out] key HMAC key
 */
__attribute__((visibility("default")))
void zpc_hmac_key_free(struct zpc_hmac_key **key);

# ifdef __cplusplus
/* *INDENT-OFF* */
}
/* *INDENT-ON* */
# endif
#endif
