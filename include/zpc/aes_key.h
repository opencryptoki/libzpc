/*
 * Copyright IBM Corp. 2021
 *
 * libzpc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef ZPC_AES_KEY_H
# define ZPC_AES_KEY_H
# ifdef __cplusplus
/* *INDENT-OFF* */
extern "C" {
/* *INDENT-ON* */
# endif

/**
 * \file zpc/aes_key.h
 * \brief AES key API.
 * 
 * Manage advanced Encryption Standard (AES) block cipher
 * \cite AES keys.
 */

# include <stddef.h>

/*
 * These constants match with kernel's pkey.h, enum pkey_key_type.
 */
# define ZPC_AES_KEY_TYPE_CCA_DATA     1
# define ZPC_AES_KEY_TYPE_CCA_CIPHER   2
# define ZPC_AES_KEY_TYPE_EP11         3

# define ZPC_AES_KEY_REENCIPHER_OLD_TO_CURRENT    1
# define ZPC_AES_KEY_REENCIPHER_CURRENT_TO_NEW    2

struct zpc_aes_key;

/**
 * Allocate a new AES key object with reference count 1.
 * \param[in,out] key AES key
 * \return 0 on success. Otherwise, a non-zero error code is returned.
 */
__attribute__((visibility("default")))
int zpc_aes_key_alloc(struct zpc_aes_key **key);
/**
 * Set the AES key size. 
 * \param[in,out] key AES key
 * \param[in] size 128, 192 or 256 bit key size
 * \return 0 on success. Otherwise, a non-zero error code is returned.
 */
__attribute__((visibility("default")))
int zpc_aes_key_set_size(struct zpc_aes_key *key, int size);
/**
 * Set the AES key type. 
 * \param[in,out] key AES key
 * \param[in] type ZPC_AES_KEY_TYPE_CCA_DATA, ZPC_AES_KEY_TYPE_CCA_CIPHER
 *     or  ZPC_AES_KEY_TYPE_EP11
 * \return 0 on success. Otherwise, a non-zero error code is returned.
 */
__attribute__((visibility("default")))
int zpc_aes_key_set_type(struct zpc_aes_key *key, int type);
/**
 * Set the AES key flags. 
 * \param[in,out] key AES key
 * \param[in] flags key flags
 * \return 0 on success. Otherwise, a non-zero error code is returned.
 */
__attribute__((visibility("default")))
int zpc_aes_key_set_flags(struct zpc_aes_key *key, unsigned int flags);
/**
 * Set the AES key Master Key Verification Pattern. 
 * \param[in,out] key AES key
 * \param[in] mkvp master key verification pattern
 * \return 0 on success. Otherwise, a non-zero error code is returned.
 */
__attribute__((visibility("default")))
int zpc_aes_key_set_mkvp(struct zpc_aes_key *key, const char *mkvp);
/**
 * Set the AES key APQNs 
 * \param[in,out] key AES key
 * \param[in] apqns NULL-terminated APQN list
 * \return 0 on success. Otherwise, a non-zero error code is returned.
 */
__attribute__((visibility("default")))
int zpc_aes_key_set_apqns(struct zpc_aes_key *key, const char *apqns[]);
/**
 * Import an AES secure-key.
 * \param[in,out] key AES key
 * \param[in] seckey AES secure-key
 * \param[in] seckeylen AES key secure-length [bytes]
 * \return 0 on success. Otherwise, a non-zero error code is returned.
 */
__attribute__((visibility("default")))
int zpc_aes_key_import(struct zpc_aes_key *key, const unsigned char *seckey,
    size_t seckeylen);
/**
 * Import an AES clear-key.
 * \param[in,out] key AES key
 * \param[in] clearkey AES clear-key
 * \return 0 on success. Otherwise, a non-zero error code is returned.
 */
__attribute__((visibility("default")))
int zpc_aes_key_import_clear(struct zpc_aes_key *key,
    const unsigned char *clrkey);
/**
 * Export an AES secure-key.
 * \param[in,out] key AES key
 * \param[out] seckey AES secure-key
 * \param[in,out] seckeylen secure AES secure-key length [bytes]
 * \return 0 on success. Otherwise, a non-zero error code is returned.
 */
__attribute__((visibility("default")))
int zpc_aes_key_export(struct zpc_aes_key *key, unsigned char *seckey,
    size_t *seckeylen);
/**
 * Generate an AES secure-key.
 * \param[in,out] key AES key
 * \return 0 on success. Otherwise, a non-zero error code is returned.
 */
__attribute__((visibility("default")))
int zpc_aes_key_generate(struct zpc_aes_key *key);
/**
 * Reencipher an AES secure-key.
 * \param[in,out] key AES key
 * \param[in] reenc ZPC_AES_KEY_REENCIPHER_OLD_TO_CURRENT
 *     or ZPC_AES_KEY_REENCIPHER_CURRENT_TO_NEW
 * \return 0 on success. Otherwise, a non-zero error code is returned.
 */
__attribute__((visibility("default")))
int zpc_aes_key_reencipher(struct zpc_aes_key *key, int reenc);
/**
 * Decrease the reference count of an AES key object
 * and free it the count reaches 0.
 * \param[in,out] key AES key
 */
__attribute__((visibility("default")))
void zpc_aes_key_free(struct zpc_aes_key **key);

# ifdef __cplusplus
/* *INDENT-OFF* */
}
/* *INDENT-ON* */
# endif
#endif
