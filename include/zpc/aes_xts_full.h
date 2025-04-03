/*
 * Copyright IBM Corp. 2025
 *
 * libzpc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef ZPC_AES_XTS_FULL_H
# define ZPC_AES_XTS_FULL_H

# ifdef __cplusplus
/* *INDENT-OFF* */
extern "C" {
/* *INDENT-ON* */
# endif

/**
 * \file zpc/aes_xts_full.h
 * 
 * \brief AES-XTS-FULL API
 *
 * Encryption API for the Advanced Encryption Standard (AES)
 * block cipher \cite AES in XEX-based Tweaked-codebook mode with
 * ciphertext Stealing (XTS) mode of operation \cite XTS .
 *
 * In contrast to the AES-XTS API, the AES-XTS-FULL API uses full-xts
 * protected keys containing two single AES keys in one single protected key.
 * This feature requires MSA 10.
 */

# include "aes_xts_key.h"
# include <stddef.h>

struct zpc_aes_xts_full;

/**
 * Allocate a new context for an AES-XTS operation to be used with an AES
 * full-xts key object..
 * \param[in,out] ctx AES-FULL-XTS context
 * \return 0 on success. Otherwise, a non-zero error code is returned.
 */
__attribute__((visibility("default")))
int zpc_aes_xts_full_alloc(struct zpc_aes_xts_full **ctx);
/**
 * Set the AES full-xts key to be used in the context of an AES-XTS operation.
 * \param[in,out] ctx AES-FULL-XTS context
 * \param[in] key full-xts key
 * \return 0 on success. Otherwise, a non-zero error code is returned.
 */
__attribute__((visibility("default")))
int zpc_aes_xts_full_set_key(struct zpc_aes_xts_full *ctx, struct zpc_aes_xts_key *key);
/**
 * Set the initialization vector to be used in the context
 * of an AES-XTS operation.
 * \param[in,out] ctx AES-FULL-XTS context
 * \param[in] iv 16 byte initialization vector
 * \return 0 on success. Otherwise, a non-zero error code is returned.
 */
__attribute__((visibility("default")))
int zpc_aes_xts_full_set_iv(struct zpc_aes_xts_full *ctx, const unsigned char *iv);
/**
 * Get the intermediate state information used in the context
 * of an AES-XTS operation.
 * \param[in,out] ctx AES-FULL-XTS context
 * \param[out] state application provided buffer with 32 bytes size to
 * receive the 32 byte intermediate state information.
 * \return 0 on success. Otherwise, a non-zero error code is returned.
 */
__attribute__((visibility("default")))
int zpc_aes_xts_full_export(struct zpc_aes_xts_full *ctx, unsigned char state[32]);
/**
 * Set the intermediate state information to be used in the context
 * of an AES-XTS operation.
 * \param[in,out] ctx AES-FULL-XTS context
 * \param[in] state 32 byte intermediate state information as
 * obtained via zpc_aes_xts_full_export().
 * \return 0 on success. Otherwise, a non-zero error code is returned.
 */
__attribute__((visibility("default")))
int zpc_aes_xts_full_import(struct zpc_aes_xts_full *ctx, const unsigned char state[32]);
/**
 * Do an AES-XTS encryption operation.
 * \param[in,out] ctx AES-FULL-XTS context
 * \param[out] ct ciphertext
 * \param[in] pt plaintext
 * \param[in] ptlen plaintext length [bytes]
 * \return 0 on success. Otherwise, a non-zero error code is returned.
 */
__attribute__((visibility("default")))
int zpc_aes_xts_full_encrypt(struct zpc_aes_xts_full *ctx, unsigned char *ct,
    const unsigned char *pt, size_t ptlen);
/**
 * Do an AES-XTS decryption operation.
 * \param[in,out] ctx AES-FULL-XTS context
 * \param[out] pt plaintext
 * \param[in] ct ciphertext
 * \param[in] ctlen ciphertext length [bytes]
 * \return 0 on success. Otherwise, a non-zero error code is returned.
 */
__attribute__((visibility("default")))
int zpc_aes_xts_full_decrypt(struct zpc_aes_xts_full *ctx, unsigned char *pt,
    const unsigned char *ct, size_t ctlen);
/**
 * Free an AES-FULL-XTS context.
 * \param[in,out] ctx AES-FULL-XTS context
 */
__attribute__((visibility("default")))
void zpc_aes_xts_full_free(struct zpc_aes_xts_full **ctx);

# ifdef __cplusplus
/* *INDENT-OFF* */
}
/* *INDENT-ON* */
# endif
#endif
