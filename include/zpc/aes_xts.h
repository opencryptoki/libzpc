/*
 * Copyright IBM Corp. 2021
 *
 * libzpc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef ZPC_AES_XTS_H
# define ZPC_AES_XTS_H
# ifdef __cplusplus
/* *INDENT-OFF* */
extern "C" {
/* *INDENT-ON* */
# endif

/**
 * \file zpc/aes_xts.h
 * 
 * \brief AES-XTS API
 *
 * Encryption API for the Advanced Encryption Standard (AES)
 * block cipher \cite AES in XEX-based Tweaked-codebook mode with
 * ciphertext Stealing (XTS) mode of operation \cite XTS .
 */

# include <zpc/aes_key.h>
# include <stddef.h>

struct zpc_aes_xts;

/**
 * Allocate a new context for an AES-XTS operation.
 * \param[in,out] ctx AES-XTS context
 * \return 0 on success. Otherwise, a non-zero error code is returned.
 */
__attribute__((visibility("default")))
int zpc_aes_xts_alloc(struct zpc_aes_xts **ctx);
/**
 * Set the key to be used in the context of an AES-XTS operation.
 * \param[in,out] ctx AES-XTS context
 * \param[in] key1 first AES key
 * \param[in] key2 second AES key
 * \return 0 on success. Otherwise, a non-zero error code is returned.
 */
__attribute__((visibility("default")))
int zpc_aes_xts_set_key(struct zpc_aes_xts *ctx, struct zpc_aes_key *key1,
    struct zpc_aes_key *key2);
/**
 * Set the initialization vector to be used in the context
 * of an AES-XTS operation.
 * \param[in,out] ctx AES-XTS context
 * \param[in] iv 16 byte initialization vector
 * \return 0 on success. Otherwise, a non-zero error code is returned.
 */
__attribute__((visibility("default")))
int zpc_aes_xts_set_iv(struct zpc_aes_xts *ctx, const unsigned char *iv);
/**
 * Do an AES-XTS encryption operation.
 * \param[in,out] ctx AES-XTS context
 * \param[out] ct ciphertext
 * \param[in] pt plaintext
 * \param[in] ptlen plaintext length [bytes]
 * \return 0 on success. Otherwise, a non-zero error code is returned.
 */
__attribute__((visibility("default")))
int zpc_aes_xts_encrypt(struct zpc_aes_xts *ctx, unsigned char *ct,
    const unsigned char *pt, size_t ptlen);
/**
 * Do an AES-XTS decryption operation.
 * \param[in,out] ctx AES-XTS context
 * \param[out] pt plaintext
 * \param[in] ct ciphertext
 * \param[in] ctlen ciphertext length [bytes]
 * \return 0 on success. Otherwise, a non-zero error code is returned.
 */
__attribute__((visibility("default")))
int zpc_aes_xts_decrypt(struct zpc_aes_xts *ctx, unsigned char *pt,
    const unsigned char *ct, size_t ctlen);
/**
 * Free an AES-XTS context.
 * \param[in,out] ctx AES-XTS context
 */
__attribute__((visibility("default")))
void zpc_aes_xts_free(struct zpc_aes_xts **ctx);

# ifdef __cplusplus
/* *INDENT-OFF* */
}
/* *INDENT-ON* */
# endif
#endif
