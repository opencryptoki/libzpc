/*
 * Copyright IBM Corp. 2021
 *
 * libzpc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef ZPC_AES_ECB_H
# define ZPC_AES_ECB_H
# ifdef __cplusplus
/* *INDENT-OFF* */
extern "C" {
/* *INDENT-ON* */
# endif

/**
 * \file zpc/aes_ecb.h
 * 
 * \brief AES-ECB API
 *
 * Encryption API for the Advanced Encryption Standard (AES)
 * block cipher \cite AES in Electronic Code Book (ECB)
 * mode of operation \cite MODES .
 */

# include <zpc/aes_key.h>
# include <stddef.h>

struct zpc_aes_ecb;

/**
 * Allocate a new context for an AES-ECB operation.
 * \param[in,out] ctx AES-ECB context
 * \return 0 on success. Otherwise, a non-zero error code is returned.
 */
__attribute__((visibility("default")))
int zpc_aes_ecb_alloc(struct zpc_aes_ecb **ctx);
/**
 * Set the key to be used in the context of an AES-ECB operation.
 * \param[in,out] ctx AES-ECB context
 * \param[in] key AES key
 * \return 0 on success. Otherwise, a non-zero error code is returned.
 */
__attribute__((visibility("default")))
int zpc_aes_ecb_set_key(struct zpc_aes_ecb *ctx, struct zpc_aes_key *key);
/**
 * Do an AES-ECB encryption operation.
 * \param[in,out] ctx AES-ECB context
 * \param[out] ct ciphertext
 * \param[in] pt plaintext
 * \param[in] ptlen plaintext length [bytes]
 * \return 0 on success. Otherwise, a non-zero error code is returned.
 */
__attribute__((visibility("default")))
int zpc_aes_ecb_encrypt(struct zpc_aes_ecb *ctx, unsigned char *ct,
    const unsigned char *pt, size_t ptlen);
/**
 * Do an AES-ECB decryption operation.
 * \param[in,out] ctx AES-ECB context
 * \param[out] pt plaintext
 * \param[in] ct ciphertext
 * \param[in] ctlen ciphertext length [bytes]
 * \return 0 on success. Otherwise, a non-zero error code is returned.
 */
__attribute__((visibility("default")))
int zpc_aes_ecb_decrypt(struct zpc_aes_ecb *ctx, unsigned char *pt,
    const unsigned char *ct, size_t ctlen);
/**
 * Free an AES-ECB context.
 * \param[in,out] ctx AES-ECB context
 */
__attribute__((visibility("default")))
void zpc_aes_ecb_free(struct zpc_aes_ecb **ctx);

# ifdef __cplusplus
/* *INDENT-OFF* */
}
/* *INDENT-ON* */
# endif
#endif
