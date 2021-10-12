/*
 * Copyright IBM Corp. 2021
 *
 * libzpc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef ZPC_AES_CCM_H
# define ZPC_AES_CCM_H
# ifdef __cplusplus
/* *INDENT-OFF* */
extern "C" {
/* *INDENT-ON* */
# endif

/**
 * \file zpc/aes_ccm.h
 * 
 * \brief AES-CCM API
 * 
 * Authenticated encryption API for the Advanced Encryption Standard (AES)
 * block cipher \cite AES in Counter with CBC-MAC mode of operation \cite CCM .
 */

# include <zpc/aes_key.h>
# include <stddef.h>

struct zpc_aes_ccm;

/**
 * Allocate a new context for an AES-CCM operation.
 * \param[in,out] ctx AES-CCM context
 * \return 0 on success. Otherwise, a non-zero error code is returned.
 */
__attribute__((visibility("default")))
int zpc_aes_ccm_alloc(struct zpc_aes_ccm **ctx);
/**
 * Set the key to be used in the context of an AES-CCM operation.
 * \param[in,out] ctx AES-CCM context
 * \param[in] key AES key
 * \return 0 on success. Otherwise, a non-zero error code is returned.
 */
__attribute__((visibility("default")))
int zpc_aes_ccm_set_key(struct zpc_aes_ccm *ctx, struct zpc_aes_key *key);
/**
 * Set the initialization vector to be used in the context
 * of an AES-CCM operation.
 * \param[in,out] ctx AES-CCM context
 * \param[in] iv 7-13 byte initialization vector
 * \param[in] ivlen initialization vector length [bytes]
 * \return 0 on success. Otherwise, a non-zero error code is returned.
 */
__attribute__((visibility("default")))
int zpc_aes_ccm_set_iv(struct zpc_aes_ccm *ctx, const unsigned char *iv,
    size_t ivlen);
/**
 * Do an AES-CCM authenticated encryption operation.
 * \param[in,out] ctx AES-CCM context
 * \param[out] ct ciphertext
 * \param[out] mac message authentication code
 * \param[in] maclen message authentication code length [bytes]
 * \param[in] aad additional authenticated data
 * \param[in] aadlen additional authenticated data length [bytes]
 * \param[in] pt plaintext
 * \param[in] ptlen plaintext length [bytes]
 * \return 0 on success. Otherwise, a non-zero error code is returned.
 */
__attribute__((visibility("default")))
int zpc_aes_ccm_encrypt(struct zpc_aes_ccm *ctx, unsigned char *ct,
    unsigned char *mac, size_t maclen, const unsigned char *aad, size_t aadlen,
    const unsigned char *pt, size_t ptlen);
/**
 * Do an AES-CCM authenticated decryption operation.
 * \param[in,out] ctx AES-CCM context
 * \param[out] pt plaintext
 * \param[in] mac message authentication code
 * \param[in] maclen message authentication code length [bytes]
 * \param[in] aad additional authenticated data
 * \param[in] aadlen additional authenticated data length [bytes]
 * \param[in] ct ciphertext
 * \param[in] ctlen ciphertext length [bytes]
 * \return 0 on success. Otherwise, a non-zero error code is returned.
 */
__attribute__((visibility("default")))
int zpc_aes_ccm_decrypt(struct zpc_aes_ccm *ctx, unsigned char *pt,
    const unsigned char *mac, size_t maclen, const unsigned char *aad,
    size_t aadlen, const unsigned char *ct, size_t ctlen);
/**
 * Free an AES-CCM context.
 * \param[in,out] ctx AES-CCM context
 */
__attribute__((visibility("default")))
void zpc_aes_ccm_free(struct zpc_aes_ccm **ctx);

# ifdef __cplusplus
/* *INDENT-OFF* */
}
/* *INDENT-ON* */
# endif
#endif
