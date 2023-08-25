/*
 * Copyright IBM Corp. 2021
 *
 * libzpc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef ZPC_AES_GCM_H
# define ZPC_AES_GCM_H
# ifdef __cplusplus
/* *INDENT-OFF* */
extern "C" {
/* *INDENT-ON* */
# endif

/**
 * \file zpc/aes_gcm.h
 * 
 * \brief AES-GCM API
 *
 * Authenticated encryption API for the Advanced Encryption Standard (AES)
 * block cipher \cite AES in Galois/Counter Mode mode of operation \cite GCM .
 */

# include <zpc/aes_key.h>
# include <stddef.h>

struct zpc_aes_gcm;

/**
 * Allocate a new context for an AES-GCM operation.
 * \param[in,out] ctx AES-GCM context
 * \return 0 on success. Otherwise, a non-zero error code is returned.
 */
__attribute__((visibility("default")))
int zpc_aes_gcm_alloc(struct zpc_aes_gcm **ctx);
/**
 * Set the key to be used in the context of an AES-GCM operation.
 * \param[in,out] ctx AES-GCM context
 * \param[in] key AES key
 * \return 0 on success. Otherwise, a non-zero error code is returned.
 */
__attribute__((visibility("default")))
int zpc_aes_gcm_set_key(struct zpc_aes_gcm *ctx, struct zpc_aes_key *key);
/**
 * Create the initialization vector to be used in the context
 * of an AES-GCM operation. The minimum and recommended iv length is 12 bytes.
 * \param[in,out] ctx AES-GCM context
 * \param[in/out] iv application provided buffer of at least ivlen bytes to
 * receive the internally created initialization vector
 * \param[in] ivlen initialization vector length [bytes]
 * \return 0 on success. Otherwise, a non-zero error code is returned.
 */
__attribute__((visibility("default")))
int zpc_aes_gcm_create_iv(struct zpc_aes_gcm *ctx, unsigned char *iv,
    size_t ivlen);
/**
 * Set the initialization vector to be used in the context
 * of an AES-GCM operation.
 * \param[in,out] ctx AES-GCM context
 * \param[in] iv initialization vector
 * \param[in] ivlen initialization vector length [bytes]
 * \return 0 on success. Otherwise, a non-zero error code is returned.
 */
__attribute__((visibility("default")))
int zpc_aes_gcm_set_iv(struct zpc_aes_gcm *ctx, const unsigned char *iv,
    size_t ivlen);
/**
 * Do an AES-GCM authenticated encryption operation.
 * \param[in,out] ctx AES-GCM context
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
int zpc_aes_gcm_encrypt(struct zpc_aes_gcm *ctx, unsigned char *ct,
    unsigned char *mac, size_t maclen, const unsigned char *aad, size_t aadlen,
    const unsigned char *pt, size_t ptlen);
/**
 * Do an AES-GCM authenticated decryption operation.
 * \param[in,out] ctx AES-GCM context
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
int zpc_aes_gcm_decrypt(struct zpc_aes_gcm *ctx, unsigned char *pt,
    const unsigned char *mac, size_t maclen, const unsigned char *aad,
    size_t aadlen, const unsigned char *ct, size_t ctlen);
/**
 * Free an AES-CCM context.
 * \param[in,out] ctx AES-GCM context
 */
__attribute__((visibility("default")))
void zpc_aes_gcm_free(struct zpc_aes_gcm **ctx);

# ifdef __cplusplus
/* *INDENT-OFF* */
}
/* *INDENT-ON* */
# endif
#endif
