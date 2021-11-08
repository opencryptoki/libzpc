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
 *
 * The context of a AES-CCM operation is stored in objects
 * of type struct zpc_aes_ccm.
 * Context objects must not be shared among multiple threads.
 * Context objects may be used for multiple operations by
 * (re)setting the key or iv.
 */

# include <zpc/aes_key.h>
# include <stddef.h>

struct zpc_aes_ccm;

/**
 * Allocate a new context object for an AES-CCM operation.
 *
 * \param[in,out] ctx AES-CCM context object
 * \return 0 on success. Otherwise, a non-zero error code is returned.
 */
__attribute__((visibility("default")))
int zpc_aes_ccm_alloc(struct zpc_aes_ccm **ctx);

/**
 * Set the key to be used in the context of an AES-CCM operation.
 *
 * If a key is already set, the reference count of that key object is
 * decremented.
 * The context's key reference is set to the key object argument.
 * If the key object argument is non-NULL, the reference count
 * of that key object is incremented.
 *
 * \param[in,out] ctx AES-CCM context object
 * \param[in] key AES key object
 * \return 0 on success. Otherwise, a non-zero error code is returned.
 */
__attribute__((visibility("default")))
int zpc_aes_ccm_set_key(struct zpc_aes_ccm *ctx, struct zpc_aes_key *key);

/**
 * Set the initialization vector to be used in the context
 * of an AES-CCM operation.
 *
 * \param[in,out] ctx AES-CCM context object
 * \param[in] iv 7-13 byte initialization vector
 * \param[in] ivlen initialization vector length [bytes]
 * \return 0 on success. Otherwise, a non-zero error code is returned.
 */
__attribute__((visibility("default")))
int zpc_aes_ccm_set_iv(struct zpc_aes_ccm *ctx, const unsigned char *iv,
    size_t ivlen);

/**
 * Encrypt a plaintext and sign the plaintext and additional data
 * using AES-CCM to obtain the corresponding ciphertext and
 * message authentication code.
 *
 * The ciphertext buffer must be large enough to store the resulting
 * ciphertext which has the same length as the plaintext.
 *
 * Plaintext and ciphertext buffer may be equal such that the operation
 * is done in-place. If the operation is not done in-place, plaintext and
 * ciphertext buffers must not overlap.
 *
 * \param[in,out] ctx AES-CCM context object
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
 * Decrypt a ciphertext verify the message authentication code of the
 * corresponding plaintext and additional data using AES-CCM.
 *
 * The plaintext buffer must be large enough to store the resulting
 * plaintext which has the same length as the ciphertext.
 *
 * Plaintext and ciphertext buffer may be equal such that the operation
 * is done in-place. If the operation is not done in-place, plaintext and
 * ciphertext buffers must not overlap.
 *
 * \param[in,out] ctx AES-CCM context object
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
 * Free an AES-CCM context object.
 *
 * If a key is set, the reference count of that key object is decremented.
 * The context object argument is set to NULL.
 *
 * \param[in,out] ctx AES-CCM context object
 */
__attribute__((visibility("default")))
void zpc_aes_ccm_free(struct zpc_aes_ccm **ctx);

# ifdef __cplusplus
/* *INDENT-OFF* */
}
/* *INDENT-ON* */
# endif
#endif
