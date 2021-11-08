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
 *
 * The context of a AES-GCM operation is stored in objects
 * of type struct zpc_aes_gcm.
 * Context objects must not be shared among multiple threads.
 * Context objects may be used for multiple operations by
 * (re)setting the key or iv.
 */

# include <zpc/aes_key.h>
# include <stddef.h>

struct zpc_aes_gcm;

/**
 * Allocate a new context object for an AES-GCM operation.
 *
 * \param[in,out] ctx AES-GCM context object
 * \return 0 on success. Otherwise, a non-zero error code is returned.
 */
__attribute__((visibility("default")))
int zpc_aes_gcm_alloc(struct zpc_aes_gcm **ctx);

/**
 * Set the key to be used in the context object of an AES-GCM operation.
 *
 * If a key is already set, the reference count of that key object is
 * decremented.
 * The context's key reference is set to the key object argument.
 * If the key object argument is non-NULL, the reference count
 * of that key object is incremented.
 *
 * \param[in,out] ctx AES-GCM context object
 * \param[in] key AES key object
 * \return 0 on success. Otherwise, a non-zero error code is returned.
 */
__attribute__((visibility("default")))
int zpc_aes_gcm_set_key(struct zpc_aes_gcm *ctx, struct zpc_aes_key *key);

/**
 * Set the initialization vector to be used in the context
 * of an AES-GCM operation.
 *
 * \param[in,out] ctx AES-GCM context object
 * \param[in] iv initialization vector
 * \param[in] ivlen initialization vector length [bytes]
 * \return 0 on success. Otherwise, a non-zero error code is returned.
 */
__attribute__((visibility("default")))
int zpc_aes_gcm_set_iv(struct zpc_aes_gcm *ctx, const unsigned char *iv,
    size_t ivlen);

/**
 * Encrypt a plaintext and sign the ciphertext and additional data
 * using AES-GCM to obtain the corresponding ciphertext and
 * message authentication code. If there is no plaintext input,
 * the operation corresponds to AES-GMAC.
 *
 * The ciphertext buffer must be large enough to store the resulting
 * ciphertext which has the same length as the plaintext.
 *
 * Plaintext and ciphertext buffer may be equal such that the operation
 * is done in-place. If the operation is not done in-place, plaintext and
 * ciphertext buffers must not overlap.
 *
 * Additional data and plaintext may be encrypted and authenticated
 * chunkwise.
 * The additional data must be processed first. All chunk-lengths
 * except the last one must be a multiple of 16 bytes. The
 * plaintext and message authentication code arguments must be
 * NULL when processing those non-final chunks.
 * A chunk-length that is not a multiple of 16 bytes, a non-NULL
 * plaintext argument or a non-NULL message authentication code
 * argument indicate the end of the additional date,
 * The plaintext must be processed second. All chunk-lengths
 * except the last one must be a multiple of 16 bytes. The
 * message autentication code argument must be NULL when processing
 * those non-final chunks.
 * A chunk-length that is not a multiple of 16 bytes or a non-NULL
 * message authentication code argument indicate the end of the
 * plaintext.
 * The same context object must be used to process all chunks without
 * modifying it in between operations.
 *
 * \param[in,out] ctx AES-GCM context object
 * \param[out] ct ciphertext buffer
 * \param[out] mac message authentication code
 * \param[in] maclen message authentication code length [bytes]
 * \param[in] aad additional authenticated data buffer
 * \param[in] aadlen additional authenticated data length [bytes]
 * \param[in] pt plaintext buffer
 * \param[in] ptlen plaintext length [bytes]
 * \return 0 on success. Otherwise, a non-zero error code is returned.
 */
__attribute__((visibility("default")))
int zpc_aes_gcm_encrypt(struct zpc_aes_gcm *ctx, unsigned char *ct,
    unsigned char *mac, size_t maclen, const unsigned char *aad, size_t aadlen,
    const unsigned char *pt, size_t ptlen);

/**
 * Decrypt a ciphertext to obtain the corresponding plaintext and
 * verify the message authentication code of the ciphertext and additional
 * data using AES-GCM. If there is no ciphertext input, the operation
 * corresponds to AES-GMAC.
 *
 * The plaintext buffer must be large enough to store the resulting
 * plaintext which has the same length as the ciphertext.
 *
 * Plaintext and ciphertext buffer may be equal such that the operation
 * is done in-place. If the operation is not done in-place, plaintext and
 * ciphertext buffers must not overlap.
 *
 * Additional data and ciphertext may be decrypted and authenticated
 * chunkwise.
 * The additional data must be processed first. All chunk-lengths
 * except the last one must be a multiple of 16 bytes. The
 * ciphertext and message authentication code arguments must be
 * NULL when processing those non-final chunks.
 * A chunk-length that is not a multiple of 16 bytes, a non-NULL
 * ciphertext argument or a non-NULL message authentication code
 * argument indicate the end of the additional date,
 * The ciphertext must be processed second. All chunk-lengths
 * except the last one must be a multiple of 16 bytes. The
 * message autentication code argument must be NULL when processing
 * those non-final chunks.
 * A chunk-length that is not a multiple of 16 bytes or a non-NULL
 * message authentication code argument indicate the end of the
 * ciphertext.
 * The same context object must be used to process all chunks without
 * modifying it in between operations.
 *
 * \param[in,out] ctx AES-GCM context object
 * \param[out] pt plaintext buffer
 * \param[in] mac message authentication code buffer
 * \param[in] maclen message authentication code length [bytes]
 * \param[in] aad additional authenticated data buffer
 * \param[in] aadlen additional authenticated data length [bytes]
 * \param[in] ct ciphertext buffer
 * \param[in] ctlen ciphertext length [bytes]
 * \return 0 on success. Otherwise, a non-zero error code is returned.
 */
__attribute__((visibility("default")))
int zpc_aes_gcm_decrypt(struct zpc_aes_gcm *ctx, unsigned char *pt,
    const unsigned char *mac, size_t maclen, const unsigned char *aad,
    size_t aadlen, const unsigned char *ct, size_t ctlen);

/**
 * Free an AES-GCM context object.
 *
 * If a key is set, the reference count of that key object is decremented.
 * The context object argument is set to NULL.
 *
 * \param[in,out] ctx AES-GCM context object
 */
__attribute__((visibility("default")))
void zpc_aes_gcm_free(struct zpc_aes_gcm **ctx);

# ifdef __cplusplus
/* *INDENT-OFF* */
}
/* *INDENT-ON* */
# endif
#endif
