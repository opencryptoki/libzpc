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
 *
 * The context of a AES-XTS operation is stored in objects
 * of type struct zpc_aes_xts.
 * Context objects must not be shared among multiple threads.
 * Context objects may be used for multiple operations by
 * (re)setting the key.
 */

# include <zpc/aes_key.h>
# include <stddef.h>

struct zpc_aes_xts;

/**
 * Allocate a new context object for an AES-XTS operation.
 *
 * \param[in,out] ctx AES-XTS context object
 * \return 0 on success. Otherwise, a non-zero error code is returned.
 */
__attribute__((visibility("default")))
int zpc_aes_xts_alloc(struct zpc_aes_xts **ctx);

/**
 * Set the key to be used in the context of an AES-XTS operation.
 *
 * If a key is already set, the reference count of that key object is
 * decremented.
 * The context's key reference is set to the key object argument.
 * If the key object argument is non-NULL, the reference count
 * of that key object is incremented.
 *
 * \param[in,out] ctx AES-XTS context object
 * \param[in] key1 first AES key object
 * \param[in] key2 second AES key object
 * \return 0 on success. Otherwise, a non-zero error code is returned.
 */
__attribute__((visibility("default")))
int zpc_aes_xts_set_key(struct zpc_aes_xts *ctx, struct zpc_aes_key *key1,
    struct zpc_aes_key *key2);

/**
 * Set the initialization vector to be used in the context
 * of an AES-XTS operation.
 *
 * \param[in,out] ctx AES-XTS context
 * \param[in] iv 16 byte initialization vector
 * \return 0 on success. Otherwise, a non-zero error code is returned.
 */
__attribute__((visibility("default")))
int zpc_aes_xts_set_iv(struct zpc_aes_xts *ctx, const unsigned char *iv);

/**
 * Encrypt a plaintext using AES-XTS to obtain the corresponding
 * ciphertext.
 *
 * The ciphertext buffer must be large enough to store the resulting
 * ciphertext which has the same length as the (padded) plaintext.
 *
 * Plaintext and ciphertext buffer may be equal such that the operation
 * is done in-place. If the operation is not done in-place, plaintext and
 * ciphertext buffers must not overlap.
 *
 * A plaintext may be encrypted chunkwise. For every operation on a
 * plaintext chunk, the same rules apply as for the one-shot encryption.
 * All chunk-lengths except the final one must be a multiple of 16 bytes.
 * The same context object must be used to encrypt all chunks without
 * modifying it in between operations.
 *
 * \param[in,out] ctx AES-XTS context object
 * \param[out] ct ciphertext buffer
 * \param[in] pt plaintext buffer
 * \param[in] ptlen plaintext length [bytes]
 * \return 0 on success. Otherwise, a non-zero error code is returned.
 */
__attribute__((visibility("default")))
int zpc_aes_xts_encrypt(struct zpc_aes_xts *ctx, unsigned char *ct,
    const unsigned char *pt, size_t ptlen);

/**
 * Decrypt a ciphertext using AES-XTS to obtain the corresponding
 * plaintext.
 *
 * The plaintext buffer must be large enough to store the resulting
 * plaintext which has the same length as the ciphertext.
 *
 * Plaintext and ciphertext buffer may be equal such that the operation
 * is done in-place. If the operation is not done in-place, plaintext and
 * ciphertext buffers must not overlap.
 *
 * A ciphertext may be decrypted chunkwise. For every operation on a
 * ciphertext chunk, the same rules apply as for the one-shot decryption.
 * All chunk-lengths except the final one must be a multiple of 16 bytes.
 * The same context object must be used to decrypt all chunks without
 * modifying it in between operations.
 *
 * \param[in,out] ctx AES-XTS context object
 * \param[out] pt plaintext buffer
 * \param[in] ct ciphertext buffer
 * \param[in] ctlen ciphertext length [bytes]
 * \return 0 on success. Otherwise, a non-zero error code is returned.
 */
__attribute__((visibility("default")))
int zpc_aes_xts_decrypt(struct zpc_aes_xts *ctx, unsigned char *pt,
    const unsigned char *ct, size_t ctlen);

/**
 * Free an AES-XTS context object.
 *
 * If a key is set, the reference count of that key object is decremented.
 * The context object argument is set to NULL.
 *
 * \param[in,out] ctx AES-XTS context object
 */
__attribute__((visibility("default")))
void zpc_aes_xts_free(struct zpc_aes_xts **ctx);

# ifdef __cplusplus
/* *INDENT-OFF* */
}
/* *INDENT-ON* */
# endif
#endif
