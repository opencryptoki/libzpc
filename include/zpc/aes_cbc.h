/*
 * Copyright IBM Corp. 2021
 *
 * libzpc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef ZPC_AES_CBC_H
# define ZPC_AES_CBC_H
# ifdef __cplusplus
/* *INDENT-OFF* */
extern "C" {
/* *INDENT-ON* */
# endif

/**
 * \file zpc/aes_cbc.h
 * 
 * \brief AES-CBC API
 *
 * Encryption API for the Advanced Encryption Standard (AES)
 * block cipher \cite AES in Cipher Block Chaining (CBC)
 * mode of operation \cite MODES .
 *
 * The context of a AES-CBC operation is stored in objects
 * of type struct zpc_aes_cbc.
 * Context objects must not be shared among multiple threads.
 * Context objects may be used for multiple operations by
 * (re)setting the key or iv.
 */

# include <zpc/aes_key.h>
# include <stddef.h>

struct zpc_aes_cbc;

/**
 * Allocate a new context object for an AES-CBC operation.
 *
 * \param[in,out] ctx AES-CBC context object
 * \return 0 on success. Otherwise, a non-zero error code is returned.
 */
__attribute__((visibility("default")))
int zpc_aes_cbc_alloc(struct zpc_aes_cbc **ctx);

/**
 * Set the key to be used in the context of an AES-CBC operation.
 *
 * If a key is already set, the reference count of that key object
 * is decremented.
 * The context's key reference is set to the key object argument.
 * If the key object argument is non-NULL, the reference count
 * of that key object is incremented.
 *
 * \param[in,out] ctx AES-CBC context object
 * \param[in] key AES key object
 * \return 0 on success. Otherwise, a non-zero error code is returned.
 */
__attribute__((visibility("default")))
int zpc_aes_cbc_set_key(struct zpc_aes_cbc *ctx, struct zpc_aes_key *key);

/**
 * Set the initialization vector to be used in the context
 * of an AES-CBC operation.
 *
 * \param[in,out] ctx AES-CBC context object
 * \param[in] iv 16 byte initialization vector
 * \return 0 on success. Otherwise, a non-zero error code is returned.
 */
__attribute__((visibility("default")))
int zpc_aes_cbc_set_iv(struct zpc_aes_cbc *ctx, const unsigned char *iv);

/**
 * Encrypt a plaintext using AES-CBC to obtain the corresponding
 * ciphertext.
 *
 * The plaintext buffer length must be a multiple of 16 bytes.
 * Padding the plaintext appropriately is application's responsibility.
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
 * In particular, each chunk's length must be a multiple of 16 bytes.
 * The same context object must be used to encrypt all chunks without
 * modifying it in between operations.
 *
 * \param[in,out] ctx AES-CBC context object
 * \param[out] ct ciphertext buffer
 * \param[in] pt plaintext buffer
 * \param[in] ptlen plaintext length [bytes]
 * \return 0 on success. Otherwise, a non-zero error code is returned.
 */
__attribute__((visibility("default")))
int zpc_aes_cbc_encrypt(struct zpc_aes_cbc *ctx, unsigned char *ct,
    const unsigned char *pt, size_t ptlen);

/**
 * Decrypt a ciphertext using AES-CBC to obtain the corresponding
 * plaintext.
 *
 * The ciphertext buffer length must be a multiple of 16 bytes.
 *
 * The plaintext buffer must be large enough to store the resulting
 * plaintext which has the same length as the ciphertext.
 * Removing any padding from the plaintext is application's responsibility.
 *
 * Plaintext and ciphertext buffer may be equal such that the operation
 * is done in-place. If the operation is not done in-place, plaintext and
 * ciphertext buffers must not overlap.
 *
 * A ciphertext may be decrypted chunkwise. For every operation on a
 * ciphertext chunk, the same rules apply as for the one-shot decryption.
 * In particular, each chunk's length must be a multiple of 16 bytes.
 * The same context object must be used to decrypt all chunks without
 * modifying it in between operations.
 *
 * \param[in,out] ctx AES-CBC context object
 * \param[out] pt plaintext buffer
 * \param[in] ct ciphertext buffer
 * \param[in] ctlen ciphertext length [bytes]
 * \return 0 on success. Otherwise, a non-zero error code is returned.
 */
__attribute__((visibility("default")))
int zpc_aes_cbc_decrypt(struct zpc_aes_cbc *ctx, unsigned char *pt,
    const unsigned char *ct, size_t ctlen);

/**
 * Free an AES-CBC context object.
 *
 * If a key is set, the reference count of that key object is decremented.
 * The context object argument is set to NULL.
 *
 * \param[in,out] ctx AES-CBC context object
 */
__attribute__((visibility("default")))
void zpc_aes_cbc_free(struct zpc_aes_cbc **ctx);

# ifdef __cplusplus
/* *INDENT-OFF* */
}
/* *INDENT-ON* */
# endif
#endif
