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
 */

# include <zpc/aes_key.h>
# include <stddef.h>

struct zpc_aes_cbc;

/**
 * Allocate a new context for an AES-CBC operation.
 * \param[in,out] ctx AES-CBC context
 * \return 0 on success. Otherwise, a non-zero error code is returned.
 */
__attribute__((visibility("default")))
int zpc_aes_cbc_alloc(struct zpc_aes_cbc **ctx);
/**
 * Set the key to be used in the context of an AES-CBC operation.
 * \param[in,out] ctx AES-CBC context
 * \param[in] key AES key
 * \return 0 on success. Otherwise, a non-zero error code is returned.
 */
__attribute__((visibility("default")))
int zpc_aes_cbc_set_key(struct zpc_aes_cbc *ctx, struct zpc_aes_key *key);
/**
 * Set the initialization vector to be used in the context
 * of an AES-CBC operation.
 * \param[in,out] ctx AES-CBC context
 * \param[in] iv 16 byte initialization vector
 * \return 0 on success. Otherwise, a non-zero error code is returned.
 */
__attribute__((visibility("default")))
int zpc_aes_cbc_set_iv(struct zpc_aes_cbc *ctx, const unsigned char *iv);
/**
 * Do an AES-CBC encryption operation.
 * \param[in,out] ctx AES-CBC context
 * \param[out] ct ciphertext
 * \param[in] pt plaintext
 * \param[in] ptlen plaintext length [bytes]
 * \return 0 on success. Otherwise, a non-zero error code is returned.
 */
__attribute__((visibility("default")))
int zpc_aes_cbc_encrypt(struct zpc_aes_cbc *ctx, unsigned char *ct,
    const unsigned char *pt, size_t ptlen);
/**
 * Do an AES-CBC decryption operation.
 * \param[in,out] ctx AES-CBC context
 * \param[out] pt plaintext
 * \param[in] ct ciphertext
 * \param[in] ctlen ciphertext length [bytes]
 * \return 0 on success. Otherwise, a non-zero error code is returned.
 */
__attribute__((visibility("default")))
int zpc_aes_cbc_decrypt(struct zpc_aes_cbc *ctx, unsigned char *pt,
    const unsigned char *ct, size_t ctlen);
/**
 * Free an AES-CBC context.
 * \param[in,out] ctx AES-CBC context
 */
__attribute__((visibility("default")))
void zpc_aes_cbc_free(struct zpc_aes_cbc **ctx);

# ifdef __cplusplus
/* *INDENT-OFF* */
}
/* *INDENT-ON* */
# endif
#endif
