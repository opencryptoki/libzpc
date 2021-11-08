/*
 * Copyright IBM Corp. 2021
 *
 * libzpc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef ZPC_AES_CMAC_H
# define ZPC_AES_CMAC_H
# ifdef __cplusplus
/* *INDENT-OFF* */
extern "C" {
/* *INDENT-ON* */
# endif

/**
 * \file zpc/aes_cmac.h
 * 
 * \brief AES-CMAC API
 * 
 * Message authentication API for the Cipher-based Message Authentication
 * Code (CMAC) \cite CMAC based on the Advanced Encryption Standard (AES)
 * block cipher \cite AES . 
 *
 * The context of a AES-CMAC operation is stored in objects
 * of type struct zpc_aes_cmac.
 * Context objects must not be shared among multiple threads.
 * Context objects may be used for multiple operations by
 * (re)setting the key.
 */

# include <zpc/aes_key.h>
# include <stddef.h>

struct zpc_aes_cmac;

/**
 * Allocate a new context object for an AES-CMAC operation.
 *
 * \param[in,out] ctx AES-CMAC context object
 * \return 0 on success. Otherwise, a non-zero error code is returned.
 */
__attribute__((visibility("default")))
int zpc_aes_cmac_alloc(struct zpc_aes_cmac **ctx);

/**
 * Set the key to be used in the context of an AES-CMAC operation.
 *
 * If a key is already set, the reference count of that key object is
 * decremented.
 * The context's key reference is set to the key object argument.
 * If the key object argument is non-NULL, the reference count
 * of that key object is incremented.
 *
 * \param[in,out] ctx AES-CMAC context object
 * \param[in] key AES key object
 * \return 0 on success. Otherwise, a non-zero error code is returned.
 */
__attribute__((visibility("default")))
int zpc_aes_cmac_set_key(struct zpc_aes_cmac *ctx, struct zpc_aes_key *key);

/**
 * Sign a message using AES-CMAC to obtain the corresponding
 * message authentication code.
 *
 * A message may be processed chunkwise. Each chunk's length except the
 * lastcone's must be a multiple of 16 bytes.
 * The same context object must be used to process all chunks without
 * modifying it in between operations.
 *
 * \param[in,out] ctx AES-CMAC context object
 * \param[out] mac message authentication code buffer
 * \param[in] maclen message authentication code length [bytes]
 * \param[in] msg message buffer
 * \param[in] msglen message length [bytes]
 * \return 0 on success. Otherwise, a non-zero error code is returned.
 */
__attribute__((visibility("default")))
int zpc_aes_cmac_sign(struct zpc_aes_cmac *ctx, unsigned char *mac,
    size_t maclen, const unsigned char *msg, size_t msglen);

/**
 * Verify a message authentication code with a message using
 * AES-CMAC.
 *
 * A message may be processed chunkwise. Each chunk's length except the
 * last one's must be a multiple of 16 bytes.
 * The same context object must be used to process all chunks without
 * modifying it in between operations.
 *
 * \param[in,out] ctx AES-CMAC context object
 * \param[in] mac message authentication code buffer
 * \param[in] maclen message authentication code length [bytes]
 * \param[in] msg message buffer
 * \param[in] msglen message length [bytes]
 * \return 0 on success. Otherwise, a non-zero error code is returned.
 */
__attribute__((visibility("default")))
int zpc_aes_cmac_verify(struct zpc_aes_cmac *ctx, const unsigned char *mac,
    size_t maclen, const unsigned char *msg, size_t msglen);

/**
 * Free an AES-CMAC context object.
 *
 * If a key is set, the reference count of that key object is decremented.
 * The context object argument is set to NULL.
 *
 * \param[in,out] ctx AES-CMAC context object
 */
__attribute__((visibility("default")))
void zpc_aes_cmac_free(struct zpc_aes_cmac **ctx);

# ifdef __cplusplus
/* *INDENT-OFF* */
}
/* *INDENT-ON* */
# endif
#endif
