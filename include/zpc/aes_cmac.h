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
 */

# include <zpc/aes_key.h>
# include <stddef.h>

struct zpc_aes_cmac;

/**
 * Allocate a new context for an AES-CMAC operation.
 * \param[in,out] ctx AES-CMAC context
 * \return 0 on success. Otherwise, a non-zero error code is returned.
 */
__attribute__((visibility("default")))
int zpc_aes_cmac_alloc(struct zpc_aes_cmac **ctx);
/**
 * Set the key to be used in the context of an AES-CMAC operation.
 * \param[in,out] ctx AES-CMAC context
 * \param[in] key AES key
 * \return 0 on success. Otherwise, a non-zero error code is returned.
 */
__attribute__((visibility("default")))
int zpc_aes_cmac_set_key(struct zpc_aes_cmac *ctx, struct zpc_aes_key *key);
/**
 * Do an AES-CMAC signing operation.
 * \param[in,out] ctx AES-CMAC context
 * \param[out] mac message authentication code
 * \param[in] maclen message authentication code length [bytes]
 * \param[in] msg message
 * \param[in] msglen message length [bytes]
 * \return 0 on success. Otherwise, a non-zero error code is returned.
 */
__attribute__((visibility("default")))
int zpc_aes_cmac_sign(struct zpc_aes_cmac *ctx, unsigned char *mac,
    size_t maclen, const unsigned char *msg, size_t msglen);
/**
 * Do an AES-CMAC verify operation.
 * \param[in,out] ctx AES-CMAC context
 * \param[in] mac message authentication code
 * \param[in] maclen message authentication code length [bytes]
 * \param[in] msg message
 * \param[in] msglen message length [bytes]
 * \return 0 on success. Otherwise, a non-zero error code is returned.
 */
__attribute__((visibility("default")))
int zpc_aes_cmac_verify(struct zpc_aes_cmac *ctx, const unsigned char *mac,
    size_t maclen, const unsigned char *msg, size_t msglen);
/**
 * Free an AES-CMAC context.
 * \param[in,out] ctx AES-CMAC context
 */
__attribute__((visibility("default")))
void zpc_aes_cmac_free(struct zpc_aes_cmac **ctx);

# ifdef __cplusplus
/* *INDENT-OFF* */
}
/* *INDENT-ON* */
# endif
#endif
