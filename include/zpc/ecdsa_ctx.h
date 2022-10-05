/*
 * Copyright IBM Corp. 2022
 *
 * libzpc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef ZPC_ECDSA_CTX_H
# define ZPC_ECDSA_CTX_H
# ifdef __cplusplus
/* *INDENT-OFF* */
extern "C" {
/* *INDENT-ON* */
# endif

/**
 * \file zpc/ecdsa_ctx.h
 * 
 * \brief ECDSA-CTX API
 *
 * Sign/verify API for elliptic curve cryptography (ECDSA) algorithms.
 * \cite ECDSA sign/verify
 */

# include <zpc/ecc_key.h>
# include <stddef.h>

struct zpc_ecdsa_ctx;

/**
 * Allocate a new context for an ECDSA sign/verify operation.
 * \param[in,out] ctx ECDSA context
 * \return 0 on success. Otherwise, a non-zero error code is returned.
 */
__attribute__((visibility("default")))
int zpc_ecdsa_ctx_alloc(struct zpc_ecdsa_ctx **ctx);

/**
 * Set the key to be used in the context of an ECDSA sign/verify operation.
 * \param[in,out] ctx ECDSA context
 * \param[in] key EC key
 * \return 0 on success. Otherwise, a non-zero error code is returned.
 */
__attribute__((visibility("default")))
int zpc_ecdsa_ctx_set_key(struct zpc_ecdsa_ctx *ctx, struct zpc_ec_key *key);

/**
 * Do an ECDSA sign operation.
 * \param[in,out] ctx ECDSA context
 * \param[in] hash input message to sign
 * \param[in] hash_len input message length [bytes]
 * \param[out] signature signature
 * \param[in,out] *sig_len address of signature length field [bytes]
 *             On input, the application must specify the buffer length
 *             to receive the signature [bytes]. If signature is NULL,
 *             only the length of the signature is returned.
 * \return 0 on success. Otherwise, a non-zero error code is returned.
 */
__attribute__((visibility("default")))
int zpc_ecdsa_sign(struct zpc_ecdsa_ctx *ctx,
				const unsigned char *hash, unsigned int hash_len,
				unsigned char *signature, unsigned int *sig_len);

/**
 * Do an ECDSA verify operation.
 * \param[in,out] ctx ECDSA context
 * \param[in] hash input message to verify
 * \param[in] hash_len input message length [bytes]
 * \param[in] signature signature to verify
 * \param[in] sig_len signature length
 * \return 0 on success. Otherwise, a non-zero error code is returned.
 */
__attribute__((visibility("default")))
int zpc_ecdsa_verify(struct zpc_ecdsa_ctx *ctx,
				const unsigned char *hash, unsigned int hash_len,
				const unsigned char *signature, unsigned int sig_len);

/**
 * Free an ECDSA context.
 * \param[in,out] ctx ECDSA context
 */
__attribute__((visibility("default")))
void zpc_ecdsa_ctx_free(struct zpc_ecdsa_ctx **ctx);

# ifdef __cplusplus
/* *INDENT-OFF* */
}
/* *INDENT-ON* */
# endif
#endif
