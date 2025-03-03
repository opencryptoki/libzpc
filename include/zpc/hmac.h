/*
 * Copyright IBM Corp. 2025
 *
 * libzpc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef ZPC_HMAC_H
# define ZPC_HMAC_H
# ifdef __cplusplus
/* *INDENT-OFF* */
extern "C" {
/* *INDENT-ON* */
# endif

/**
 * \file zpc/hmac.h
 * 
 * \brief HMAC API
 * 
 * Message authentication API for the Hash-based Message Authentication
 * Code (HMAC).
 */

# include <zpc/hmac_key.h>
# include <stddef.h>

struct zpc_hmac;

/**
 * Allocate a new context for an HMAC operation.
 * \param[in,out] ctx HMAC context
 * \return 0 on success. Otherwise, a non-zero error code is returned.
 */
__attribute__((visibility("default")))
int zpc_hmac_alloc(struct zpc_hmac **ctx);
/**
 * Set the key to be used in the context of an HMAC operation.
 * \param[in,out] ctx HMAC context
 * \param[in] key HMAC key
 * \return 0 on success. Otherwise, a non-zero error code is returned.
 */
__attribute__((visibility("default")))
int zpc_hmac_set_key(struct zpc_hmac *ctx, struct zpc_hmac_key *key);
/**
 * Do an HMAC signing operation.
 * \param[in,out] ctx HMAC context
 * \param[in,out] mac message authentication code when set to NULL, this
 * indicates that an internal intermediate MAC is calculated and further
 * intermediate calls with additional msg data may follow. If the mac parm is
 * not NULL and the maclen is a valid MAC length (dependent on the underlying
 * hash function of the key) the final MAC is computed.
 * \param[in] maclen message authentication code length [bytes]
 * \param[in] msg message
 * \param[in] msglen message length [bytes]
 * \return 0 on success. Otherwise, a non-zero error code is returned.
 */
__attribute__((visibility("default")))
int zpc_hmac_sign(struct zpc_hmac *ctx, unsigned char *mac,
    size_t maclen, const unsigned char *msg, size_t msglen);
/**
 * Do an HMAC verify operation.
 * \param[in,out] ctx HMAC context
 * \param[in,out] mac message authentication code if the mac parm is NULL, then
 * an intermediate verify op is performed. If the mac parm is not NULL and the
 * maclen is a valid MAC length (dependent on the underlying hash function of
 * the key), then the given MAC is checked for correctness.
 * \param[in] maclen message authentication code length [bytes]
 * \param[in] msg message
 * \param[in] msglen message length [bytes]
 * \return 0 on success. Otherwise, a non-zero error code is returned.
 */
__attribute__((visibility("default")))
int zpc_hmac_verify(struct zpc_hmac *ctx, const unsigned char *mac,
    size_t maclen, const unsigned char *msg, size_t msglen);
/**
 * Free an HMAC context.
 * \param[in,out] ctx HMAC context
 */
__attribute__((visibility("default")))
void zpc_hmac_free(struct zpc_hmac **ctx);

# ifdef __cplusplus
/* *INDENT-OFF* */
}
/* *INDENT-ON* */
# endif
#endif
