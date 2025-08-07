/*
 * Copyright IBM Corp. 2025
 *
 * libzpc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef ZPC_AES_XTS_KEY_H
# define ZPC_AES_XTS_KEY_H
# ifdef __cplusplus
/* *INDENT-OFF* */
extern "C" {
/* *INDENT-ON* */
# endif

/**
 * \file zpc/aes_xts_key.h
 * \brief AES full-xts key API.
 * 
 * Manage advanced Encryption Standard (AES) block cipher
 * \cite XTS keys to be used in a full-xts context.
 */

# include <stddef.h>

/*
 * These constants match with kernel's pkey.h, enum pkey_key_type.
 */
# define ZPC_AES_XTS_KEY_TYPE_PVSECRET     9

typedef enum {
	ZPC_XTS_SECRET_TYPE_NOT_SET = -2,
	ZPC_XTS_SECRET_TYPE_INVALID = -1,
	ZPC_XTS_SECRET_AES_XTS_128 = 0x07, /* architected key types, also below */
	ZPC_XTS_SECRET_AES_XTS_256 = 0x08,
} zpc_xtssecret_type_t;

struct zpc_aes_xts_key;

/**
 * Allocate a new AES full-xts key object with reference count 1.
 * \param[in,out] key AES-XTS key
 * \return 0 on success. Otherwise, a non-zero error code is returned.
 */
__attribute__((visibility("default")))
int zpc_aes_xts_key_alloc(struct zpc_aes_xts_key **key);
/**
 * Set the AES full-xts key size.
 * \param[in,out] key AES-XTS key
 * \param[in] size 128 or 256 bit key size
 * \return 0 on success. Otherwise, a non-zero error code is returned.
 */
__attribute__((visibility("default")))
int zpc_aes_xts_key_set_size(struct zpc_aes_xts_key *key, int size);
/**
 * Set the AES full-xts key type.
 * \param[in,out] key AES-XTS key
 * \param[in] type currently only ZPC_AES_XTS_KEY_TYPE_PVSECRET
 * \return 0 on success. Otherwise, a non-zero error code is returned.
 */
__attribute__((visibility("default")))
int zpc_aes_xts_key_set_type(struct zpc_aes_xts_key *key, int type);
/**
 * Import an AES-XTS protected key origin (secure key or pvsecret ID).
 * \param[in,out] key AES full-xts key
 * \param[in] seckey AES full-xts protected key origin (secure-key or pvsecret ID)
 * \param[in] seckeylen AES full-xts protected key origin length [bytes]
 * \return 0 on success. Otherwise, a non-zero error code is returned.
 */
__attribute__((visibility("default")))
int zpc_aes_xts_key_import(struct zpc_aes_xts_key *key, const unsigned char *seckey,
    size_t seckeylen);
/**
 * Import an AES-XTS clear-key.
 * \param[in,out] key AES-XTS key. If the key object has no type set, a
 * full-xts protected key is created from the given key material. If the type
 * is set to ZPC_AES_XTS_KEY_TYPE_PVSECRET then the import is not possible.
 * \param[in] clrkey AES XTS clear-key. The application must provide
 * concatenated key material for two single AES keys of the specified size,
 * i.e. either 2 x 16 bytes or 2 x 32 bytes.
 * \return 0 on success. Otherwise, a non-zero error code is returned.
 */
__attribute__((visibility("default")))
int zpc_aes_xts_key_import_clear(struct zpc_aes_xts_key *key,
    const unsigned char *clrkey);
/**
 * Export an AES-XTS protected key origin (secure key or pvsecret ID).
 * \param[in,out] key AES full-xts key
 * \param[out] seckey AES full-xts protected key origin (secure-key or pvsecret ID)
 * \param[in,out] seckeylen secure AES full-xts protected key origin length [bytes]
 * \return 0 on success. Otherwise, a non-zero error code is returned.
 */
__attribute__((visibility("default")))
int zpc_aes_xts_key_export(struct zpc_aes_xts_key *key, unsigned char *seckey,
    size_t *seckeylen);
/**
 * Generate an AES-XTS key. If the key object has no type set, a
 * full-xts random protected key is created. If the type is set to
 * ZPC_AES_XTS_KEY_TYPE_PVSECRET then generate is not possible.
 * \param[in,out] key AES full-xts key
 * \return 0 on success. Otherwise, a non-zero error code is returned.
 */
__attribute__((visibility("default")))
int zpc_aes_xts_key_generate(struct zpc_aes_xts_key *key);
/**
 * Decrease the reference count of an AES full-xts key object
 * and free it the count reaches 0.
 * \param[in,out] key AES full-xts key
 */
__attribute__((visibility("default")))
void zpc_aes_xts_key_free(struct zpc_aes_xts_key **key);

# ifdef __cplusplus
/* *INDENT-OFF* */
}
/* *INDENT-ON* */
# endif
#endif
