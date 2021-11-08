/*
 * Copyright IBM Corp. 2021
 *
 * libzpc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef ZPC_AES_KEY_H
# define ZPC_AES_KEY_H
# ifdef __cplusplus
/* *INDENT-OFF* */
extern "C" {
/* *INDENT-ON* */
# endif

/**
 * \file zpc/aes_key.h
 * \brief AES key API.
 * 
 * Manage advanced Encryption Standard (AES) block cipher
 * \cite AES keys.
 *
 * AES key objects of type struct zpc_aes_key store a secure AES key
 * of size 128, 192 or 256 bits and of type ZPC_AES_KEY_TYPE_CCA_DATA,
 * ZPC_AES_KEY_TYPE_CCA_CIPHER or ZPC_AES_KEY_TYPE_EP11, flags, a
 * reference count and the corresponding protected key.
 *
 * Setting flags is optional for AES key objects and flags=0 if flags
 * are not explicitely set.
 * 
 * The secure key is set by either generating it or importing it
 * (either directly or from a clear key).
 * 
 * The protected is automatically derived from the secure key
 * (and re-dervided whenever it is needed).
 *
 * The protected key can also be randomly generated resulting in
 * a protected key that is not associated to any secure key. Key objects
 * that are not associated to a secure key become unusable when the WKVP
 * changes.
 *
 * Key object's reference count is 1 on allocation and decremented by free.
 * Setting the key object in an operation context increments the reference
 * und unsetting the key object in an oparation context or freeing the
 * operation context decrements the reference count. The key object is
 * destroyed if oand only if the reference count is 0.
 * Key objects may be shared among multiple threads.
 */

# include <stddef.h>

# define ZPC_AES_KEY_TYPE_CCA_DATA     1
# define ZPC_AES_KEY_TYPE_CCA_CIPHER   2
# define ZPC_AES_KEY_TYPE_EP11         3

# define ZPC_AES_KEY_REENCIPHER_OLD_TO_CURRENT    1
# define ZPC_AES_KEY_REENCIPHER_CURRENT_TO_NEW    2

struct zpc_aes_key;

/**
 * Allocate a new AES key object with reference count 1.
 *
 * \param[in,out] key AES key object
 * \return 0 on success. Otherwise, a non-zero error code is returned.
 */
__attribute__((visibility("default")))
int zpc_aes_key_alloc(struct zpc_aes_key **key);

/**
 * Set the AES key size. 
 *
 * The key size cannot be changed, when the key object is in use
 * (reference count greater than 1).
 *
 * \param[in,out] key AES key object
 * \param[in] size 128, 192 or 256 bit key size
 * \return 0 on success. Otherwise, a non-zero error code is returned.
 */
__attribute__((visibility("default")))
int zpc_aes_key_set_size(struct zpc_aes_key *key, int size);

/**
 * Set the AES key type. 
 *
 * The key type cannot be changed, when the key object is in use
 * (reference count greater than 1).
 *
 * \param[in,out] key AES key object
 * \param[in] type ZPC_AES_KEY_TYPE_CCA_DATA, ZPC_AES_KEY_TYPE_CCA_CIPHER
 *     or  ZPC_AES_KEY_TYPE_EP11
 * \return 0 on success. Otherwise, a non-zero error code is returned.
 */
__attribute__((visibility("default")))
int zpc_aes_key_set_type(struct zpc_aes_key *key, int type);

/**
 * Set the AES key flags. 
 *
 * The flags have a key type specific meaning and provide a fine grained
 * control of the kernel's key generation ioctls.
 * For a detailed description of the ioctls and the flags,
 * see kernel's arch/s390/include/uapi/asm/pkey.h.
 *
 * The key flags cannot be changed, when the key object is in use
 * (reference count greater than 1).
 *
 * \param[in,out] key AES key object
 * \param[in] flags key flags
 * \return 0 on success. Otherwise, a non-zero error code is returned.
 */
__attribute__((visibility("default")))
int zpc_aes_key_set_flags(struct zpc_aes_key *key, unsigned int flags);

/**
 * Set the AES key Master Key Verification Pattern. 
 *
 * Associate all APQNs that match the given MKVP with the key object.
 * Overrides the key object's present APQN settings.
 *
 * The MKVP cannot be changed, when the key object is in use
 * (reference count greater than 1).
 *
 * \param[in,out] key AES key object
 * \param[in] mkvp master key verification pattern
 * \return 0 on success. Otherwise, a non-zero error code is returned.
 */
__attribute__((visibility("default")))
int zpc_aes_key_set_mkvp(struct zpc_aes_key *key, const char *mkvp);

/**
 * Set the AES key APQNs.
 *
 * Associate all giveb APQNs with the key object,
 * Overrides the key object's present APQN settings.
 *
 * The APQNs cannot be changed, when the key object is in use
 * (reference count greater than 1).
 *
 * \param[in,out] key AES key object
 * \param[in] apqns NULL-terminated APQN list
 * \return 0 on success. Otherwise, a non-zero error code is returned.
 */
__attribute__((visibility("default")))
int zpc_aes_key_set_apqns(struct zpc_aes_key *key, const char *apqns[]);

/**
 * Import an AES secure-key.
 *
 * The imported key must match the key object's key type, size and
 * APQN settings.
 *
 * No secure-key can be imported, when the key object is in use
 * (reference count greater than 1).
 *
 * The corresponding protected key is automatically derived.
 *
 * \param[in,out] key AES key object
 * \param[in] seckey AES secure-key buffer
 * \param[in] seckeylen AES key secure-length [bytes]
 * \return 0 on success. Otherwise, a non-zero error code is returned.
 */
__attribute__((visibility("default")))
int zpc_aes_key_import(struct zpc_aes_key *key, const unsigned char *seckey,
    size_t seckeylen);

/**
 * Import an AES clear-key.
 *
 * The imported key must match the key object's key size setting.
 *
 * No clear-key can be imported, when the key object is in use
 * (reference count greater than 1).
 *
 * The corresponding secure/protected key pair is automatically derived.
 *
 * \param[in,out] key AES key object
 * \param[in] clearkey AES clear-key buffer
 * \return 0 on success. Otherwise, a non-zero error code is returned.
 */
__attribute__((visibility("default")))
int zpc_aes_key_import_clear(struct zpc_aes_key *key,
    const unsigned char *clrkey);

/**
 * Export an AES secure-key.
 *
 * If the secure-key buffer is NULL, the byte-length of the
 * secure-key is returned in the secure-key length argument.
 *
 * If the secure-key buffer is non-NULL and the secure-key
 * length argument is greater than or equal to the secure-key's
 * byte-length, the secure key is returned in the secure-key buffer.
 * The byte-length of the secure-key is returned in the secure-key
 * length argument.
 *
 * \param[in,out] key AES key object
 * \param[out] seckey AES secure-key buffer
 * \param[in,out] seckeylen AES secure-key length [bytes]
 * \return 0 on success. Otherwise, a non-zero error code is returned.
 */
__attribute__((visibility("default")))
int zpc_aes_key_export(struct zpc_aes_key *key, unsigned char *seckey,
    size_t *seckeylen);

/**
 * Generate a random AES secure/protected key pair or a random protected key.
 *
 * If there are no APQNs associated with the key object, a random protected
 * key is generated.
 * Otherwise, a random secure key is generated and the corresponding
 * protected key is automatically derived.
 *
 * \param[in,out] key AES key object
 * \return 0 on success. Otherwise, a non-zero error code is returned.
 */
__attribute__((visibility("default")))
int zpc_aes_key_generate(struct zpc_aes_key *key);

/**
 * Reencipher an AES secure-key with another master key.
 *
 * Secure-keys of type ZPC_AES_KEY_TYPE_EP11 only support
 * ZPC_AES_KEY_REENCIPHER_CURRENT_TO_NEW.
 * The corresponding protected key is automatically derived.
 *
 * A backup of the prevous secure/protected key pair is kept in case
 * the new secure/protected key pair is not usable yet.
 *
 * \param[in,out] key AES key
 * \param[in] reenc ZPC_AES_KEY_REENCIPHER_OLD_TO_CURRENT
 *     or ZPC_AES_KEY_REENCIPHER_CURRENT_TO_NEW
 * \return 0 on success. Otherwise, a non-zero error code is returned.
 */
__attribute__((visibility("default")))
int zpc_aes_key_reencipher(struct zpc_aes_key *key, int reenc);

/**
 * Decrease the reference count of an AES key object
 * and free it the count reaches 0.
 *
 * Set the key object argument to NULL.
 *
 * \param[in,out] key AES key object
 */
__attribute__((visibility("default")))
void zpc_aes_key_free(struct zpc_aes_key **key);

# ifdef __cplusplus
/* *INDENT-OFF* */
}
/* *INDENT-ON* */
# endif
#endif
