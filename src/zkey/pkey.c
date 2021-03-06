/*
 * zkey - Generate, re-encipher, and validate secure keys
 *
 * Copyright IBM Corp. 2018
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <dlfcn.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/if_alg.h>
#include <stdbool.h>
#include <string.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "lib/util_base.h"
#include "lib/util_libc.h"
#include "lib/util_panic.h"

#include "pkey.h"
#include "utils.h"

/**
 * Check if the specified key is a CCA AESDATA key token.
 *
 * @param[in] key           the secure key token
 * @param[in] key_size      the size of the secure key
 *
 * @returns true if the key is an CCA AESDATA token type
 */
bool is_cca_aes_data_key(const u8 *key, size_t key_size)
{
	struct tokenheader *hdr = (struct tokenheader *)key;

	if (key == NULL || key_size < AESDATA_KEY_SIZE)
		return false;

	if (hdr->type != TOKEN_TYPE_CCA_INTERNAL)
		return false;
	if (hdr->version != TOKEN_VERSION_AESDATA)
		return false;

	return true;
}

/**
 * Check if the specified key is a CCA AESCIPHER key token.
 *
 * @param[in] key           the secure key token
 * @param[in] key_size      the size of the secure key
 *
 * @returns true if the key is an CCA AESCIPHER token type
 */
bool is_cca_aes_cipher_key(const u8 *key, size_t key_size)
{
	struct aescipherkeytoken *cipherkey = (struct aescipherkeytoken *)key;

	if (key == NULL || key_size < AESCIPHER_KEY_SIZE)
		return false;

	if (cipherkey->type != TOKEN_TYPE_CCA_INTERNAL)
		return false;
	if (cipherkey->version != TOKEN_VERSION_AESCIPHER)
		return false;
	if (cipherkey->length > key_size)
		return false;

	if (cipherkey->kms != 0x03) /* key wrapped by master key */
		return false;
	if (cipherkey->kwm != 0x02) /* key wrapped using AESKW */
		return false;
	if (cipherkey->pfv != 0x00 && cipherkey->pfv != 0x01) /* V0 or V1 */
		return false;
	if (cipherkey->adv != 0x01) /* Should have ass. data sect. version 1 */
		return false;
	if (cipherkey->at != 0x02) /* Algorithm: AES */
		return false;
	if (cipherkey->kt != 0x0001) /* Key type: CIPHER */
		return false;
	if (cipherkey->adl != 26) /* Ass. data section length should be 26 */
		return false;
	if (cipherkey->kll != 0) /* Should have no key label */
		return false;
	if (cipherkey->eadl != 0) /* Should have no ext associated data */
		return false;
	if (cipherkey->uadl != 0) /* Should have no user associated data */
		return false;
	if (cipherkey->kufc != 2) /* Should have 2 KUFs */
		return false;
	if (cipherkey->kmfc != 3) /* Should have 3 KMFs */
		return false;

	return true;
}

/**
 * Check if the specified key is a EP11 AES key token.
 *
 * @param[in] key           the secure key token
 * @param[in] key_size      the size of the secure key
 *
 * @returns true if the key is an EP11 AES token type
 */
bool is_ep11_aes_key(const u8 *key, size_t key_size)
{
	struct ep11keytoken *ep11key = (struct ep11keytoken *)key;

	if (key == NULL || key_size < EP11_KEY_SIZE)
		return false;

	if (ep11key->head.type != TOKEN_TYPE_NON_CCA)
		return false;
	if (ep11key->head.version != TOKEN_VERSION_EP11_AES)
		return false;
	if (ep11key->head.length > key_size)
		return false;

	if (ep11key->version != 0x1234)
		return false;

	return true;
}

/**
 * Check if the specified key is an XTS type key
 *
 * @param[in] key           the secure key token
 * @param[in] key_size      the size of the secure key
 *
 * @returns true if the key is an XTS key type
 */
bool is_xts_key(const u8 *key, size_t key_size)
{
	if (is_cca_aes_data_key(key, key_size)) {
		if (key_size == 2 * AESDATA_KEY_SIZE &&
		    is_cca_aes_data_key(key + AESDATA_KEY_SIZE,
					key_size - AESDATA_KEY_SIZE))
			return true;
	} else if (is_cca_aes_cipher_key(key, key_size)) {
		if (key_size == 2 * AESCIPHER_KEY_SIZE &&
		    is_cca_aes_cipher_key(key + AESCIPHER_KEY_SIZE,
					  key_size - AESCIPHER_KEY_SIZE))
			return true;
	} else if (is_ep11_aes_key(key, key_size)) {
		if (key_size == 2 * EP11_KEY_SIZE &&
		    is_ep11_aes_key(key + EP11_KEY_SIZE,
					  key_size - EP11_KEY_SIZE))
			return true;
	}

	return false;
}
