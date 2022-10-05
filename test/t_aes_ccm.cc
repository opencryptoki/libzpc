/*
 * Copyright IBM Corp. 2021
 *
 * libzpc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "testlib.h"

#include "gtest/gtest.h"
#include "zpc/aes_ccm.h"
#include "zpc/error.h"

#include "aes_key_local.h"  /* de-opaquify struct zpc_aes_key */
#include "aes_ccm_local.h"  /* de-opaquify struct zpc_aes_ccm */

#include <json-c/json.h>
#include <stdio.h>
#include <thread>
#include <unistd.h>

static void __run_json(const char *json);

TEST(aes_ccm, alloc)
{
	struct zpc_aes_ccm *aes_ccm;
	int rc;

	TESTLIB_ENV_AES_KEY_CHECK();

	rc = zpc_aes_ccm_alloc(NULL);
	EXPECT_EQ(rc, ZPC_ERROR_ARG1NULL);

	aes_ccm = NULL;
	rc = zpc_aes_ccm_alloc(&aes_ccm);
	EXPECT_EQ(rc, 0);
	zpc_aes_ccm_free(&aes_ccm);
	EXPECT_EQ(aes_ccm, nullptr);

	aes_ccm = (struct zpc_aes_ccm *)&aes_ccm;
	rc = zpc_aes_ccm_alloc(&aes_ccm);
	EXPECT_EQ(rc, 0);
	zpc_aes_ccm_free(&aes_ccm);
	EXPECT_EQ(aes_ccm, nullptr);
}

TEST(aes_ccm, free)
{
	struct zpc_aes_ccm *aes_ccm;
	int rc;

	TESTLIB_ENV_AES_KEY_CHECK();

	zpc_aes_ccm_free(NULL);

	aes_ccm = NULL;
	zpc_aes_ccm_free(&aes_ccm);
	EXPECT_EQ(aes_ccm, nullptr);

	rc = zpc_aes_ccm_alloc(&aes_ccm);
	EXPECT_EQ(rc, 0);
	zpc_aes_ccm_free(&aes_ccm);
	EXPECT_EQ(aes_ccm, nullptr);
}

TEST(aes_ccm, set_key)
{
	struct zpc_aes_key *aes_key;
	struct zpc_aes_ccm *aes_ccm;
	u8 clearkey[32], iv[12];
	unsigned int flags = 0;
	const char *mkvp, *apqns[257];
	int rc, size, type;

	TESTLIB_ENV_AES_KEY_CHECK();
	size = testlib_env_aes_key_size();
	type = testlib_env_aes_key_type();
	flags = testlib_env_aes_key_flags();
	mkvp = testlib_env_aes_key_mkvp();
	(void)testlib_env_aes_key_apqns(apqns);

	rc = zpc_aes_key_alloc(&aes_key);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_ccm_alloc(&aes_ccm);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_ccm_set_key(aes_ccm, aes_key);
	EXPECT_EQ(rc, ZPC_ERROR_KEYNOTSET);

	rc = zpc_aes_key_set_size(aes_key, size);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_key_set_type(aes_key, type);
	EXPECT_EQ(rc, 0);
	if (mkvp != NULL) {
		rc = zpc_aes_key_set_mkvp(aes_key, mkvp);
		EXPECT_EQ(rc, 0);
	} else {
		rc = zpc_aes_key_set_apqns(aes_key, apqns);
		EXPECT_EQ(rc, 0);
	}
	rc = zpc_aes_key_set_flags(aes_key, flags);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_key_import_clear(aes_key, clearkey);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_ccm_set_key(NULL, NULL);
	EXPECT_EQ(rc, ZPC_ERROR_ARG1NULL);
	rc = zpc_aes_ccm_set_key(NULL, aes_key);
	EXPECT_EQ(rc, ZPC_ERROR_ARG1NULL);

	rc = zpc_aes_ccm_set_key(aes_ccm, NULL);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_ccm_set_iv(aes_ccm, iv, 12);
	EXPECT_EQ(rc, ZPC_ERROR_KEYNOTSET);
	rc = zpc_aes_ccm_set_key(aes_ccm, aes_key);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_ccm_set_iv(aes_ccm, iv, 12);
	EXPECT_EQ(rc, 0);

	zpc_aes_ccm_free(&aes_ccm);
	EXPECT_EQ(aes_ccm, nullptr);
	zpc_aes_key_free(&aes_key);
	EXPECT_EQ(aes_key, nullptr);
}

TEST(aes_ccm, set_iv)
{
	struct zpc_aes_key *aes_key;
	struct zpc_aes_ccm *aes_ccm;
	const char *mkvp, *apqns[257];
	u8 iv[16];
	int rc, size, type;
	unsigned int flags;

	TESTLIB_ENV_AES_KEY_CHECK();
	size = testlib_env_aes_key_size();
	type = testlib_env_aes_key_type();
	flags = testlib_env_aes_key_flags();
	mkvp = testlib_env_aes_key_mkvp();
	(void)testlib_env_aes_key_apqns(apqns);

	rc = zpc_aes_key_alloc(&aes_key);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_ccm_alloc(&aes_ccm);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_ccm_set_iv(NULL, NULL, 0);
	EXPECT_EQ(rc, ZPC_ERROR_ARG1NULL);
	rc = zpc_aes_ccm_set_iv(NULL, iv, 12);
	EXPECT_EQ(rc, ZPC_ERROR_ARG1NULL);

	rc = zpc_aes_ccm_set_iv(aes_ccm, NULL, 0);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_ccm_set_iv(aes_ccm, iv, 12);
	EXPECT_EQ(rc, ZPC_ERROR_KEYNOTSET);

	rc = zpc_aes_key_set_size(aes_key, size);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_key_set_type(aes_key, type);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_key_set_flags(aes_key, flags);
	EXPECT_EQ(rc, 0);
	if (mkvp != NULL) {
		rc = zpc_aes_key_set_mkvp(aes_key, mkvp);
		EXPECT_EQ(rc, 0);
	} else {
		rc = zpc_aes_key_set_apqns(aes_key, apqns);
		EXPECT_EQ(rc, 0);
	}
	rc = zpc_aes_key_generate(aes_key);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_ccm_set_iv(aes_ccm, iv, 12);
	EXPECT_EQ(rc, ZPC_ERROR_KEYNOTSET);

	rc = zpc_aes_ccm_set_key(aes_ccm, aes_key);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_ccm_set_iv(aes_ccm, iv, 0);
	EXPECT_EQ(rc, ZPC_ERROR_IVSIZE);
	rc = zpc_aes_ccm_set_iv(aes_ccm, iv, SIZE_MAX);
	EXPECT_EQ(rc, ZPC_ERROR_IVSIZE);
	rc = zpc_aes_ccm_set_iv(aes_ccm, iv, 12);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_ccm_set_iv(aes_ccm, iv, 13);
	EXPECT_EQ(rc, 0);

	zpc_aes_ccm_free(&aes_ccm);
	EXPECT_EQ(aes_ccm, nullptr);
	zpc_aes_key_free(&aes_key);
	EXPECT_EQ(aes_key, nullptr);
}

TEST(aes_ccm, encrypt)
{
	struct zpc_aes_key *aes_key;
	struct zpc_aes_ccm *aes_ccm;
	const char *mkvp, *apqns[257];
	u8 iv[12], aad[99], m[99], tag[12], c[99];
	unsigned int flags;
	int rc, size, type;

	TESTLIB_ENV_AES_KEY_CHECK();
	size = testlib_env_aes_key_size();
	type = testlib_env_aes_key_type();
	flags = testlib_env_aes_key_flags();
	mkvp = testlib_env_aes_key_mkvp();
	(void)testlib_env_aes_key_apqns(apqns);

	rc = zpc_aes_key_alloc(&aes_key);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_ccm_alloc(&aes_ccm);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_key_set_type(aes_key, type);
	EXPECT_EQ(rc, 0);
	if (mkvp != NULL) {
		rc = zpc_aes_key_set_mkvp(aes_key, mkvp);
		EXPECT_EQ(rc, 0);
	} else {
		rc = zpc_aes_key_set_apqns(aes_key, apqns);
		EXPECT_EQ(rc, 0);
	}
	rc = zpc_aes_key_set_size(aes_key, size);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_key_set_flags(aes_key, flags);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_key_generate(aes_key);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_ccm_set_key(aes_ccm, aes_key);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_ccm_set_iv(aes_ccm, iv, 12);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_ccm_encrypt(aes_ccm, c, tag, 12, aad, 99, m, 99);
	EXPECT_EQ(rc, 0);

	zpc_aes_ccm_free(&aes_ccm);
	EXPECT_EQ(aes_ccm, nullptr);
	zpc_aes_key_free(&aes_key);
	EXPECT_EQ(aes_key, nullptr);
}

TEST(aes_ccm, decrypt)
{
	struct zpc_aes_key *aes_key;
	struct zpc_aes_ccm *aes_ccm;
	const char *mkvp, *apqns[257];
	u8 iv[12], aad[99], m[99], tag[12], c[99];
	unsigned int flags;
	int rc, size, type;

	TESTLIB_ENV_AES_KEY_CHECK();
	size = testlib_env_aes_key_size();
	type = testlib_env_aes_key_type();
	flags = testlib_env_aes_key_flags();
	mkvp = testlib_env_aes_key_mkvp();
	(void)testlib_env_aes_key_apqns(apqns);

	rc = zpc_aes_key_alloc(&aes_key);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_ccm_alloc(&aes_ccm);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_key_set_type(aes_key, type);
	EXPECT_EQ(rc, 0);
	if (mkvp != NULL) {
		rc = zpc_aes_key_set_mkvp(aes_key, mkvp);
		EXPECT_EQ(rc, 0);
	} else {
		rc = zpc_aes_key_set_apqns(aes_key, apqns);
		EXPECT_EQ(rc, 0);
	}
	rc = zpc_aes_key_set_size(aes_key, size);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_key_set_flags(aes_key, flags);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_key_generate(aes_key);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_ccm_set_key(aes_ccm, aes_key);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_ccm_set_iv(aes_ccm, iv, 12);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_ccm_decrypt(aes_ccm, m, tag, 12, aad, 99, c, 99);
	EXPECT_EQ(rc, ZPC_ERROR_TAGMISMATCH);

	zpc_aes_ccm_free(&aes_ccm);
	EXPECT_EQ(aes_ccm, nullptr);
	zpc_aes_key_free(&aes_key);
	EXPECT_EQ(aes_key, nullptr);
}

TEST(aes_ccm, pc)
{
	struct zpc_aes_key *aes_key1, *aes_key2;
	struct zpc_aes_ccm *aes_ccm1, *aes_ccm2;
	const char *mkvp, *apqns[257];
	u8 iv[12], aad[99], m[99], tag[12], c[99], key[32], m_bak[99];
	unsigned int flags;
	int rc, size, type;

	TESTLIB_ENV_AES_KEY_CHECK();
	size = testlib_env_aes_key_size();
	type = testlib_env_aes_key_type();
	flags = testlib_env_aes_key_flags();
	mkvp = testlib_env_aes_key_mkvp();
	(void)testlib_env_aes_key_apqns(apqns);

	memcpy(m_bak, m, 99);

	rc = zpc_aes_key_alloc(&aes_key1);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_key_alloc(&aes_key2);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_ccm_alloc(&aes_ccm1);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_ccm_alloc(&aes_ccm2);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_key_set_size(aes_key1, size);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_key_set_type(aes_key1, type);
	EXPECT_EQ(rc, 0);
	if (mkvp != NULL) {
		rc = zpc_aes_key_set_mkvp(aes_key1, mkvp);
		EXPECT_EQ(rc, 0);
	} else {
		rc = zpc_aes_key_set_apqns(aes_key1, apqns);
		EXPECT_EQ(rc, 0);
	}
	rc = zpc_aes_key_set_flags(aes_key1, flags);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_key_import_clear(aes_key1, key);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_ccm_set_key(aes_ccm1, aes_key1);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_ccm_set_iv(aes_ccm1, iv, 12);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_key_set_size(aes_key2, size);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_key_set_type(aes_key2, type);
	EXPECT_EQ(rc, 0);
	if (mkvp != NULL) {
		rc = zpc_aes_key_set_mkvp(aes_key2, mkvp);
		EXPECT_EQ(rc, 0);
	} else {
		rc = zpc_aes_key_set_apqns(aes_key2, apqns);
		EXPECT_EQ(rc, 0);
	}
	rc = zpc_aes_key_set_flags(aes_key2, flags);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_key_import_clear(aes_key2, key);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_ccm_set_key(aes_ccm2, aes_key2);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_ccm_set_iv(aes_ccm2, iv, 12);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_ccm_encrypt(aes_ccm1, c, tag, 12, aad, 99, m, 99);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_ccm_decrypt(aes_ccm2, m, tag, 12, aad, 99, c, 99);
	EXPECT_EQ(rc, 0);
	EXPECT_TRUE(memcmp(m, m_bak, 99) == 0);
	rc = zpc_aes_ccm_encrypt(aes_ccm2, c, tag, 12, aad, 99, m, 99);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_ccm_decrypt(aes_ccm1, m, tag, 12, aad, 99, c, 99);
	EXPECT_EQ(rc, 0);
	EXPECT_TRUE(memcmp(m, m_bak, 99) == 0);

	rc = zpc_aes_ccm_encrypt(aes_ccm2, c, tag, 12, aad, 99, m, 99);
	EXPECT_EQ(rc, 0);
	c[0] ^= 1;
	rc = zpc_aes_ccm_decrypt(aes_ccm1, m, tag, 12, aad, 99, c, 99);
	EXPECT_EQ(rc, ZPC_ERROR_TAGMISMATCH);
	rc = zpc_aes_ccm_encrypt(aes_ccm1, c, tag, 12, aad, 99, m, 99);
	EXPECT_EQ(rc, 0);
	tag[0] ^= 1;
	rc = zpc_aes_ccm_decrypt(aes_ccm2, m, tag, 12, aad, 99, c, 99);
	EXPECT_EQ(rc, ZPC_ERROR_TAGMISMATCH);

	memcpy(m_bak, m, 99);

	/* Random protected key */
	rc = zpc_aes_ccm_set_key(aes_ccm1, NULL);   /* Unset key. */
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_ccm_set_key(aes_ccm2, NULL);   /* Unset key. */
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_key_set_mkvp(aes_key1, NULL);   /* Unset apqns. */
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_key_set_size(aes_key1, size);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_key_generate(aes_key1);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_ccm_set_key(aes_ccm1, aes_key1);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_ccm_set_iv(aes_ccm1, iv, 12);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_ccm_set_key(aes_ccm2, aes_key1);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_ccm_set_iv(aes_ccm2, iv, 12);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_ccm_encrypt(aes_ccm1, c, tag, 12, aad, 99, m, 99);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_ccm_decrypt(aes_ccm2, m, tag, 12, aad, 99, c, 99);
	EXPECT_EQ(rc, 0);
	EXPECT_TRUE(memcmp(m, m_bak, 99) == 0);
	rc = zpc_aes_ccm_encrypt(aes_ccm2, c, tag, 12, aad, 99, m, 99);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_ccm_decrypt(aes_ccm1, m, tag, 12, aad, 99, c, 99);
	EXPECT_EQ(rc, 0);
	EXPECT_TRUE(memcmp(m, m_bak, 99) == 0);

	rc = zpc_aes_ccm_encrypt(aes_ccm2, c, tag, 12, aad, 99, m, 99);
	EXPECT_EQ(rc, 0);
	c[0] ^= 1;
	rc = zpc_aes_ccm_decrypt(aes_ccm1, m, tag, 12, aad, 99, c, 99);
	EXPECT_EQ(rc, ZPC_ERROR_TAGMISMATCH);
	rc = zpc_aes_ccm_encrypt(aes_ccm1, c, tag, 12, aad, 99, m, 99);
	EXPECT_EQ(rc, 0);
	tag[0] ^= 1;
	rc = zpc_aes_ccm_decrypt(aes_ccm2, m, tag, 12, aad, 99, c, 99);
	EXPECT_EQ(rc, ZPC_ERROR_TAGMISMATCH);

	zpc_aes_ccm_free(&aes_ccm2);
	zpc_aes_ccm_free(&aes_ccm1);
	zpc_aes_key_free(&aes_key2);
	EXPECT_EQ(aes_key2, nullptr);
	zpc_aes_key_free(&aes_key1);
	EXPECT_EQ(aes_key1, nullptr);
}

TEST(aes_ccm, stream_inplace_kat1)
{
	TESTLIB_ENV_AES_KEY_CHECK();

	size_t keylen, ivlen, msglen, ctlen, taglen, aadlen;
	unsigned char buf[4096], mac[16];
	const char *mkvp, *apqns[257];
	struct zpc_aes_key *aes_key;
	struct zpc_aes_ccm *aes_ccm;
	unsigned int flags;
	int type, rc;

	const char *keystr = "e258b117c2fdd75587f07b400ae4af3e673a51dcf761e4ca";
	const char *ivstr = "5ead03aa8c720d21b77075db";
	const char *aadstr = "27702950960b9c79";
	const char *msgstr = "afe96113a684bc52a6d962cf2724f6791d";
	const char *ctstr = "7830446f333057d996a1a79b21c68d8b43";
	const char *tagstr = "72ac478a66f5637563f1f12c1d0267ca";

	u8 *key = testlib_hexstr2buf(keystr, &keylen);
	ASSERT_NE(key, nullptr);
	u8 *iv = testlib_hexstr2buf(ivstr, &ivlen);
	ASSERT_NE(iv, nullptr);
	u8 *aad = testlib_hexstr2buf(aadstr, &aadlen);
	ASSERT_NE(aad, nullptr);
	u8 *msg = testlib_hexstr2buf(msgstr, &msglen);
	ASSERT_NE(msg, nullptr);
	u8 *ct = testlib_hexstr2buf(ctstr, &ctlen);
	ASSERT_NE(ct, nullptr);
	u8 *tag = testlib_hexstr2buf(tagstr, &taglen);
	ASSERT_NE(tag, nullptr);

	type = testlib_env_aes_key_type();
	flags = testlib_env_aes_key_flags();
	mkvp = testlib_env_aes_key_mkvp();
	(void)testlib_env_aes_key_apqns(apqns);

	rc = zpc_aes_key_alloc(&aes_key);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_ccm_alloc(&aes_ccm);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_key_set_type(aes_key, type);
	EXPECT_EQ(rc, 0);
	if (mkvp != NULL) {
		rc = zpc_aes_key_set_mkvp(aes_key, mkvp);
		EXPECT_EQ(rc, 0);
	} else {
		rc = zpc_aes_key_set_apqns(aes_key, apqns);
		EXPECT_EQ(rc, 0);
	}
	rc = zpc_aes_key_set_flags(aes_key, flags);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_key_set_size(aes_key, keylen * 8);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_key_import_clear(aes_key, key);
	EXPECT_EQ(rc, 0);

	/* Encrypt */
	memcpy(buf, msg, msglen);

	rc = zpc_aes_ccm_set_key(aes_ccm, aes_key);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_ccm_set_iv(aes_ccm, iv, ivlen);
	EXPECT_EQ(rc, 0);

	EXPECT_EQ(rc, 0);
	rc = zpc_aes_ccm_encrypt(aes_ccm, buf, mac, taglen, aad, aadlen, buf, msglen);
	EXPECT_EQ(rc, 0);

	EXPECT_TRUE(memcmp(buf, ct, ctlen) == 0);
	EXPECT_TRUE(memcmp(mac, tag, taglen) == 0);

	/* Encrypt */
	memcpy(buf, msg, msglen);

	rc = zpc_aes_ccm_set_key(aes_ccm, aes_key);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_ccm_set_iv(aes_ccm, iv, ivlen);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_ccm_encrypt(aes_ccm, buf, mac, taglen, aad, aadlen, buf, msglen);
	EXPECT_EQ(rc, 0);

	EXPECT_TRUE(memcmp(buf, ct, ctlen) == 0);
	EXPECT_TRUE(memcmp(mac, tag, taglen) == 0);

	/* Decrypt */
	memcpy(buf, ct, ctlen);

	rc = zpc_aes_ccm_set_iv(aes_ccm, iv, ivlen);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_ccm_decrypt(aes_ccm, buf, tag, taglen, aad, aadlen, buf, msglen);
	EXPECT_EQ(rc, 0);

	EXPECT_TRUE(memcmp(buf, msg, msglen) == 0);

	/* Decrypt */
	memcpy(buf, ct, ctlen);

	rc = zpc_aes_ccm_set_iv(aes_ccm, iv, ivlen);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_ccm_decrypt(aes_ccm, buf, tag, taglen, aad, aadlen, buf, msglen);
	EXPECT_EQ(rc, 0);

	EXPECT_TRUE(memcmp(buf, msg, msglen) == 0);

	zpc_aes_ccm_free(&aes_ccm);
	EXPECT_EQ(aes_ccm, nullptr);
	zpc_aes_key_free(&aes_key);
	EXPECT_EQ(aes_key, nullptr);

	free(key);
	free(iv);
	free(aad);
	free(msg);
	free(ct);
	free(tag);
}

TEST(aes_ccm, stream_inplace_kat2)
{
	TESTLIB_ENV_AES_KEY_CHECK();

	size_t keylen, ivlen, msglen, ctlen, taglen, aadlen;
	unsigned char buf[4096], mac[16];
	const char *mkvp, *apqns[257];
	struct zpc_aes_key *aes_key;
	struct zpc_aes_ccm *aes_ccm;
	unsigned int flags;
	int type, rc;

	const char *keystr = "e258b117c2fdd75587f07b400ae4af3e673a51dcf761e4ca";
	const char *ivstr = "5ead03aa8c720d21b77075db";
	const char *aadstr = "27702950960b9c79";
	const char *msgstr = "afe96113a684bc52a6d962cf2724f6791d";
	const char *ctstr = "7830446f333057d996a1a79b21c68d8b43";
	const char *tagstr = "72ac478a66f5637563f1f12c1d0267ca";

	u8 *key = testlib_hexstr2buf(keystr, &keylen);
	ASSERT_NE(key, nullptr);
	u8 *iv = testlib_hexstr2buf(ivstr, &ivlen);
	ASSERT_NE(iv, nullptr);
	u8 *aad = testlib_hexstr2buf(aadstr, &aadlen);
	ASSERT_NE(aad, nullptr);
	u8 *msg = testlib_hexstr2buf(msgstr, &msglen);
	ASSERT_NE(msg, nullptr);
	u8 *ct = testlib_hexstr2buf(ctstr, &ctlen);
	ASSERT_NE(ct, nullptr);
	u8 *tag = testlib_hexstr2buf(tagstr, &taglen);
	ASSERT_NE(tag, nullptr);

	type = testlib_env_aes_key_type();
	flags = testlib_env_aes_key_flags();
	mkvp = testlib_env_aes_key_mkvp();
	(void)testlib_env_aes_key_apqns(apqns);

	rc = zpc_aes_key_alloc(&aes_key);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_ccm_alloc(&aes_ccm);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_key_set_type(aes_key, type);
	EXPECT_EQ(rc, 0);
	if (mkvp != NULL) {
		rc = zpc_aes_key_set_mkvp(aes_key, mkvp);
		EXPECT_EQ(rc, 0);
	} else {
		rc = zpc_aes_key_set_apqns(aes_key, apqns);
		EXPECT_EQ(rc, 0);
	}
	rc = zpc_aes_key_set_flags(aes_key, flags);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_key_set_size(aes_key, keylen * 8);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_key_import_clear(aes_key, key);
	EXPECT_EQ(rc, 0);

	/* Encrypt */
	memcpy(buf, msg, msglen);

	rc = zpc_aes_ccm_set_key(aes_ccm, aes_key);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_ccm_set_iv(aes_ccm, iv, ivlen);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_ccm_encrypt(aes_ccm, buf, mac, taglen, aad, aadlen, buf, msglen);
	EXPECT_EQ(rc, 0);

	EXPECT_TRUE(memcmp(buf, ct, ctlen) == 0);
	EXPECT_TRUE(memcmp(mac, tag, taglen) == 0);

	/* Decrypt */
	memcpy(buf, ct, ctlen);

	rc = zpc_aes_ccm_set_iv(aes_ccm, iv, ivlen);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_ccm_decrypt(aes_ccm, buf, tag, taglen, aad, aadlen, buf, msglen);  /* Works iff msglen == 0 mod 16 */
	EXPECT_EQ(rc, 0);

	EXPECT_TRUE(memcmp(buf, msg, msglen) == 0);

	zpc_aes_ccm_free(&aes_ccm);
	EXPECT_EQ(aes_ccm, nullptr);
	zpc_aes_key_free(&aes_key);
	EXPECT_EQ(aes_key, nullptr);

	free(key);
	free(iv);
	free(aad);
	free(msg);
	free(ct);
	free(tag);
}

TEST(aes_ccm, wycheproof_kat)
{
	TESTLIB_ENV_AES_KEY_CHECK();
	__run_json("wycheproof/src/wycheproof/testvectors/aes_ccm_test.json");
}

static void __run_json(const char *json)
{
	const char *tv = json, *str;
	const char *mkvp, *apqns[257];
	struct zpc_aes_key *aes_key;
	struct zpc_aes_ccm *aes_ccm;
	unsigned int flags;
	u8 *key = NULL, *iv = NULL, *aad = NULL;
	u8 *pt = NULL, *pt_out = NULL, *ct = NULL, *ct_out = NULL;
	u8 *tag = NULL, *tag_out = NULL;
	int rc, tagsize = 0, ivsize = 0, keysize = 0;
	int valid = 0, ivlen0 = 0, tag0 = 0, nonce0 = 0;
	size_t aadlen, ptlen, ctlen, taglen, i, j, k, max;
	json_object *jkey, *jiv, *jtag, *jaad, *jmsg, *jct, *jresult, *jflags, *jtmp, *jtestgroups, *jfile, *jkeysize, *jivsize, *jtagsize, *jtests;
	json_bool b;
	int type;

	type = testlib_env_aes_key_type();
	flags = testlib_env_aes_key_flags();
	mkvp = testlib_env_aes_key_mkvp();
	(void)testlib_env_aes_key_apqns(apqns);

	rc = zpc_aes_key_alloc(&aes_key);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_ccm_alloc(&aes_ccm);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_key_set_type(aes_key, type);
	EXPECT_EQ(rc, 0);
	if (mkvp != NULL) {
		rc = zpc_aes_key_set_mkvp(aes_key, mkvp);
		EXPECT_EQ(rc, 0);
	} else {
		rc = zpc_aes_key_set_apqns(aes_key, apqns);
		EXPECT_EQ(rc, 0);
	}
	rc = zpc_aes_key_set_flags(aes_key, flags);
	EXPECT_EQ(rc, 0);

	jfile = json_object_from_file(tv);
	ASSERT_NE(jfile, nullptr);

	b = json_object_object_get_ex(jfile, "testGroups", &jtestgroups);
	ASSERT_TRUE(b);

	for (i = 0; i < (size_t)json_object_array_length(jtestgroups); i++) {
		jtmp = json_object_array_get_idx(jtestgroups, i);
		ASSERT_NE(jtmp, nullptr);

		b = json_object_object_get_ex(jtmp, "keySize", &jkeysize);
		ASSERT_TRUE(b);
		b = json_object_object_get_ex(jtmp, "ivSize", &jivsize);
		ASSERT_TRUE(b);
		b = json_object_object_get_ex(jtmp, "tagSize", &jtagsize);
		ASSERT_TRUE(b);
		b = json_object_object_get_ex(jtmp, "tests", &jtests);
		ASSERT_TRUE(b);

		keysize = json_object_get_int(jkeysize);
		ivsize = json_object_get_int(jivsize);
		tagsize = json_object_get_int(jtagsize);

		rc = zpc_aes_key_set_size(aes_key, keysize);
		EXPECT_EQ(rc, 0);

		for (j = 0; j < (size_t)json_object_array_length(jtests); j++) {
			jtmp = json_object_array_get_idx(jtests, j);
			ASSERT_NE(jtmp, nullptr);

			b = json_object_object_get_ex(jtmp, "key", &jkey);
			ASSERT_TRUE(b);
			b = json_object_object_get_ex(jtmp, "iv", &jiv);
			ASSERT_TRUE(b);
			b = json_object_object_get_ex(jtmp, "tag", &jtag);
			ASSERT_TRUE(b);
			b = json_object_object_get_ex(jtmp, "aad", &jaad);
			ASSERT_TRUE(b);
			b = json_object_object_get_ex(jtmp, "msg", &jmsg);
			ASSERT_TRUE(b);
			b = json_object_object_get_ex(jtmp, "ct", &jct);
			ASSERT_TRUE(b);
			b = json_object_object_get_ex(jtmp, "flags", &jflags);
			ASSERT_TRUE(b);
			b = json_object_object_get_ex(jtmp, "result", &jresult);
			ASSERT_TRUE(b);

			str = json_object_get_string(jkey);
			ASSERT_NE(str, nullptr);
			key = testlib_hexstr2buf(str, NULL);
			ASSERT_NE(key, nullptr);
			str = json_object_get_string(jiv);
			ASSERT_NE(str, nullptr);
			iv = testlib_hexstr2buf(str, NULL);
			str = json_object_get_string(jtag);
			ASSERT_NE(str, nullptr);
			tag = testlib_hexstr2buf(str, &taglen);
			ASSERT_NE(tag, nullptr);
			tag_out = (unsigned char *)calloc(1, taglen);
			ASSERT_NE(tag_out, nullptr);
			str = json_object_get_string(jaad);
			ASSERT_NE(str, nullptr);
			aad = testlib_hexstr2buf(str, &aadlen);
			str = json_object_get_string(jmsg);
			ASSERT_NE(str, nullptr);
			pt = testlib_hexstr2buf(str, &ptlen);
			str = json_object_get_string(jct);
			ASSERT_NE(str, nullptr);
			ct = testlib_hexstr2buf(str, &ctlen);
			str = json_object_get_string(jresult);
			ASSERT_NE(str, nullptr);
			if (strcmp(str, "valid") == 0 || strcmp(str, "acceptable") == 0)
				valid = 1;
			else
				valid = 0;

			for (k = 0; k < (size_t)json_object_array_length(jflags); k++) {
				jtmp = json_object_array_get_idx(jflags, k);
				ASSERT_NE(jtmp, nullptr);
				str = json_object_get_string(jtmp);
				if (strcmp(str, "LongIv") == 0)
					ivlen0 = 1;
				else
					ivlen0 = 0;
				str = json_object_get_string(jtmp);
				if (strcmp(str, "InvalidNonceSize") == 0)
					nonce0 = 1;
				else
					nonce0 = 0;
				str = json_object_get_string(jtmp);
				if (strcmp(str, "InvalidTagSize") == 0)
					tag0 = 1;
				else
					tag0 = 0;
			}

			max = ptlen > ctlen ? ptlen : ctlen;

			pt_out = NULL;
			ct_out = NULL;
			if (max > 0) {
				pt_out = (unsigned char *)calloc(1, max);
				ASSERT_NE(pt_out, nullptr);
				ct_out = (unsigned char *)calloc(1, max);
				ASSERT_NE(ct_out, nullptr);
			}

			rc = zpc_aes_key_import_clear(aes_key, key);
			EXPECT_EQ(rc, 0);

			rc = zpc_aes_ccm_set_key(aes_ccm, aes_key);
			EXPECT_EQ(rc, 0);
			rc = zpc_aes_ccm_set_iv(aes_ccm, (ivlen0 || nonce0) ? (unsigned char *)1 : iv, ivsize / 8);
			EXPECT_EQ(rc, (ivlen0 || nonce0) ? ZPC_ERROR_IVSIZE : 0);

			if (!ivlen0 && !nonce0) {
				rc = zpc_aes_ccm_encrypt(aes_ccm, ct_out, tag_out, tagsize / 8, aad, aadlen, pt, ptlen);
				EXPECT_EQ(rc, tag0 ? ZPC_ERROR_TAGSIZE : 0);
				if (rc == 0) {
					EXPECT_TRUE(memcmp(ct_out, ct, ctlen) == 0);
					if (valid) {
						EXPECT_TRUE(memcmp(tag_out, tag, tagsize / 8) == 0);
					}
				}

				rc = zpc_aes_ccm_set_iv(aes_ccm, iv, ivsize / 8);
				EXPECT_EQ(rc, 0);

				rc = zpc_aes_ccm_decrypt(aes_ccm, pt_out, tag, tagsize / 8, aad, aadlen, ct, ctlen);
				EXPECT_EQ(rc, tag0 ? ZPC_ERROR_TAGSIZE :  (valid ? 0 : ZPC_ERROR_TAGMISMATCH));
				if (rc == 0) {
					EXPECT_TRUE(memcmp(pt_out, pt, ptlen) == 0);
				}
			}

			/* Unset key. */
			rc = zpc_aes_ccm_set_key(aes_ccm, NULL);
			EXPECT_EQ(rc, 0);

			free(key); key = NULL;
			free(iv); iv = NULL;
			free(aad); aad = NULL;
			free(pt); pt = NULL;
			free(pt_out); pt_out = NULL;
			free(ct); ct = NULL;
			free(ct_out); ct_out = NULL;
			free(tag); tag = NULL;
			free(tag_out); tag_out = NULL;
		}
	}
	zpc_aes_ccm_free(&aes_ccm);
	EXPECT_EQ(aes_ccm, nullptr);
	zpc_aes_key_free(&aes_key);
	EXPECT_EQ(aes_key, nullptr);
}

TEST(aes_ccm, rederive_protected_key1)
{
	struct zpc_aes_key *aes_key1;
	struct zpc_aes_ccm *aes_ccm1, *aes_ccm2, *aes_ccm3;
	u8 iv[12], aad[99], m[99], tag[16], c[99]; /* use ivlen != 12 bytes such that it must be processed by kma */
	int rc, size;

	TESTLIB_ENV_AES_KEY_CHECK();
	size = testlib_env_aes_key_size();

	rc = zpc_aes_key_alloc(&aes_key1);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_ccm_alloc(&aes_ccm1);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_ccm_alloc(&aes_ccm2);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_ccm_alloc(&aes_ccm3);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_ccm_set_key(aes_ccm1, NULL);   /* Unset key. */
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_ccm_set_key(aes_ccm2, NULL);   /* Unset key. */
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_ccm_set_key(aes_ccm3, NULL);   /* Unset key. */
	EXPECT_EQ(rc, 0);

	/* Random protected keys cannot be re-derived. */

	rc = zpc_aes_key_set_mkvp(aes_key1, NULL);   /* Unset apqns. */
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_key_set_size(aes_key1, size);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_key_generate(aes_key1);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_ccm_set_key(aes_ccm1, aes_key1);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_ccm_set_iv(aes_ccm1, iv, sizeof(iv));
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_ccm_set_key(aes_ccm2, aes_key1);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_ccm_set_iv(aes_ccm2, iv, sizeof(iv));
	EXPECT_EQ(rc, 0);
	memset(aes_ccm2->param_kma.protkey, 0, sizeof(aes_ccm2->param_kma.protkey));
	memset(aes_ccm2->param_kmac.protkey, 0, sizeof(aes_ccm2->param_kmac.protkey));
	rc = zpc_aes_ccm_encrypt(aes_ccm2, c, tag, 12, aad, 99, m, 99);
	EXPECT_EQ(rc, ZPC_ERROR_PROTKEYONLY);

	rc = zpc_aes_ccm_set_key(aes_ccm3, aes_key1);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_ccm_set_iv(aes_ccm3, iv, sizeof(iv));
	EXPECT_EQ(rc, 0);
	memset(aes_ccm3->param_kma.protkey, 0, sizeof(aes_ccm3->param_kma.protkey));
	memset(aes_ccm2->param_kma.protkey, 0, sizeof(aes_ccm2->param_kmac.protkey));
	rc = zpc_aes_ccm_decrypt(aes_ccm3, m, tag, 12, aad, 99, c, 99);
	EXPECT_EQ(rc, ZPC_ERROR_PROTKEYONLY);

	rc = zpc_aes_ccm_set_key(aes_ccm1, aes_key1);
	EXPECT_EQ(rc, 0);

	zpc_aes_ccm_free(&aes_ccm3);
	zpc_aes_ccm_free(&aes_ccm2);
	zpc_aes_ccm_free(&aes_ccm1);
	zpc_aes_key_free(&aes_key1);
	EXPECT_EQ(aes_ccm3, nullptr);
	EXPECT_EQ(aes_ccm2, nullptr);
	EXPECT_EQ(aes_ccm1, nullptr);
	EXPECT_EQ(aes_key1, nullptr);
}

TEST(aes_ccm, rederive_protected_key2)
{
	TESTLIB_ENV_AES_KEY_CHECK();

	size_t keylen, ivlen, msglen, ctlen, taglen, aadlen;
	unsigned char buf[4096], mac[16];
	const char *mkvp, *apqns[257];
	struct zpc_aes_key *aes_key;
	struct zpc_aes_ccm *aes_ccm;
	unsigned int flags;
	int type, rc;

	const char *keystr = "e258b117c2fdd75587f07b400ae4af3e673a51dcf761e4ca";
	const char *ivstr = "5ead03aa8c720d21b77075db";
	const char *aadstr = "27702950960b9c79";
	const char *msgstr = "afe96113a684bc52a6d962cf2724f6791d";
	const char *ctstr = "7830446f333057d996a1a79b21c68d8b43";
	const char *tagstr = "72ac478a66f5637563f1f12c1d0267ca";

	u8 *key = testlib_hexstr2buf(keystr, &keylen);
	ASSERT_NE(key, nullptr);
	u8 *iv = testlib_hexstr2buf(ivstr, &ivlen);
	ASSERT_NE(iv, nullptr);
	u8 *aad = testlib_hexstr2buf(aadstr, &aadlen);
	ASSERT_NE(aad, nullptr);
	u8 *msg = testlib_hexstr2buf(msgstr, &msglen);
	ASSERT_NE(msg, nullptr);
	u8 *ct = testlib_hexstr2buf(ctstr, &ctlen);
	ASSERT_NE(ct, nullptr);
	u8 *tag = testlib_hexstr2buf(tagstr, &taglen);
	ASSERT_NE(tag, nullptr);

	type = testlib_env_aes_key_type();
	flags = testlib_env_aes_key_flags();
	mkvp = testlib_env_aes_key_mkvp();
	(void)testlib_env_aes_key_apqns(apqns);

	rc = zpc_aes_key_alloc(&aes_key);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_ccm_alloc(&aes_ccm);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_key_set_type(aes_key, type);
	EXPECT_EQ(rc, 0);
	if (mkvp != NULL) {
		rc = zpc_aes_key_set_mkvp(aes_key, mkvp);
		EXPECT_EQ(rc, 0);
	} else {
		rc = zpc_aes_key_set_apqns(aes_key, apqns);
		EXPECT_EQ(rc, 0);
	}
	rc = zpc_aes_key_set_flags(aes_key, flags);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_key_set_size(aes_key, keylen * 8);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_key_import_clear(aes_key, key);
	EXPECT_EQ(rc, 0);

	/* Encrypt */
	memcpy(buf, msg, msglen);

	rc = zpc_aes_ccm_set_key(aes_ccm, aes_key);
	EXPECT_EQ(rc, 0);
	memset(aes_ccm->param_kmac.protkey, 0, sizeof(aes_ccm->param_kmac.protkey));    /* force WKaVP mismatch */
	rc = zpc_aes_ccm_set_iv(aes_ccm, iv, ivlen);
	EXPECT_EQ(rc, 0);

	memset(aes_ccm->param_kmac.protkey, 0, sizeof(aes_ccm->param_kmac.protkey));    /* force WKaVP mismatch */
	memset(aes_ccm->param_kma.protkey, 0, sizeof(aes_ccm->param_kma.protkey));    /* force WKaVP mismatch */
	rc = zpc_aes_ccm_encrypt(aes_ccm, buf, mac, taglen, aad, aadlen, buf, msglen);
	EXPECT_EQ(rc, 0);

	EXPECT_TRUE(memcmp(buf, ct, ctlen) == 0);
	EXPECT_TRUE(memcmp(mac, tag, taglen) == 0);

	/* Encrypt */
	memcpy(buf, msg, msglen);

	rc = zpc_aes_ccm_set_key(aes_ccm, aes_key);
	EXPECT_EQ(rc, 0);
	memset(aes_ccm->param_kmac.protkey, 0, sizeof(aes_ccm->param_kmac.protkey));    /* force WKaVP mismatch */
	memset(aes_ccm->param_kma.protkey, 0, sizeof(aes_ccm->param_kma.protkey));    /* force WKaVP mismatch */
	rc = zpc_aes_ccm_set_iv(aes_ccm, iv, ivlen);
	EXPECT_EQ(rc, 0);

	memset(aes_ccm->param_kmac.protkey, 0, sizeof(aes_ccm->param_kmac.protkey));    /* force WKaVP mismatch */
	memset(aes_ccm->param_kma.protkey, 0, sizeof(aes_ccm->param_kma.protkey));    /* force WKaVP mismatch */
	rc = zpc_aes_ccm_encrypt(aes_ccm, buf, mac, taglen, aad, aadlen, buf, msglen);
	EXPECT_EQ(rc, 0);
	EXPECT_EQ(rc, 0);

	EXPECT_TRUE(memcmp(buf, ct, ctlen) == 0);
	EXPECT_TRUE(memcmp(mac, tag, taglen) == 0);

	/* Decrypt */
	memcpy(buf, ct, ctlen);

	memset(aes_ccm->param_kmac.protkey, 0, sizeof(aes_ccm->param_kmac.protkey));    /* force WKaVP mismatch */
	memset(aes_ccm->param_kma.protkey, 0, sizeof(aes_ccm->param_kma.protkey));    /* force WKaVP mismatch */
	rc = zpc_aes_ccm_set_iv(aes_ccm, iv, ivlen);
	EXPECT_EQ(rc, 0);

	memset(aes_ccm->param_kmac.protkey, 0, sizeof(aes_ccm->param_kmac.protkey));    /* force WKaVP mismatch */
	memset(aes_ccm->param_kma.protkey, 0, sizeof(aes_ccm->param_kma.protkey));    /* force WKaVP mismatch */
	rc = zpc_aes_ccm_decrypt(aes_ccm, buf, tag, taglen, aad, aadlen, buf, ctlen);
	EXPECT_EQ(rc, 0);

	EXPECT_TRUE(memcmp(buf, msg, msglen) == 0);

	/* Decrypt */
	memcpy(buf, ct, ctlen);

	memset(aes_ccm->param_kmac.protkey, 0, sizeof(aes_ccm->param_kmac.protkey));    /* force WKaVP mismatch */
	memset(aes_ccm->param_kma.protkey, 0, sizeof(aes_ccm->param_kma.protkey));    /* force WKaVP mismatch */
	rc = zpc_aes_ccm_set_iv(aes_ccm, iv, ivlen);
	EXPECT_EQ(rc, 0);

	memcpy(buf, ct, ctlen);

	memset(aes_ccm->param_kmac.protkey, 0, sizeof(aes_ccm->param_kmac.protkey));    /* force WKaVP mismatch */
	memset(aes_ccm->param_kma.protkey, 0, sizeof(aes_ccm->param_kma.protkey));    /* force WKaVP mismatch */
	rc = zpc_aes_ccm_decrypt(aes_ccm, buf, tag, taglen, aad, aadlen, buf, ctlen);
	EXPECT_EQ(rc, 0);

	EXPECT_TRUE(memcmp(buf, msg, msglen) == 0);

	zpc_aes_ccm_free(&aes_ccm);
	EXPECT_EQ(aes_ccm, nullptr);
	zpc_aes_key_free(&aes_key);
	EXPECT_EQ(aes_key, nullptr);

	free(key);
	free(iv);
	free(aad);
	free(msg);
	free(ct);
	free(tag);
}

TEST(aes_ccm, reencipher)
{
	TESTLIB_ENV_AES_KEY_CHECK();

	size_t keylen, ivlen, msglen, ctlen, taglen, aadlen;
	unsigned char buf[4096], mac[16];
	const char *mkvp, *apqns[257];
	struct zpc_aes_key *aes_key;
	struct zpc_aes_ccm *aes_ccm;
	unsigned int flags;
	int type, rc;

	const char *keystr = "e258b117c2fdd75587f07b400ae4af3e673a51dcf761e4ca";
	const char *ivstr = "5ead03aa8c720d21b77075db";
	const char *aadstr = "27702950960b9c79";
	const char *msgstr = "afe96113a684bc52a6d962cf2724f6791d";
	const char *ctstr = "7830446f333057d996a1a79b21c68d8b43";
	const char *tagstr = "72ac478a66f5637563f1f12c1d0267ca";

	u8 *key = testlib_hexstr2buf(keystr, &keylen);
	ASSERT_NE(key, nullptr);
	u8 *iv = testlib_hexstr2buf(ivstr, &ivlen);
	ASSERT_NE(iv, nullptr);
	u8 *aad = testlib_hexstr2buf(aadstr, &aadlen);
	ASSERT_NE(aad, nullptr);
	u8 *msg = testlib_hexstr2buf(msgstr, &msglen);
	ASSERT_NE(msg, nullptr);
	u8 *ct = testlib_hexstr2buf(ctstr, &ctlen);
	ASSERT_NE(ct, nullptr);
	u8 *tag = testlib_hexstr2buf(tagstr, &taglen);
	ASSERT_NE(tag, nullptr);

	type = testlib_env_aes_key_type();
	flags = testlib_env_aes_key_flags();
	mkvp = testlib_env_aes_key_mkvp();
	(void)testlib_env_aes_key_apqns(apqns);

	rc = zpc_aes_key_alloc(&aes_key);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_ccm_alloc(&aes_ccm);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_key_set_type(aes_key, type);
	EXPECT_EQ(rc, 0);
	if (mkvp != NULL) {
		rc = zpc_aes_key_set_mkvp(aes_key, mkvp);
		EXPECT_EQ(rc, 0);
	} else {
		rc = zpc_aes_key_set_apqns(aes_key, apqns);
		EXPECT_EQ(rc, 0);
	}
	rc = zpc_aes_key_set_flags(aes_key, flags);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_key_set_size(aes_key, keylen * 8);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_key_import_clear(aes_key, key);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_key_reencipher(aes_key, ZPC_AES_KEY_REENCIPHER_CURRENT_TO_NEW);
	EXPECT_EQ(rc, 0);
	memset(&aes_key->cur, 0, sizeof(aes_key->cur));     /* destroy current secure key */

	/* Encrypt */
	memcpy(buf, msg, msglen);

	rc = zpc_aes_ccm_set_key(aes_ccm, aes_key);
	EXPECT_EQ(rc, 0);
	memset(&aes_key->prot, 0, sizeof(aes_key->prot));    /* destroy cached protected key */
	memset(aes_ccm->param_kma.protkey, 0, sizeof(aes_ccm->param_kma.protkey));    /* force WKaVP mismatch */
	memset(aes_ccm->param_kmac.protkey, 0, sizeof(aes_ccm->param_kmac.protkey));    /* force WKaVP mismatch */
	rc = zpc_aes_ccm_set_iv(aes_ccm, iv, ivlen);
	EXPECT_EQ(rc, 0);

	memset(&aes_key->prot, 0, sizeof(aes_key->prot));    /* destroy cached protected key */
	memset(aes_ccm->param_kma.protkey, 0, sizeof(aes_ccm->param_kma.protkey));    /* force WKaVP mismatch */
	memset(aes_ccm->param_kmac.protkey, 0, sizeof(aes_ccm->param_kmac.protkey));    /* force WKaVP mismatch */
	rc = zpc_aes_ccm_encrypt(aes_ccm, buf, mac, taglen, aad, aadlen, buf, msglen);
	EXPECT_EQ(rc, 0);

	EXPECT_TRUE(memcmp(buf, ct, ctlen) == 0);
	EXPECT_TRUE(memcmp(mac, tag, taglen) == 0);

	/* Encrypt */
	memcpy(buf, msg, msglen);

	rc = zpc_aes_ccm_set_key(aes_ccm, aes_key);
	EXPECT_EQ(rc, 0);
	memset(&aes_key->prot, 0, sizeof(aes_key->prot));    /* destroy cached protected key */
	memset(aes_ccm->param_kma.protkey, 0, sizeof(aes_ccm->param_kma.protkey));    /* force WKaVP mismatch */
	memset(aes_ccm->param_kmac.protkey, 0, sizeof(aes_ccm->param_kmac.protkey));    /* force WKaVP mismatch */
	rc = zpc_aes_ccm_set_iv(aes_ccm, iv, ivlen);
	EXPECT_EQ(rc, 0);

	memset(&aes_key->prot, 0, sizeof(aes_key->prot));    /* destroy cached protected key */
	memset(aes_ccm->param_kma.protkey, 0, sizeof(aes_ccm->param_kma.protkey));    /* force WKaVP mismatch */
	memset(aes_ccm->param_kmac.protkey, 0, sizeof(aes_ccm->param_kmac.protkey));    /* force WKaVP mismatch */
	rc = zpc_aes_ccm_encrypt(aes_ccm, buf, mac, taglen, aad, aadlen, buf, msglen);
	EXPECT_EQ(rc, 0);

	EXPECT_TRUE(memcmp(buf, ct, ctlen) == 0);
	EXPECT_TRUE(memcmp(mac, tag, taglen) == 0);

	/* Decrypt */
	memcpy(buf, ct, ctlen);

	memset(&aes_key->prot, 0, sizeof(aes_key->prot));    /* destroy cached protected key */
	memset(aes_ccm->param_kmac.protkey, 0, sizeof(aes_ccm->param_kmac.protkey));    /* force WKaVP mismatch */
	memset(aes_ccm->param_kma.protkey, 0, sizeof(aes_ccm->param_kma.protkey));    /* force WKaVP mismatch */
	rc = zpc_aes_ccm_set_iv(aes_ccm, iv, ivlen);
	EXPECT_EQ(rc, 0);

	memset(&aes_key->prot, 0, sizeof(aes_key->prot));    /* destroy cached protected key */
	memset(aes_ccm->param_kmac.protkey, 0, sizeof(aes_ccm->param_kmac.protkey));    /* force WKaVP mismatch */
	memset(aes_ccm->param_kma.protkey, 0, sizeof(aes_ccm->param_kma.protkey));    /* force WKaVP mismatch */
	rc = zpc_aes_ccm_decrypt(aes_ccm, buf, tag, taglen, aad, aadlen, buf, msglen);
	EXPECT_EQ(rc, 0);

	EXPECT_TRUE(memcmp(buf, msg, msglen) == 0);

	/* Decrypt */
	memcpy(buf, ct, ctlen);

	memset(&aes_key->prot, 0, sizeof(aes_key->prot));    /* destroy cached protected key */
	memset(aes_ccm->param_kmac.protkey, 0, sizeof(aes_ccm->param_kmac.protkey));    /* force WKaVP mismatch */
	rc = zpc_aes_ccm_set_iv(aes_ccm, iv, ivlen);
	EXPECT_EQ(rc, 0);

	memset(&aes_key->prot, 0, sizeof(aes_key->prot));    /* destroy cached protected key */
	memset(aes_ccm->param_kma.protkey, 0, sizeof(aes_ccm->param_kma.protkey));    /* force WKaVP mismatch */
	memset(aes_ccm->param_kmac.protkey, 0, sizeof(aes_ccm->param_kmac.protkey));    /* force WKaVP mismatch */
	rc = zpc_aes_ccm_decrypt(aes_ccm, buf, tag, taglen, aad, aadlen, buf, msglen);
	EXPECT_EQ(rc, 0);

	EXPECT_TRUE(memcmp(buf, msg, msglen) == 0);

	zpc_aes_ccm_free(&aes_ccm);
	EXPECT_EQ(aes_ccm, nullptr);
	zpc_aes_key_free(&aes_key);
	EXPECT_EQ(aes_key, nullptr);

	free(key);
	free(iv);
	free(aad);
	free(msg);
	free(ct);
	free(tag);
}

static void
__task(struct zpc_aes_key *aes_key)
{
	struct zpc_aes_ccm *aes_ccm;
	unsigned char buf[4096], mac[16];
	size_t ivlen, msglen, ctlen, taglen, aadlen;
	int rc, i;

	const char *ivstr = "5ead03aa8c720d21b77075db";
	const char *aadstr = "27702950960b9c79";
	const char *msgstr = "afe96113a684bc52a6d962cf2724f6791d";
	const char *ctstr = "7830446f333057d996a1a79b21c68d8b43";
	const char *tagstr = "72ac478a66f5637563f1f12c1d0267ca";

	u8 *iv = testlib_hexstr2buf(ivstr, &ivlen);
	ASSERT_NE(iv, nullptr);
	u8 *aad = testlib_hexstr2buf(aadstr, &aadlen);
	ASSERT_NE(aad, nullptr);
	u8 *msg = testlib_hexstr2buf(msgstr, &msglen);
	ASSERT_NE(msg, nullptr);
	u8 *ct = testlib_hexstr2buf(ctstr, &ctlen);
	ASSERT_NE(ct, nullptr);
	u8 *tag = testlib_hexstr2buf(tagstr, &taglen);
	ASSERT_NE(tag, nullptr);

	rc = zpc_aes_ccm_alloc(&aes_ccm);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_ccm_set_key(aes_ccm, aes_key);
	EXPECT_EQ(rc, 0);

	for (i = 0; i < 1000; i++) {
		/* Encrypt */
		memcpy(buf, msg, msglen);

		memset(aes_ccm->param_kmac.protkey, 0, sizeof(aes_ccm->param_kmac.protkey));    /* force WKaVP mismatch */
		rc = zpc_aes_ccm_set_iv(aes_ccm, iv, ivlen);
		EXPECT_EQ(rc, 0);

		memset(aes_ccm->param_kmac.protkey, 0, sizeof(aes_ccm->param_kmac.protkey));    /* force WKaVP mismatch */
		rc = zpc_aes_ccm_encrypt(aes_ccm, buf, mac, taglen, aad, aadlen, buf, msglen);
		EXPECT_EQ(rc, 0);

		EXPECT_TRUE(memcmp(buf, ct, ctlen) == 0);
		EXPECT_TRUE(memcmp(mac, tag, taglen) == 0);

		/* Decrypt */
		memcpy(buf, ct, ctlen);

		rc = zpc_aes_ccm_set_iv(aes_ccm, iv, ivlen);
		EXPECT_EQ(rc, 0);

		memset(aes_ccm->param_kmac.protkey, 0, sizeof(aes_ccm->param_kmac.protkey));    /* force WKaVP mismatch */
		rc = zpc_aes_ccm_decrypt(aes_ccm, buf, tag, taglen, aad, aadlen, buf, msglen);
		EXPECT_EQ(rc, 0);

		EXPECT_TRUE(memcmp(buf, msg, msglen) == 0);
	}

	zpc_aes_ccm_free(&aes_ccm);
	EXPECT_EQ(aes_ccm, nullptr);

	free(iv);
	free(aad);
	free(msg);
	free(ct);
	free(tag);
}

TEST(aes_ccm, threads)
{
	TESTLIB_ENV_AES_KEY_CHECK();

	size_t keylen;
	const char *mkvp, *apqns[257];
	struct zpc_aes_key *aes_key;
	unsigned int flags;
	int type, rc, i;
	std::thread *t[500];

	const char *keystr = "e258b117c2fdd75587f07b400ae4af3e673a51dcf761e4ca";

	u8 *key = testlib_hexstr2buf(keystr, &keylen);

	type = testlib_env_aes_key_type();
	flags = testlib_env_aes_key_flags();
	mkvp = testlib_env_aes_key_mkvp();
	(void)testlib_env_aes_key_apqns(apqns);

	rc = zpc_aes_key_alloc(&aes_key);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_key_set_type(aes_key, type);
	EXPECT_EQ(rc, 0);
	if (mkvp != NULL) {
		rc = zpc_aes_key_set_mkvp(aes_key, mkvp);
		EXPECT_EQ(rc, 0);
	} else {
		rc = zpc_aes_key_set_apqns(aes_key, apqns);
		EXPECT_EQ(rc, 0);
	}
	rc = zpc_aes_key_set_flags(aes_key, flags);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_key_set_size(aes_key, keylen * 8);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_key_import_clear(aes_key, key);
	EXPECT_EQ(rc, 0);

	for (i = 0; i < 500; i++) {
		t[i] = new std::thread(__task, aes_key);
	}

	/* Do something with key object while threads are working with it. */
	rc = zpc_aes_key_reencipher(aes_key, ZPC_AES_KEY_REENCIPHER_CURRENT_TO_NEW);
	EXPECT_EQ(rc, 0);
	memset(&aes_key->cur, 0, sizeof(aes_key->cur));     /* destroy current secure key */
 
	for (i = 0; i < 500; i++) {
		memset(&aes_key->prot, 0, sizeof(aes_key->prot));    /* destroy cached protected key */
		usleep(1);
	}

	for (i = 0; i < 500; i++) {
		t[i]->join();
		delete t[i];
	}

	zpc_aes_key_free(&aes_key);
	EXPECT_EQ(aes_key, nullptr);

	free(key);
}
