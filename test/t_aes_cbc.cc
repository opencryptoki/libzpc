/*
 * Copyright IBM Corp. 2021
 *
 * libzpc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "testlib.h"

#include "gtest/gtest.h"
#include "zpc/aes_cbc.h"
#include "zpc/error.h"

#include "aes_key_local.h"  /* de-opaquify struct zpc_aes_key */
#include "aes_cbc_local.h"  /* de-opaquify struct zpc_aes_cbc */

#include <json-c/json.h>
#include <stdio.h>
#include <thread>
#include <unistd.h>

static void __run_json(const char *json);

TEST(aes_cbc, alloc)
{
	struct zpc_aes_cbc *aes_cbc;
	int rc;

	TESTLIB_ENV_AES_KEY_CHECK();

	TESTLIB_AES_CBC_HW_CAPS_CHECK();

	rc = zpc_aes_cbc_alloc(NULL);
	EXPECT_EQ(rc, ZPC_ERROR_ARG1NULL);

	aes_cbc = NULL;
	rc = zpc_aes_cbc_alloc(&aes_cbc);
	EXPECT_EQ(rc, 0);
	zpc_aes_cbc_free(&aes_cbc);
	EXPECT_EQ(aes_cbc, nullptr);

	aes_cbc = (struct zpc_aes_cbc *)&aes_cbc;
	rc = zpc_aes_cbc_alloc(&aes_cbc);
	EXPECT_EQ(rc, 0);
	zpc_aes_cbc_free(&aes_cbc);
	EXPECT_EQ(aes_cbc, nullptr);
}

TEST(aes_cbc, free)
{
	struct zpc_aes_cbc *aes_cbc;
	int rc;

	TESTLIB_ENV_AES_KEY_CHECK();

	TESTLIB_AES_CBC_HW_CAPS_CHECK();

	zpc_aes_cbc_free(NULL);

	aes_cbc = NULL;
	zpc_aes_cbc_free(&aes_cbc);
	EXPECT_EQ(aes_cbc, nullptr);

	rc = zpc_aes_cbc_alloc(&aes_cbc);
	EXPECT_EQ(rc, 0);
	zpc_aes_cbc_free(&aes_cbc);
	EXPECT_EQ(aes_cbc, nullptr);
}

TEST(aes_cbc, set_key)
{
	struct zpc_aes_key *aes_key;
	struct zpc_aes_cbc *aes_cbc;
	u8 clearkey[32], iv[16];
	unsigned int flags = 0;
	const char *mkvp, *apqns[257];
	int rc, size, type;

	TESTLIB_ENV_AES_KEY_CHECK();

	TESTLIB_AES_CBC_HW_CAPS_CHECK();

	size = testlib_env_aes_key_size();
	type = testlib_env_aes_key_type();
	flags = testlib_env_aes_key_flags();
	mkvp = testlib_env_aes_key_mkvp();
	(void)testlib_env_aes_key_apqns(apqns);

	TESTLIB_AES_KERNEL_CAPS_CHECK(type);

	TESTLIB_AES_SW_CAPS_CHECK(type);

	TESTLIB_APQN_CAPS_CHECK(apqns, mkvp, type, size, flags);

	rc = zpc_aes_key_alloc(&aes_key);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_cbc_alloc(&aes_cbc);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_cbc_set_key(aes_cbc, aes_key);
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

	if (type != ZPC_AES_KEY_TYPE_PVSECRET) {
		rc = zpc_aes_key_import_clear(aes_key, clearkey);
		EXPECT_EQ(rc, 0);
	} else {
		rc = testlib_set_aes_key_from_pvsecret(aes_key, size);
		if (rc)
			goto ret;
	}

	rc = zpc_aes_cbc_set_key(NULL, NULL);
	EXPECT_EQ(rc, ZPC_ERROR_ARG1NULL);
	rc = zpc_aes_cbc_set_key(NULL, aes_key);
	EXPECT_EQ(rc, ZPC_ERROR_ARG1NULL);

	rc = zpc_aes_cbc_set_key(aes_cbc, NULL);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_cbc_set_iv(aes_cbc, iv);
	EXPECT_EQ(rc, ZPC_ERROR_KEYNOTSET);
	rc = zpc_aes_cbc_set_key(aes_cbc, aes_key);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_cbc_set_iv(aes_cbc, iv);
	EXPECT_EQ(rc, 0);

ret:
	zpc_aes_cbc_free(&aes_cbc);
	EXPECT_EQ(aes_cbc, nullptr);
	zpc_aes_key_free(&aes_key);
	EXPECT_EQ(aes_key, nullptr);
}

TEST(aes_cbc, set_iv)
{
	struct zpc_aes_key *aes_key;
	struct zpc_aes_cbc *aes_cbc;
	const char *mkvp, *apqns[257];
	u8 iv[16];
	int rc, size, type;
	unsigned int flags;

	TESTLIB_ENV_AES_KEY_CHECK();

	TESTLIB_AES_CBC_HW_CAPS_CHECK();

	size = testlib_env_aes_key_size();
	type = testlib_env_aes_key_type();
	flags = testlib_env_aes_key_flags();
	mkvp = testlib_env_aes_key_mkvp();
	(void)testlib_env_aes_key_apqns(apqns);

	TESTLIB_AES_KERNEL_CAPS_CHECK(type);

	TESTLIB_AES_SW_CAPS_CHECK(type);

	TESTLIB_APQN_CAPS_CHECK(apqns, mkvp, type, size, flags);

	rc = zpc_aes_key_alloc(&aes_key);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_cbc_alloc(&aes_cbc);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_cbc_set_iv(NULL, NULL);
	EXPECT_EQ(rc, ZPC_ERROR_ARG1NULL);
	rc = zpc_aes_cbc_set_iv(NULL, iv);
	EXPECT_EQ(rc, ZPC_ERROR_ARG1NULL);

	rc = zpc_aes_cbc_set_iv(aes_cbc, NULL);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_cbc_set_iv(aes_cbc, iv);
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

	if (type != ZPC_AES_KEY_TYPE_PVSECRET) {
		rc = zpc_aes_key_generate(aes_key);
		EXPECT_EQ(rc, 0);
	} else {
		rc = testlib_set_aes_key_from_pvsecret(aes_key, size);
		if (rc)
			goto ret;
	}

	rc = zpc_aes_cbc_set_iv(aes_cbc, iv);
	EXPECT_EQ(rc, ZPC_ERROR_KEYNOTSET);

	rc = zpc_aes_cbc_set_key(aes_cbc, aes_key);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_cbc_set_iv(aes_cbc, iv);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_cbc_set_iv(aes_cbc, iv);
	EXPECT_EQ(rc, 0);

ret:
	zpc_aes_cbc_free(&aes_cbc);
	EXPECT_EQ(aes_cbc, nullptr);
	zpc_aes_key_free(&aes_key);
	EXPECT_EQ(aes_key, nullptr);
}

TEST(aes_cbc, encrypt)
{
	struct zpc_aes_key *aes_key;
	struct zpc_aes_cbc *aes_cbc;
	const char *mkvp, *apqns[257];
	u8 iv[16], m[64], c[64];
	unsigned int flags;
	int rc, size, type;

	TESTLIB_ENV_AES_KEY_CHECK();

	TESTLIB_AES_CBC_HW_CAPS_CHECK();

	size = testlib_env_aes_key_size();
	type = testlib_env_aes_key_type();
	flags = testlib_env_aes_key_flags();
	mkvp = testlib_env_aes_key_mkvp();
	(void)testlib_env_aes_key_apqns(apqns);

	TESTLIB_AES_KERNEL_CAPS_CHECK(type);

	TESTLIB_AES_SW_CAPS_CHECK(type);

	TESTLIB_APQN_CAPS_CHECK(apqns, mkvp, type, size, flags);

	rc = zpc_aes_key_alloc(&aes_key);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_cbc_alloc(&aes_cbc);
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

	if (type != ZPC_AES_KEY_TYPE_PVSECRET) {
		rc = zpc_aes_key_generate(aes_key);
		EXPECT_EQ(rc, 0);
	} else {
		rc = testlib_set_aes_key_from_pvsecret(aes_key, size);
		if (rc)
			goto ret;
	}

	rc = zpc_aes_cbc_set_key(aes_cbc, aes_key);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_cbc_set_iv(aes_cbc, iv);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_cbc_encrypt(aes_cbc, c, m, 64);
	EXPECT_EQ(rc, 0);

ret:
	zpc_aes_cbc_free(&aes_cbc);
	EXPECT_EQ(aes_cbc, nullptr);
	zpc_aes_key_free(&aes_key);
	EXPECT_EQ(aes_key, nullptr);
}

TEST(aes_cbc, decrypt)
{
	struct zpc_aes_key *aes_key;
	struct zpc_aes_cbc *aes_cbc;
	const char *mkvp, *apqns[257];
	u8 iv[16], m[64], c[64];
	unsigned int flags;
	int rc, size, type;

	TESTLIB_ENV_AES_KEY_CHECK();

	TESTLIB_AES_CBC_HW_CAPS_CHECK();

	size = testlib_env_aes_key_size();
	type = testlib_env_aes_key_type();
	flags = testlib_env_aes_key_flags();
	mkvp = testlib_env_aes_key_mkvp();
	(void)testlib_env_aes_key_apqns(apqns);

	TESTLIB_AES_KERNEL_CAPS_CHECK(type);

	TESTLIB_AES_SW_CAPS_CHECK(type);

	TESTLIB_APQN_CAPS_CHECK(apqns, mkvp, type, size, flags);

	rc = zpc_aes_key_alloc(&aes_key);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_cbc_alloc(&aes_cbc);
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

	if (type != ZPC_AES_KEY_TYPE_PVSECRET) {
		rc = zpc_aes_key_generate(aes_key);
		EXPECT_EQ(rc, 0);
	} else {
		rc = testlib_set_aes_key_from_pvsecret(aes_key, size);
		if (rc)
			goto ret;
	}

	rc = zpc_aes_cbc_set_key(aes_cbc, aes_key);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_cbc_set_iv(aes_cbc, iv);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_cbc_decrypt(aes_cbc, m, c, 64);
	EXPECT_EQ(rc, 0);

ret:
	zpc_aes_cbc_free(&aes_cbc);
	EXPECT_EQ(aes_cbc, nullptr);
	zpc_aes_key_free(&aes_key);
	EXPECT_EQ(aes_key, nullptr);
}

TEST(aes_cbc, pc)
{
	struct zpc_aes_key *aes_key1, *aes_key2;
	struct zpc_aes_cbc *aes_cbc1, *aes_cbc2;
	const char *mkvp, *apqns[257];
	u8 iv[16], m[96], c[96], key[32], m_bak[96];
	unsigned int flags;
	int rc, size, type;

	TESTLIB_ENV_AES_KEY_CHECK();

	TESTLIB_AES_CBC_HW_CAPS_CHECK();

	size = testlib_env_aes_key_size();
	type = testlib_env_aes_key_type();
	flags = testlib_env_aes_key_flags();
	mkvp = testlib_env_aes_key_mkvp();
	(void)testlib_env_aes_key_apqns(apqns);

	TESTLIB_AES_KERNEL_CAPS_CHECK(type);

	TESTLIB_AES_SW_CAPS_CHECK(type);

	TESTLIB_APQN_CAPS_CHECK(apqns, mkvp, type, size, flags);

	memcpy(m_bak, m, 96);

	rc = zpc_aes_key_alloc(&aes_key1);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_key_alloc(&aes_key2);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_cbc_alloc(&aes_cbc1);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_cbc_alloc(&aes_cbc2);
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

	if (type != ZPC_AES_KEY_TYPE_PVSECRET) {
		rc = zpc_aes_key_import_clear(aes_key1, key);
		EXPECT_EQ(rc, 0);
	} else {
		rc = testlib_set_aes_key_from_pvsecret(aes_key1, size);
		if (rc)
			goto ret;
	}

	rc = zpc_aes_cbc_set_key(aes_cbc1, aes_key1);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_cbc_set_iv(aes_cbc1, iv);
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

	if (type != ZPC_AES_KEY_TYPE_PVSECRET) {
		rc = zpc_aes_key_import_clear(aes_key2, key);
		EXPECT_EQ(rc, 0);
	} else {
		rc = testlib_set_aes_key_from_pvsecret(aes_key2, size);
		if (rc)
			goto ret;
	}

	rc = zpc_aes_cbc_set_key(aes_cbc2, aes_key2);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_cbc_set_iv(aes_cbc2, iv);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_cbc_encrypt(aes_cbc1, c, m, 96);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_cbc_decrypt(aes_cbc2, m, c, 96);
	EXPECT_EQ(rc, 0);
	EXPECT_TRUE(memcmp(m, m_bak, 96) == 0);
	rc = zpc_aes_cbc_encrypt(aes_cbc2, c, m, 96);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_cbc_decrypt(aes_cbc1, m, c, 96);
	EXPECT_EQ(rc, 0);
	EXPECT_TRUE(memcmp(m, m_bak, 96) == 0);

	rc = zpc_aes_cbc_encrypt(aes_cbc2, c,  m, 96);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_cbc_decrypt(aes_cbc1, m, c, 96);
	EXPECT_EQ(rc, 0);
	EXPECT_TRUE(memcmp(m, m_bak, 96) == 0);
	rc = zpc_aes_cbc_encrypt(aes_cbc1, c, m, 96);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_cbc_decrypt(aes_cbc2, m, c, 96);
	EXPECT_EQ(rc, 0);
	EXPECT_TRUE(memcmp(m, m_bak, 96) == 0);

	/* Random protected key */
	rc = zpc_aes_cbc_set_key(aes_cbc1, NULL);   /* Unset key. */
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_cbc_set_key(aes_cbc2, NULL);   /* Unset key. */
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_key_set_mkvp(aes_key1, NULL);   /* Unset apqns. */
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_key_set_size(aes_key1, size);
	EXPECT_EQ(rc, 0);

	if (type != ZPC_AES_KEY_TYPE_PVSECRET) {
		rc = zpc_aes_key_generate(aes_key1);
		EXPECT_EQ(rc, 0);
	} else {
		rc = testlib_set_aes_key_from_pvsecret(aes_key1, size);
		if (rc)
			goto ret;
	}

	rc = zpc_aes_cbc_set_key(aes_cbc1, aes_key1);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_cbc_set_iv(aes_cbc1, iv);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_cbc_set_key(aes_cbc2, aes_key1);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_cbc_set_iv(aes_cbc2, iv);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_cbc_encrypt(aes_cbc1, c, m, 96);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_cbc_decrypt(aes_cbc2, m, c, 96);
	EXPECT_EQ(rc, 0);
	EXPECT_TRUE(memcmp(m, m_bak, 96) == 0);
	rc = zpc_aes_cbc_encrypt(aes_cbc2, c, m, 96);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_cbc_decrypt(aes_cbc1, m, c, 96);
	EXPECT_EQ(rc, 0);
	EXPECT_TRUE(memcmp(m, m_bak, 96) == 0);

	rc = zpc_aes_cbc_encrypt(aes_cbc2, c, m, 96);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_cbc_decrypt(aes_cbc1, m, c, 96);
	EXPECT_EQ(rc, 0);
	EXPECT_TRUE(memcmp(m, m_bak, 96) == 0);
	rc = zpc_aes_cbc_encrypt(aes_cbc1, c, m, 96);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_cbc_decrypt(aes_cbc2, m, c, 96);
	EXPECT_EQ(rc, 0);
	EXPECT_TRUE(memcmp(m, m_bak, 96) == 0);

ret:
	zpc_aes_cbc_free(&aes_cbc2);
	zpc_aes_cbc_free(&aes_cbc1);
	zpc_aes_key_free(&aes_key2);
	EXPECT_EQ(aes_key2, nullptr);
	zpc_aes_key_free(&aes_key1);
	EXPECT_EQ(aes_key1, nullptr);
}

TEST(aes_cbc, stream_inplace_kat1)
{
	TESTLIB_ENV_AES_KEY_CHECK();

	TESTLIB_AES_CBC_HW_CAPS_CHECK();

	size_t keylen, msglen, ctlen, ivlen;
	unsigned char buf[4096];
	const char *mkvp, *apqns[257];
	struct zpc_aes_key *aes_key;
	struct zpc_aes_cbc *aes_cbc;
	unsigned int flags;
	int type, rc;

	const char *keystr = "b6f9afbfe5a1562bba1368fc72ac9d9c";
	const char *ivstr = "3f9d5ebe250ee7ce384b0d00ee849322";
	const char *msgstr = "db397ec22718dbffb9c9d13de0efcd4611bf792be4fce0dc5f25d4f577ed8cdbd4eb9208d593dda3d4653954ab64f05676caa3ce9bfa795b08b67ceebc923fdc89a8c431188e9e482d8553982cf304d1";
	const char *ctstr = "10ea27b19e16b93af169c4a88e06e35c99d8b420980b058e34b4b8f132b13766f72728202b089f428fecdb41c79f8aa0d0ef68f5786481cca29e2126f69bc14160f1ae2187878ba5c49cf3961e1b7ee9";

	type = testlib_env_aes_key_type();
	flags = testlib_env_aes_key_flags();
	mkvp = testlib_env_aes_key_mkvp();
	(void)testlib_env_aes_key_apqns(apqns);

	TESTLIB_AES_KERNEL_CAPS_CHECK(type);

	TESTLIB_AES_SW_CAPS_CHECK(type);

	TESTLIB_APQN_CAPS_CHECK(apqns, mkvp, type, 256, flags);

	if (type == ZPC_AES_KEY_TYPE_PVSECRET)
		GTEST_SKIP_("Skipping stream_inplace_kat1 test. KATs cannot be performed with UV secrets.");

	u8 *key = testlib_hexstr2buf(keystr, &keylen);
	ASSERT_NE(key, nullptr);
	u8 *iv = testlib_hexstr2buf(ivstr, &ivlen);
	ASSERT_NE(iv, nullptr);
	u8 *msg = testlib_hexstr2buf(msgstr, &msglen);
	ASSERT_NE(msg, nullptr);
	u8 *ct = testlib_hexstr2buf(ctstr, &ctlen);
	ASSERT_NE(ct, nullptr);

	rc = zpc_aes_key_alloc(&aes_key);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_cbc_alloc(&aes_cbc);
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

	rc = zpc_aes_cbc_set_key(aes_cbc, aes_key);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_cbc_set_iv(aes_cbc, iv);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_cbc_encrypt(aes_cbc, buf, buf, 16);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_cbc_encrypt(aes_cbc, buf + 16, buf + 16, msglen - 16);
	EXPECT_EQ(rc, 0);

	EXPECT_TRUE(memcmp(buf, ct, ctlen) == 0);

	/* Encrypt */
	memcpy(buf, msg, msglen);

	rc = zpc_aes_cbc_set_key(aes_cbc, aes_key);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_cbc_set_iv(aes_cbc, iv);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_cbc_encrypt(aes_cbc, buf, buf, 16);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_cbc_encrypt(aes_cbc, buf + 16, buf + 16, msglen - 16);
	EXPECT_EQ(rc, 0);

	EXPECT_TRUE(memcmp(buf, ct, ctlen) == 0);

	/* Decrypt */
	memcpy(buf, ct, ctlen);

	rc = zpc_aes_cbc_set_iv(aes_cbc, iv);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_cbc_decrypt(aes_cbc, buf, buf, 16);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_cbc_decrypt(aes_cbc, buf + 16, buf + 16, msglen - 16);
	EXPECT_EQ(rc, 0);

	EXPECT_TRUE(memcmp(buf, msg, msglen) == 0);

	/* Decrypt */
	memcpy(buf, ct, ctlen);

	rc = zpc_aes_cbc_set_iv(aes_cbc, iv);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_cbc_decrypt(aes_cbc, buf, buf, 16);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_cbc_decrypt(aes_cbc, buf + 16, buf + 16, msglen - 16);
	EXPECT_EQ(rc, 0);

	EXPECT_TRUE(memcmp(buf, msg, msglen) == 0);

	zpc_aes_cbc_free(&aes_cbc);
	EXPECT_EQ(aes_cbc, nullptr);
	zpc_aes_key_free(&aes_key);
	EXPECT_EQ(aes_key, nullptr);

	free(key);
	free(iv);
	free(msg);
	free(ct);
}

TEST(aes_cbc, stream_inplace_kat2)
{
	TESTLIB_ENV_AES_KEY_CHECK();

	TESTLIB_AES_CBC_HW_CAPS_CHECK();

	size_t keylen, ivlen, msglen, ctlen;
	unsigned char buf[4096];
	const char *mkvp, *apqns[257];
	struct zpc_aes_key *aes_key;
	struct zpc_aes_cbc *aes_cbc;
	unsigned int flags;
	int type, rc;

	const char *keystr = "b6f9afbfe5a1562bba1368fc72ac9d9c";
	const char *ivstr = "3f9d5ebe250ee7ce384b0d00ee849322";
	const char *msgstr = "db397ec22718dbffb9c9d13de0efcd4611bf792be4fce0dc5f25d4f577ed8cdbd4eb9208d593dda3d4653954ab64f05676caa3ce9bfa795b08b67ceebc923fdc89a8c431188e9e482d8553982cf304d1";
	const char *ctstr = "10ea27b19e16b93af169c4a88e06e35c99d8b420980b058e34b4b8f132b13766f72728202b089f428fecdb41c79f8aa0d0ef68f5786481cca29e2126f69bc14160f1ae2187878ba5c49cf3961e1b7ee9";

	type = testlib_env_aes_key_type();
	flags = testlib_env_aes_key_flags();
	mkvp = testlib_env_aes_key_mkvp();
	(void)testlib_env_aes_key_apqns(apqns);

	TESTLIB_AES_KERNEL_CAPS_CHECK(type);

	TESTLIB_AES_SW_CAPS_CHECK(type);

	TESTLIB_APQN_CAPS_CHECK(apqns, mkvp, type, 256, flags);

	if (type == ZPC_AES_KEY_TYPE_PVSECRET)
		GTEST_SKIP_("Skipping stream_inplace_kat2 test. KATs cannot be performed with UV secrets.");

	u8 *key = testlib_hexstr2buf(keystr, &keylen);
	ASSERT_NE(key, nullptr);
	u8 *iv = testlib_hexstr2buf(ivstr, &ivlen);
	ASSERT_NE(iv, nullptr);
	u8 *msg = testlib_hexstr2buf(msgstr, &msglen);
	ASSERT_NE(msg, nullptr);
	u8 *ct = testlib_hexstr2buf(ctstr, &ctlen);
	ASSERT_NE(ct, nullptr);

	rc = zpc_aes_key_alloc(&aes_key);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_cbc_alloc(&aes_cbc);
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

	rc = zpc_aes_cbc_set_key(aes_cbc, aes_key);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_cbc_set_iv(aes_cbc, iv);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_cbc_encrypt(aes_cbc, buf, buf, msglen);  /* Works iff msglen == 0 mod 16 */
	EXPECT_EQ(rc, 0);

	EXPECT_TRUE(memcmp(buf, ct, ctlen) == 0);

	/* Decrypt */
	memcpy(buf, ct, ctlen);

	rc = zpc_aes_cbc_set_iv(aes_cbc, iv);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_cbc_decrypt(aes_cbc, buf, buf, msglen);  /* Works iff msglen == 0 mod 16 */
	EXPECT_EQ(rc, 0);

	EXPECT_TRUE(memcmp(buf, msg, msglen) == 0);

	zpc_aes_cbc_free(&aes_cbc);
	EXPECT_EQ(aes_cbc, nullptr);
	zpc_aes_key_free(&aes_key);
	EXPECT_EQ(aes_key, nullptr);

	free(key);
	free(iv);
	free(msg);
	free(ct);
}

TEST(aes_cbc, stream_inplace_kat3)
{
	TESTLIB_ENV_AES_KEY_CHECK();

	TESTLIB_AES_CBC_HW_CAPS_CHECK();

	size_t keylen, ivlen, msglen, ctlen;
	unsigned char buf[4096], iv2[16];
	const char *mkvp, *apqns[257];
	struct zpc_aes_key *aes_key;
	struct zpc_aes_cbc *aes_cbc1, *aes_cbc2;
	unsigned int flags;
	int type, rc;

	const char *keystr = "b6f9afbfe5a1562bba1368fc72ac9d9c";
	const char *ivstr = "3f9d5ebe250ee7ce384b0d00ee849322";
	const char *msgstr = "db397ec22718dbffb9c9d13de0efcd4611bf792be4fce0dc5f25d4f577ed8cdbd4eb9208d593dda3d4653954ab64f05676caa3ce9bfa795b08b67ceebc923fdc89a8c431188e9e482d8553982cf304d1";
	const char *ctstr = "10ea27b19e16b93af169c4a88e06e35c99d8b420980b058e34b4b8f132b13766f72728202b089f428fecdb41c79f8aa0d0ef68f5786481cca29e2126f69bc14160f1ae2187878ba5c49cf3961e1b7ee9";

	type = testlib_env_aes_key_type();
	flags = testlib_env_aes_key_flags();
	mkvp = testlib_env_aes_key_mkvp();
	(void)testlib_env_aes_key_apqns(apqns);

	TESTLIB_AES_KERNEL_CAPS_CHECK(type);

	TESTLIB_AES_SW_CAPS_CHECK(type);

	TESTLIB_APQN_CAPS_CHECK(apqns, mkvp, type, 256, flags);

	if (type == ZPC_AES_KEY_TYPE_PVSECRET)
		GTEST_SKIP_("Skipping stream_inplace_kat3 test. KATs cannot be performed with UV secrets.");

	u8 *key = testlib_hexstr2buf(keystr, &keylen);
	ASSERT_NE(key, nullptr);
	u8 *iv = testlib_hexstr2buf(ivstr, &ivlen);
	ASSERT_NE(iv, nullptr);
	u8 *msg = testlib_hexstr2buf(msgstr, &msglen);
	ASSERT_NE(msg, nullptr);
	u8 *ct = testlib_hexstr2buf(ctstr, &ctlen);
	ASSERT_NE(ct, nullptr);

	rc = zpc_aes_key_alloc(&aes_key);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_cbc_alloc(&aes_cbc1);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_cbc_alloc(&aes_cbc2);
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

	rc = zpc_aes_cbc_set_key(aes_cbc1, aes_key);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_cbc_set_key(aes_cbc2, aes_key);
	EXPECT_EQ(rc, 0);

	/* Encrypt first chunk with first ctx */
	memcpy(buf, msg, msglen);
	rc = zpc_aes_cbc_set_iv(aes_cbc1, iv);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_cbc_encrypt(aes_cbc1, buf, buf, 16);
	EXPECT_EQ(rc, 0);

	/* Get intermediate iv from first ctx */
	rc = zpc_aes_cbc_get_intermediate_iv(aes_cbc1, iv2);
	EXPECT_EQ(rc, 0);

	/* Encrypt a 2nd chunk with 2nd ctx */
	rc = zpc_aes_cbc_set_iv(aes_cbc2, iv);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_cbc_set_intermediate_iv(aes_cbc2, iv2);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_cbc_encrypt(aes_cbc2, buf + 16, buf + 16, msglen - 16);
	EXPECT_EQ(rc, 0);

	EXPECT_TRUE(memcmp(buf, ct, ctlen) == 0);

	/* Decrypt first chunk with first ctx */
	memcpy(buf, ct, ctlen);
	rc = zpc_aes_cbc_set_iv(aes_cbc1, iv);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_cbc_decrypt(aes_cbc1, buf, buf, 16);
	EXPECT_EQ(rc, 0);

	/* Get intermediate iv from first ctx */
	rc = zpc_aes_cbc_get_intermediate_iv(aes_cbc1, iv2);
	EXPECT_EQ(rc, 0);

	/* Decrypt remaining chunk with 2nd ctx */
	rc = zpc_aes_cbc_set_iv(aes_cbc2, iv);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_cbc_set_intermediate_iv(aes_cbc2, iv2);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_cbc_decrypt(aes_cbc2, buf + 16, buf + 16, msglen - 16);
	EXPECT_EQ(rc, 0);

	EXPECT_TRUE(memcmp(buf, msg, msglen) == 0);

	zpc_aes_cbc_free(&aes_cbc1);
	EXPECT_EQ(aes_cbc1, nullptr);
	zpc_aes_cbc_free(&aes_cbc2);
	EXPECT_EQ(aes_cbc2, nullptr);
	zpc_aes_key_free(&aes_key);
	EXPECT_EQ(aes_key, nullptr);

	free(key);
	free(iv);
	free(msg);
	free(ct);
}

TEST(aes_cbc, nist_kat)
{
	int type;

	type = testlib_env_aes_key_type();

	TESTLIB_ENV_AES_KEY_CHECK();

	TESTLIB_AES_CBC_HW_CAPS_CHECK();

	TESTLIB_AES_KERNEL_CAPS_CHECK(type);
	
	TESTLIB_AES_SW_CAPS_CHECK(type);

	if (type == ZPC_AES_KEY_TYPE_PVSECRET)
		GTEST_SKIP_("Skipping nist_kat test. KATs cannot be performed with UV secrets.");

	__run_json("nist_aes_cbc.json");
}

static void __run_json(const char *json)
{
	const char *tv = json, *str;
	const char *mkvp, *apqns[257];
	struct zpc_aes_key *aes_key;
	struct zpc_aes_cbc *aes_cbc;
	unsigned int flags;
	u8 *key = NULL, *iv = NULL;
	u8 *pt = NULL, *pt_out = NULL, *ct = NULL, *ct_out = NULL;
	int rc, keysize = 0;
	size_t ptlen, ctlen, i, j, max;
	json_object *jkey, *jiv, *jmsg, *jct, *jtmp, *jtestgroups, *jfile, *jkeysize, *jtests;
	json_bool b;
	int type;

	type = testlib_env_aes_key_type();
	flags = testlib_env_aes_key_flags();
	mkvp = testlib_env_aes_key_mkvp();
	(void)testlib_env_aes_key_apqns(apqns);

	TESTLIB_AES_SW_CAPS_CHECK(type);

	TESTLIB_APQN_CAPS_CHECK(apqns, mkvp, type, 256, flags);

	rc = zpc_aes_key_alloc(&aes_key);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_cbc_alloc(&aes_cbc);
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
		b = json_object_object_get_ex(jtmp, "tests", &jtests);
		ASSERT_TRUE(b);

		keysize = json_object_get_int(jkeysize);

		rc = zpc_aes_key_set_size(aes_key, keysize);
		EXPECT_EQ(rc, 0);

		for (j = 0; j < (size_t)json_object_array_length(jtests); j++) {
			jtmp = json_object_array_get_idx(jtests, j);
			ASSERT_NE(jtmp, nullptr);

			b = json_object_object_get_ex(jtmp, "key", &jkey);
			ASSERT_TRUE(b);
			b = json_object_object_get_ex(jtmp, "iv", &jiv);
			ASSERT_TRUE(b);
			b = json_object_object_get_ex(jtmp, "msg", &jmsg);
			ASSERT_TRUE(b);
			b = json_object_object_get_ex(jtmp, "ct", &jct);
			ASSERT_TRUE(b);

			str = json_object_get_string(jkey);
			ASSERT_NE(str, nullptr);
			key = testlib_hexstr2buf(str, NULL);
			ASSERT_NE(key, nullptr);
			str = json_object_get_string(jiv);
			ASSERT_NE(str, nullptr);
			iv = testlib_hexstr2buf(str, NULL);
			str = json_object_get_string(jmsg);
			ASSERT_NE(str, nullptr);
			pt = testlib_hexstr2buf(str, &ptlen);
			str = json_object_get_string(jct);
			ASSERT_NE(str, nullptr);
			ct = testlib_hexstr2buf(str, &ctlen);

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

			rc = zpc_aes_cbc_set_key(aes_cbc, aes_key);
			EXPECT_EQ(rc, 0);

			rc = zpc_aes_cbc_set_iv(aes_cbc, iv);
			EXPECT_EQ(rc, 0);
			rc = zpc_aes_cbc_encrypt(aes_cbc, ct_out, pt, ptlen);
			EXPECT_EQ(rc, 0);
			EXPECT_TRUE(memcmp(ct_out, ct, ctlen) == 0);

			rc = zpc_aes_cbc_set_iv(aes_cbc, iv);
			EXPECT_EQ(rc, 0);
			rc = zpc_aes_cbc_decrypt(aes_cbc, pt_out, ct, ctlen);
			EXPECT_EQ(rc, 0);
			EXPECT_TRUE(memcmp(pt_out, pt, ptlen) == 0);

			/* Unset key. */
			rc = zpc_aes_cbc_set_key(aes_cbc, NULL);
			EXPECT_EQ(rc, 0);

			free(key); key = NULL;
			free(iv); iv = NULL;
			free(pt); pt = NULL;
			free(pt_out); pt_out = NULL;
			free(ct); ct = NULL;
			free(ct_out); ct_out = NULL;
		}
	}
	zpc_aes_cbc_free(&aes_cbc);
	EXPECT_EQ(aes_cbc, nullptr);
	zpc_aes_key_free(&aes_key);
	EXPECT_EQ(aes_key, nullptr);
}

TEST(aes_cbc, rederive_protected_key1)
{
	struct zpc_aes_key *aes_key1;
	struct zpc_aes_cbc *aes_cbc1, *aes_cbc2, *aes_cbc3;
	u8 iv[16], m[96], c[96];
	int rc, size, type;

	TESTLIB_ENV_AES_KEY_CHECK();

	TESTLIB_AES_CBC_HW_CAPS_CHECK();

	size = testlib_env_aes_key_size();
	type = testlib_env_aes_key_type();

	TESTLIB_AES_KERNEL_CAPS_CHECK(type);

	rc = zpc_aes_key_alloc(&aes_key1);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_cbc_alloc(&aes_cbc1);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_cbc_alloc(&aes_cbc2);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_cbc_alloc(&aes_cbc3);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_cbc_set_key(aes_cbc1, NULL);   /* Unset key. */
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_cbc_set_key(aes_cbc2, NULL);   /* Unset key. */
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_cbc_set_key(aes_cbc3, NULL);   /* Unset key. */
	EXPECT_EQ(rc, 0);

	/* Random protected keys cannot be re-derived. */

	rc = zpc_aes_key_set_mkvp(aes_key1, NULL);   /* Unset apqns. */
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_key_set_size(aes_key1, size);
	EXPECT_EQ(rc, 0);
	/*
	 * This key obj has no type set. Therefore the generate will work also
	 * for tests with ZPC_TEST_AES_KEY_TYPE = ZPC_AES_KEY_TYPE_PVSECRET.
	 * The generated protected key has no dependency on any secure key or
	 * pvsecret.
	 */
	rc = zpc_aes_key_generate(aes_key1);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_cbc_set_key(aes_cbc1, aes_key1);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_cbc_set_iv(aes_cbc1, iv);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_cbc_set_key(aes_cbc2, aes_key1);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_cbc_set_iv(aes_cbc2, iv);
	EXPECT_EQ(rc, 0);
	memset(aes_cbc2->param.protkey, 0, sizeof(aes_cbc2->param.protkey));
	rc = zpc_aes_cbc_encrypt(aes_cbc2, c, m, 96);
	EXPECT_EQ(rc, ZPC_ERROR_PROTKEYONLY);

	rc = zpc_aes_cbc_set_key(aes_cbc3, aes_key1);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_cbc_set_iv(aes_cbc3, iv);
	EXPECT_EQ(rc, 0);
	memset(aes_cbc3->param.protkey, 0, sizeof(aes_cbc3->param.protkey));
	rc = zpc_aes_cbc_decrypt(aes_cbc3, m, c, 96);
	EXPECT_EQ(rc, ZPC_ERROR_PROTKEYONLY);

	zpc_aes_cbc_free(&aes_cbc3);
	zpc_aes_cbc_free(&aes_cbc2);
	zpc_aes_cbc_free(&aes_cbc1);
	zpc_aes_key_free(&aes_key1);
	EXPECT_EQ(aes_cbc3, nullptr);
	EXPECT_EQ(aes_cbc2, nullptr);
	EXPECT_EQ(aes_cbc1, nullptr);
	EXPECT_EQ(aes_key1, nullptr);
}

TEST(aes_cbc, rederive_protected_key2)
{
	TESTLIB_ENV_AES_KEY_CHECK();

	TESTLIB_AES_CBC_HW_CAPS_CHECK();

	size_t keylen, msglen, ctlen, ivlen;
	unsigned char buf[4096];
	const char *mkvp, *apqns[257];
	struct zpc_aes_key *aes_key;
	struct zpc_aes_cbc *aes_cbc;
	unsigned int flags;
	int type, rc;

	const char *keystr = "b6f9afbfe5a1562bba1368fc72ac9d9c";
	const char *ivstr = "3f9d5ebe250ee7ce384b0d00ee849322";
	const char *msgstr = "db397ec22718dbffb9c9d13de0efcd4611bf792be4fce0dc5f25d4f577ed8cdbd4eb9208d593dda3d4653954ab64f05676caa3ce9bfa795b08b67ceebc923fdc89a8c431188e9e482d8553982cf304d1";
	const char *ctstr = "10ea27b19e16b93af169c4a88e06e35c99d8b420980b058e34b4b8f132b13766f72728202b089f428fecdb41c79f8aa0d0ef68f5786481cca29e2126f69bc14160f1ae2187878ba5c49cf3961e1b7ee9";

	type = testlib_env_aes_key_type();
	flags = testlib_env_aes_key_flags();
	mkvp = testlib_env_aes_key_mkvp();
	(void)testlib_env_aes_key_apqns(apqns);

	TESTLIB_AES_KERNEL_CAPS_CHECK(type);

	TESTLIB_AES_SW_CAPS_CHECK(type);

	TESTLIB_APQN_CAPS_CHECK(apqns, mkvp, type, 128, flags);

	u8 *key = testlib_hexstr2buf(keystr, &keylen);
	ASSERT_NE(key, nullptr);
	u8 *iv = testlib_hexstr2buf(ivstr, &ivlen);
	ASSERT_NE(iv, nullptr);
	u8 *msg = testlib_hexstr2buf(msgstr, &msglen);
	ASSERT_NE(msg, nullptr);
	u8 *ct = testlib_hexstr2buf(ctstr, &ctlen);
	ASSERT_NE(ct, nullptr);

	rc = zpc_aes_key_alloc(&aes_key);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_cbc_alloc(&aes_cbc);
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

	if (type != ZPC_AES_KEY_TYPE_PVSECRET) {
		rc = zpc_aes_key_import_clear(aes_key, key);
		EXPECT_EQ(rc, 0);
	} else {
		rc = testlib_set_aes_key_from_pvsecret(aes_key, keylen * 8);
		if (rc)
			goto ret;
	}

	/* Encrypt */
	memcpy(buf, msg, msglen);

	rc = zpc_aes_cbc_set_key(aes_cbc, aes_key);
	EXPECT_EQ(rc, 0);
	memset(aes_cbc->param.protkey, 0, sizeof(aes_cbc->param.protkey));    /* force WKaVP mismatch */
	rc = zpc_aes_cbc_set_iv(aes_cbc, iv);
	EXPECT_EQ(rc, 0);

	memset(aes_cbc->param.protkey, 0, sizeof(aes_cbc->param.protkey));    /* force WKaVP mismatch */
	rc = zpc_aes_cbc_encrypt(aes_cbc, buf, buf, 16);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_cbc_encrypt(aes_cbc, buf + 16, buf + 16, msglen - 16);
	EXPECT_EQ(rc, 0);

	if (type != ZPC_AES_KEY_TYPE_PVSECRET) {
		EXPECT_TRUE(memcmp(buf, ct, ctlen) == 0);
	}

	/* Encrypt */
	memcpy(buf, msg, msglen);

	rc = zpc_aes_cbc_set_key(aes_cbc, aes_key);
	EXPECT_EQ(rc, 0);
	memset(aes_cbc->param.protkey, 0, sizeof(aes_cbc->param.protkey));    /* force WKaVP mismatch */
	rc = zpc_aes_cbc_set_iv(aes_cbc, iv);
	EXPECT_EQ(rc, 0);

	memset(aes_cbc->param.protkey, 0, sizeof(aes_cbc->param.protkey));    /* force WKaVP mismatch */
	rc = zpc_aes_cbc_encrypt(aes_cbc, buf, buf, 16);
	EXPECT_EQ(rc, 0);
	memset(aes_cbc->param.protkey, 0, sizeof(aes_cbc->param.protkey));    /* force WKaVP mismatch */
	rc = zpc_aes_cbc_encrypt(aes_cbc, buf + 16, buf + 16, msglen - 16);
	EXPECT_EQ(rc, 0);

	if (type != ZPC_AES_KEY_TYPE_PVSECRET) {
		EXPECT_TRUE(memcmp(buf, ct, ctlen) == 0);
	}

	/* Decrypt */
	memcpy(buf, ct, ctlen);

	memset(aes_cbc->param.protkey, 0, sizeof(aes_cbc->param.protkey));    /* force WKaVP mismatch */
	rc = zpc_aes_cbc_set_iv(aes_cbc, iv);
	EXPECT_EQ(rc, 0);

	memset(aes_cbc->param.protkey, 0, sizeof(aes_cbc->param.protkey));    /* force WKaVP mismatch */
	rc = zpc_aes_cbc_decrypt(aes_cbc, buf, buf, 16);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_cbc_decrypt(aes_cbc, buf + 16, buf + 16,  msglen - 16);
	EXPECT_EQ(rc, 0);

	if (type != ZPC_AES_KEY_TYPE_PVSECRET) {
		EXPECT_TRUE(memcmp(buf, msg, msglen) == 0);
	}

	/* Decrypt */
	memcpy(buf, ct, ctlen);

	memset(aes_cbc->param.protkey, 0, sizeof(aes_cbc->param.protkey));    /* force WKaVP mismatch */
	rc = zpc_aes_cbc_set_iv(aes_cbc, iv);
	EXPECT_EQ(rc, 0);

	memset(aes_cbc->param.protkey, 0, sizeof(aes_cbc->param.protkey));    /* force WKaVP mismatch */
	rc = zpc_aes_cbc_decrypt(aes_cbc, buf, buf, 16);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_cbc_decrypt(aes_cbc, buf + 16, buf + 16, msglen - 16);
	EXPECT_EQ(rc, 0);

	if (type != ZPC_AES_KEY_TYPE_PVSECRET) {
		EXPECT_TRUE(memcmp(buf, msg, msglen) == 0);
	}

ret:
	zpc_aes_cbc_free(&aes_cbc);
	EXPECT_EQ(aes_cbc, nullptr);
	zpc_aes_key_free(&aes_key);
	EXPECT_EQ(aes_key, nullptr);

	free(key);
	free(iv);
	free(msg);
	free(ct);
}

TEST(aes_cbc, reencipher)
{
	TESTLIB_ENV_AES_KEY_CHECK();

	TESTLIB_AES_CBC_HW_CAPS_CHECK();

	size_t keylen, msglen, ctlen, ivlen;
	unsigned char buf[4096];
	const char *mkvp, *apqns[257];
	struct zpc_aes_key *aes_key;
	struct zpc_aes_cbc *aes_cbc;
	unsigned int flags;
	int type, rc;

	const char *keystr = "b6f9afbfe5a1562bba1368fc72ac9d9c";
	const char *ivstr = "3f9d5ebe250ee7ce384b0d00ee849322";
	const char *msgstr = "db397ec22718dbffb9c9d13de0efcd4611bf792be4fce0dc5f25d4f577ed8cdbd4eb9208d593dda3d4653954ab64f05676caa3ce9bfa795b08b67ceebc923fdc89a8c431188e9e482d8553982cf304d1";
	const char *ctstr = "10ea27b19e16b93af169c4a88e06e35c99d8b420980b058e34b4b8f132b13766f72728202b089f428fecdb41c79f8aa0d0ef68f5786481cca29e2126f69bc14160f1ae2187878ba5c49cf3961e1b7ee9";

	type = testlib_env_aes_key_type();
	flags = testlib_env_aes_key_flags();
	mkvp = testlib_env_aes_key_mkvp();
	(void)testlib_env_aes_key_apqns(apqns);

	TESTLIB_AES_KERNEL_CAPS_CHECK(type);

	TESTLIB_AES_SW_CAPS_CHECK(type);

	TESTLIB_APQN_CAPS_CHECK(apqns, mkvp, type, 128, flags);

	TESTLIB_AES_NEW_MK_CHECK(type, mkvp, apqns);

	if (type == ZPC_AES_KEY_TYPE_PVSECRET)
		GTEST_SKIP_("Skipping reencipher test. Not applicable for UV secrets.");

	u8 *key = testlib_hexstr2buf(keystr, &keylen);
	ASSERT_NE(key, nullptr);
	u8 *iv = testlib_hexstr2buf(ivstr, &ivlen);
	ASSERT_NE(iv, nullptr);
	u8 *msg = testlib_hexstr2buf(msgstr, &msglen);
	ASSERT_NE(msg, nullptr);
	u8 *ct = testlib_hexstr2buf(ctstr, &ctlen);
	ASSERT_NE(ct, nullptr);

	rc = zpc_aes_key_alloc(&aes_key);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_cbc_alloc(&aes_cbc);
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

	rc = zpc_aes_cbc_set_key(aes_cbc, aes_key);
	EXPECT_EQ(rc, 0);
	memset(&aes_key->prot, 0, sizeof(aes_key->prot));    /* destroy cached protected key */
	memset(aes_cbc->param.protkey, 0, sizeof(aes_cbc->param.protkey));    /* force WKaVP mismatch */
	rc = zpc_aes_cbc_set_iv(aes_cbc, iv);
	EXPECT_EQ(rc, 0);

	memset(&aes_key->prot, 0, sizeof(aes_key->prot));    /* destroy cached protected key */
	memset(aes_cbc->param.protkey, 0, sizeof(aes_cbc->param.protkey));    /* force WKaVP mismatch */
	rc = zpc_aes_cbc_encrypt(aes_cbc, buf, buf, 16);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_cbc_encrypt(aes_cbc, buf + 16, buf + 16, msglen - 16);
	EXPECT_EQ(rc, 0);

	EXPECT_TRUE(memcmp(buf, ct, ctlen) == 0);

	/* Encrypt */
	memcpy(buf, msg, msglen);

	rc = zpc_aes_cbc_set_key(aes_cbc, aes_key);
	EXPECT_EQ(rc, 0);
	memset(&aes_key->prot, 0, sizeof(aes_key->prot));    /* destroy cached protected key */
	memset(aes_cbc->param.protkey, 0, sizeof(aes_cbc->param.protkey));    /* force WKaVP mismatch */
	rc = zpc_aes_cbc_set_iv(aes_cbc, iv);
	EXPECT_EQ(rc, 0);

	memset(&aes_key->prot, 0, sizeof(aes_key->prot));    /* destroy cached protected key */
	memset(aes_cbc->param.protkey, 0, sizeof(aes_cbc->param.protkey));    /* force WKaVP mismatch */
	rc = zpc_aes_cbc_encrypt(aes_cbc, buf, buf, 16);
	EXPECT_EQ(rc, 0);
	memset(&aes_key->prot, 0, sizeof(aes_key->prot));    /* destroy cached protected key */
	memset(aes_cbc->param.protkey, 0, sizeof(aes_cbc->param.protkey));    /* force WKaVP mismatch */
	rc = zpc_aes_cbc_encrypt(aes_cbc, buf + 16, buf + 16, msglen - 16);
	EXPECT_EQ(rc, 0);

	EXPECT_TRUE(memcmp(buf, ct, ctlen) == 0);

	/* Decrypt */
	memcpy(buf, ct, ctlen);

	memset(&aes_key->prot, 0, sizeof(aes_key->prot));    /* destroy cached protected key */
	memset(aes_cbc->param.protkey, 0, sizeof(aes_cbc->param.protkey));    /* force WKaVP mismatch */
	rc = zpc_aes_cbc_set_iv(aes_cbc, iv);
	EXPECT_EQ(rc, 0);

	memset(&aes_key->prot, 0, sizeof(aes_key->prot));    /* destroy cached protected key */
	memset(aes_cbc->param.protkey, 0, sizeof(aes_cbc->param.protkey));    /* force WKaVP mismatch */
	rc = zpc_aes_cbc_decrypt(aes_cbc, buf, buf, 16);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_cbc_decrypt(aes_cbc, buf + 16, buf + 16, msglen - 16);
	EXPECT_EQ(rc, 0);

	EXPECT_TRUE(memcmp(buf, msg, msglen) == 0);

	/* Decrypt */
	memcpy(buf, ct, ctlen);

	memset(&aes_key->prot, 0, sizeof(aes_key->prot));    /* destroy cached protected key */
	memset(aes_cbc->param.protkey, 0, sizeof(aes_cbc->param.protkey));    /* force WKaVP mismatch */
	rc = zpc_aes_cbc_set_iv(aes_cbc, iv);
	EXPECT_EQ(rc, 0);

	memset(&aes_key->prot, 0, sizeof(aes_key->prot));    /* destroy cached protected key */
	memset(aes_cbc->param.protkey, 0, sizeof(aes_cbc->param.protkey));    /* force WKaVP mismatch */
	rc = zpc_aes_cbc_decrypt(aes_cbc, buf, buf, 16);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_cbc_decrypt(aes_cbc, buf + 16, buf + 16, msglen - 16);
	EXPECT_EQ(rc, 0);

	EXPECT_TRUE(memcmp(buf, msg, msglen) == 0);

	zpc_aes_cbc_free(&aes_cbc);
	EXPECT_EQ(aes_cbc, nullptr);
	zpc_aes_key_free(&aes_key);
	EXPECT_EQ(aes_key, nullptr);

	free(key);
	free(iv);
	free(msg);
	free(ct);
}

/*
 * This test assumes that the tester manually added the clear AES key with
 * given size to the pvsecret list file, for example:
 *
 * 5 AES-128-KEY:
 *  0x8ace2a9bc6f28ae3 ...   <- secret ID
 *  0xbe0274e3f3b36 ...    <- clear AES key
 *  ...
 *
 * The test creates one pvsecret-type key and one CCA or EP11 type
 * single AES key with the given clear key material to compare results.
 * The specified APQN(s) decide if the single keys are CCA or EP11.
 */
TEST(aes_cbc, pvsecret_kat)
{
	struct zpc_aes_key *aes_key1, *aes_key2;
	struct zpc_aes_cbc *ctx1, *ctx2;
	u8 iv[16], m[96], c[96], m_bak[96], c_bak[96];
	const char *mkvp, *apqns[257];
	unsigned int flags;
	int type, type2, rc, size;

	TESTLIB_ENV_AES_KEY_CHECK();

	TESTLIB_AES_CBC_HW_CAPS_CHECK();

	size = testlib_env_aes_key_size();
	type = testlib_env_aes_key_type();
	flags = testlib_env_aes_key_flags();
	mkvp = testlib_env_aes_key_mkvp();
	(void)testlib_env_aes_key_apqns(apqns);

	if (type != ZPC_AES_KEY_TYPE_PVSECRET)
		GTEST_SKIP_("Skipping pvsecret_kat test. Only applicable for UV secrets.");

	TESTLIB_AES_KERNEL_CAPS_CHECK(type);

	TESTLIB_AES_SW_CAPS_CHECK(type);

	TESTLIB_APQN_CAPS_CHECK(apqns, mkvp, type, size, flags);

	TESTLIB_AES_SW_CAPS_CHECK(type);

	TESTLIB_AES_KERNEL_CAPS_CHECK(type);

	TESTLIB_AES_NEW_MK_CHECK(type, mkvp, apqns);

	rc = zpc_aes_key_alloc(&aes_key1);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_key_alloc(&aes_key2);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_cbc_alloc(&ctx1);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_cbc_alloc(&ctx2);
	EXPECT_EQ(rc, 0);

	/*
	 * key1 is created from pvsecret.
	 */
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
	rc = zpc_aes_key_set_size(aes_key1, size);
	EXPECT_EQ(rc, 0);

	rc = testlib_set_aes_key_from_pvsecret(aes_key1, size);
	if (rc)
		goto ret;

	rc = zpc_aes_cbc_set_key(ctx1, aes_key1);
	EXPECT_EQ(rc, 0);

	/*
	 * key2 is a normal AES key and contains clear key material from list
	 * file. We first try to create a CCA type key with the given APQN(s),
	 * if this fails we retry with EP11.
	 */
	type2 = ZPC_AES_KEY_TYPE_CCA_DATA;
	while (1) {
		rc = zpc_aes_key_set_type(aes_key2, type2);
		EXPECT_EQ(rc, 0);
		if (mkvp != NULL) {
			rc = zpc_aes_key_set_mkvp(aes_key2, mkvp);
			if (type2 == ZPC_AES_KEY_TYPE_CCA_DATA && rc != 0) {
				type2 = ZPC_AES_KEY_TYPE_EP11;
				continue;
			}
			if (rc)
				goto ret;
		} else {
			rc = zpc_aes_key_set_apqns(aes_key2, apqns);
			EXPECT_EQ(rc, 0);
		}

		rc = zpc_aes_key_set_flags(aes_key2, flags);
		EXPECT_EQ(rc, 0);

		rc = zpc_aes_key_set_size(aes_key2, size);
		EXPECT_EQ(rc, 0);

		rc = testlib_set_aes_key_from_file(aes_key2, type2, size, 0, 1);
		if (type2 == ZPC_AES_KEY_TYPE_CCA_DATA && rc != 0) {
			type2 = ZPC_AES_KEY_TYPE_EP11;
			continue;
		}
		if (rc)
			goto ret;
		else
			break;
	}

	rc = zpc_aes_cbc_set_key(ctx2, aes_key2);
	EXPECT_EQ(rc, 0);

	memcpy(m_bak, m, 96);

	/* Now encrypt with both keys and compare result */
	rc = zpc_aes_cbc_set_iv(ctx1, iv);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_cbc_encrypt(ctx1, c, m, 96);
	EXPECT_EQ(rc, 0);
	memcpy(c_bak, c, 96);
	rc = zpc_aes_cbc_set_iv(ctx2, iv);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_cbc_encrypt(ctx2, c, m, 96);
	EXPECT_EQ(rc, 0);
	EXPECT_TRUE(memcmp(c, c_bak, 96) == 0);

	/* Now encrypt with key1 and decrypt with key2 */
	rc = zpc_aes_cbc_set_iv(ctx1, iv);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_cbc_encrypt(ctx1, c, m, 96);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_cbc_set_iv(ctx2, iv);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_cbc_decrypt(ctx2, m, c, 96);
	EXPECT_EQ(rc, 0);
	EXPECT_TRUE(memcmp(m, m_bak, 96) == 0);

ret:
	zpc_aes_cbc_free(&ctx1);
	EXPECT_EQ(ctx1, nullptr);
	zpc_aes_cbc_free(&ctx2);
	EXPECT_EQ(ctx2, nullptr);
	zpc_aes_key_free(&aes_key1);
	EXPECT_EQ(aes_key1, nullptr);
	zpc_aes_key_free(&aes_key2);
	EXPECT_EQ(aes_key2, nullptr);
}

static void
__task(struct zpc_aes_key *aes_key)
{
	struct zpc_aes_cbc *aes_cbc;
	unsigned char buf[4096];
	size_t ivlen, msglen, ctlen;
	int rc, i;

	const char *ivstr = "3f9d5ebe250ee7ce384b0d00ee849322";
	const char *msgstr = "db397ec22718dbffb9c9d13de0efcd4611bf792be4fce0dc5f25d4f577ed8cdbd4eb9208d593dda3d4653954ab64f05676caa3ce9bfa795b08b67ceebc923fdc89a8c431188e9e482d8553982cf304d1";
	const char *ctstr = "10ea27b19e16b93af169c4a88e06e35c99d8b420980b058e34b4b8f132b13766f72728202b089f428fecdb41c79f8aa0d0ef68f5786481cca29e2126f69bc14160f1ae2187878ba5c49cf3961e1b7ee9";

	u8 *iv = testlib_hexstr2buf(ivstr, &ivlen);
	ASSERT_NE(iv, nullptr);
	u8 *msg = testlib_hexstr2buf(msgstr, &msglen);
	ASSERT_NE(msg, nullptr);
	u8 *ct = testlib_hexstr2buf(ctstr, &ctlen);
	ASSERT_NE(ct, nullptr);

	rc = zpc_aes_cbc_alloc(&aes_cbc);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_cbc_set_key(aes_cbc, aes_key);
	EXPECT_EQ(rc, 0);

	for (i = 0; i < 1000; i++) {
		/* Encrypt */
		memcpy(buf, msg, msglen);

		memset(aes_cbc->param.protkey, 0, sizeof(aes_cbc->param.protkey));    /* force WKaVP mismatch */
		rc = zpc_aes_cbc_set_iv(aes_cbc, iv);
		EXPECT_EQ(rc, 0);

		memset(aes_cbc->param.protkey, 0, sizeof(aes_cbc->param.protkey));    /* force WKaVP mismatch */
		rc = zpc_aes_cbc_encrypt(aes_cbc, buf, buf, 16);
		EXPECT_EQ(rc, 0);
		rc = zpc_aes_cbc_encrypt(aes_cbc, buf + 16, buf + 16, msglen - 16);
		EXPECT_EQ(rc, 0);

		if (aes_key->type != ZPC_AES_KEY_TYPE_PVSECRET) {
			EXPECT_TRUE(memcmp(buf, ct, ctlen) == 0);
		}

		/* Decrypt */
		if (aes_key->type != ZPC_AES_KEY_TYPE_PVSECRET) {
			memcpy(buf, ct, ctlen);
		}

		rc = zpc_aes_cbc_set_iv(aes_cbc, iv);
		EXPECT_EQ(rc, 0);

		memset(aes_cbc->param.protkey, 0, sizeof(aes_cbc->param.protkey));    /* force WKaVP mismatch */
		rc = zpc_aes_cbc_decrypt(aes_cbc, buf, buf, 16);
		EXPECT_EQ(rc, 0);
		rc = zpc_aes_cbc_decrypt(aes_cbc, buf + 16, buf + 16, msglen - 16);
		EXPECT_EQ(rc, 0);

		EXPECT_TRUE(memcmp(buf, msg, msglen) == 0);
	}

	zpc_aes_cbc_free(&aes_cbc);
	EXPECT_EQ(aes_cbc, nullptr);

	free(iv);
	free(msg);
	free(ct);
}

TEST(aes_cbc, threads)
{
	TESTLIB_ENV_AES_KEY_CHECK();

	TESTLIB_AES_CBC_HW_CAPS_CHECK();

	size_t keylen;
	const char *mkvp, *apqns[257];
	struct zpc_aes_key *aes_key;
	unsigned int flags;
	int type, rc, i;
	std::thread *t[500];

	const char *keystr = "b6f9afbfe5a1562bba1368fc72ac9d9c";

	type = testlib_env_aes_key_type();
	flags = testlib_env_aes_key_flags();
	mkvp = testlib_env_aes_key_mkvp();
	(void)testlib_env_aes_key_apqns(apqns);

	TESTLIB_AES_KERNEL_CAPS_CHECK(type);

	TESTLIB_AES_SW_CAPS_CHECK(type);

	TESTLIB_APQN_CAPS_CHECK(apqns, mkvp, type, 128, flags);

	TESTLIB_AES_NEW_MK_CHECK(type, mkvp, apqns);

	u8 *key = testlib_hexstr2buf(keystr, &keylen);

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

	if (type != ZPC_AES_KEY_TYPE_PVSECRET) {
		rc = zpc_aes_key_import_clear(aes_key, key);
		EXPECT_EQ(rc, 0);
	} else {
		rc = testlib_set_aes_key_from_pvsecret(aes_key, keylen * 8);
		if (rc)
			goto ret;
	}

	for (i = 0; i < 500; i++) {
		t[i] = new std::thread(__task, aes_key);
	}

	/* Do something with key object while threads are working with it. */
	if (type != ZPC_AES_KEY_TYPE_PVSECRET) {
		rc = zpc_aes_key_reencipher(aes_key, ZPC_AES_KEY_REENCIPHER_CURRENT_TO_NEW);
		EXPECT_EQ(rc, 0);
		memset(&aes_key->cur, 0, sizeof(aes_key->cur));     /* destroy current secure key */
	}
 
	for (i = 0; i < 500; i++) {
		memset(&aes_key->prot, 0, sizeof(aes_key->prot));    /* destroy cached protected key */
		usleep(1);
	}

	for (i = 0; i < 500; i++) {
		t[i]->join();
		delete t[i];
	}

ret:
	zpc_aes_key_free(&aes_key);
	EXPECT_EQ(aes_key, nullptr);

	free(key);
}
