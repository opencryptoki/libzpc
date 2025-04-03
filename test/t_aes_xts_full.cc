/*
 * Copyright IBM Corp. 2025
 *
 * libzpc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <json-c/json.h>
#include <stdio.h>
#include <thread>
#include <unistd.h>

#include "testlib.h"
#include "gtest/gtest.h"

#include "zpc/aes_xts_full.h"
#include "zpc/aes_xts.h"
#include "zpc/error.h"

#include "aes_xts_full_local.h"  /* de-opaquify struct zpc_aes_xts_full */
#include "aes_xts_key_local.h"  /* de-opaquify struct zpc_aes_xts_key */
#include "aes_key_local.h"  /* de-opaquify struct zpc_aes_key */


static void __run_json(const char *json);

TEST(aes_xts_full, alloc)
{
	struct zpc_aes_xts_full *xts_full;
	int rc;

	TESTLIB_ENV_AES_XTS_KEY_CHECK();

	TESTLIB_AES_XTS_FULL_HW_CAPS_CHECK();

	rc = zpc_aes_xts_full_alloc(NULL);
	EXPECT_EQ(rc, ZPC_ERROR_ARG1NULL);

	xts_full = NULL;
	rc = zpc_aes_xts_full_alloc(&xts_full);
	EXPECT_EQ(rc, 0);
	zpc_aes_xts_full_free(&xts_full);
	EXPECT_EQ(xts_full, nullptr);

	xts_full = (struct zpc_aes_xts_full *)&xts_full;
	rc = zpc_aes_xts_full_alloc(&xts_full);
	EXPECT_EQ(rc, 0);
	zpc_aes_xts_full_free(&xts_full);
	EXPECT_EQ(xts_full, nullptr);
}

TEST(aes_xts_full, free)
{
	struct zpc_aes_xts_full *xts_full;
	int rc;

	TESTLIB_ENV_AES_XTS_KEY_CHECK();

	TESTLIB_AES_XTS_FULL_HW_CAPS_CHECK();

	zpc_aes_xts_full_free(NULL);

	xts_full = NULL;
	zpc_aes_xts_full_free(&xts_full);
	EXPECT_EQ(xts_full, nullptr);

	rc = zpc_aes_xts_full_alloc(&xts_full);
	EXPECT_EQ(rc, 0);
	zpc_aes_xts_full_free(&xts_full);
	EXPECT_EQ(xts_full, nullptr);
}

TEST(aes_xts_full, set_key)
{
	struct zpc_aes_xts_key *xts_key;
	struct zpc_aes_xts_full *xts_full;
	u8 iv[16];
	int rc, size, type;

	TESTLIB_ENV_AES_XTS_KEY_CHECK();

	TESTLIB_AES_XTS_FULL_HW_CAPS_CHECK();

	size = testlib_env_aes_xts_key_size();
	type = testlib_env_aes_xts_key_type();

	TESTLIB_AES_XTS_FULL_KERNEL_CAPS_CHECK();

	TESTLIB_AES_XTS_FULL_SW_CAPS_CHECK(type);

	TESTLIB_AES_XTS_KEY_SIZE_CHECK(size);

	rc = zpc_aes_xts_key_alloc(&xts_key);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_full_alloc(&xts_full);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_xts_full_set_key(NULL, NULL);
	EXPECT_EQ(rc, ZPC_ERROR_ARG1NULL);
	rc = zpc_aes_xts_full_set_key(NULL, xts_key);
	EXPECT_EQ(rc, ZPC_ERROR_ARG1NULL);
	rc = zpc_aes_xts_full_set_key(xts_full, NULL);

	rc = zpc_aes_xts_full_set_key(xts_full, xts_key);
	EXPECT_EQ(rc, ZPC_ERROR_KEYNOTSET);

	rc = zpc_aes_xts_key_set_type(xts_key, type);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_key_set_size(xts_key, size);
	EXPECT_EQ(rc, 0);

	rc = testlib_set_aes_xts_key_from_pvsecret(xts_key, size);
	if (rc)
		goto ret;

	rc = zpc_aes_xts_full_set_key(xts_full, xts_key);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_xts_full_set_key(xts_full, NULL); /* Unset key. */
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_xts_full_set_iv(xts_full, iv);
	EXPECT_EQ(rc, ZPC_ERROR_KEYNOTSET);
	rc = zpc_aes_xts_full_set_key(xts_full, xts_key);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_full_set_iv(xts_full, iv);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_xts_full_set_key(xts_full, xts_key);
	EXPECT_EQ(rc, 0);

ret:
	zpc_aes_xts_full_free(&xts_full);
	EXPECT_EQ(xts_full, nullptr);
	zpc_aes_xts_key_free(&xts_key);
	EXPECT_EQ(xts_key, nullptr);
}

TEST(aes_xts_full, set_iv)
{
	struct zpc_aes_xts_key *xts_key;
	struct zpc_aes_xts_full *xts_full;
	u8 iv[16];
	int rc, size, type;

	TESTLIB_ENV_AES_XTS_KEY_CHECK();

	TESTLIB_AES_XTS_FULL_HW_CAPS_CHECK();

	type = testlib_env_aes_xts_key_type();
	size = testlib_env_aes_xts_key_size();

	TESTLIB_AES_XTS_FULL_KERNEL_CAPS_CHECK();

	TESTLIB_AES_XTS_FULL_SW_CAPS_CHECK(type);

	TESTLIB_AES_XTS_KEY_SIZE_CHECK(size);

	rc = zpc_aes_xts_key_alloc(&xts_key);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_full_alloc(&xts_full);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_xts_full_set_iv(NULL, NULL);
	EXPECT_EQ(rc, ZPC_ERROR_ARG1NULL);
	rc = zpc_aes_xts_full_set_iv(NULL, iv);
	EXPECT_EQ(rc, ZPC_ERROR_ARG1NULL);

	rc = zpc_aes_xts_full_set_iv(xts_full, NULL);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_full_set_iv(xts_full, iv);
	EXPECT_EQ(rc, ZPC_ERROR_KEYNOTSET);

	rc = zpc_aes_xts_key_set_size(xts_key, size);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_key_set_type(xts_key, type);
	EXPECT_EQ(rc, 0);

	rc = testlib_set_aes_xts_key_from_pvsecret(xts_key, size);
	if (rc)
		goto ret;

	rc = zpc_aes_xts_full_set_iv(xts_full, iv);
	EXPECT_EQ(rc, ZPC_ERROR_KEYNOTSET);

	rc = zpc_aes_xts_full_set_key(xts_full, xts_key);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_xts_full_set_iv(xts_full, iv);
	EXPECT_EQ(rc, 0);

ret:
	zpc_aes_xts_full_free(&xts_full);
	EXPECT_EQ(xts_full, nullptr);
	zpc_aes_xts_key_free(&xts_key);
	EXPECT_EQ(xts_key, nullptr);
}

TEST(aes_xts_full, encrypt)
{
	struct zpc_aes_xts_key *xts_key;
	struct zpc_aes_xts_full *xts_full;
	u8 iv[16], m[64], c[64];
	int rc, size, type;

	TESTLIB_ENV_AES_XTS_KEY_CHECK();

	TESTLIB_AES_XTS_FULL_HW_CAPS_CHECK();

	type = testlib_env_aes_xts_key_type();
	size = testlib_env_aes_xts_key_size();

	TESTLIB_AES_XTS_FULL_KERNEL_CAPS_CHECK();

	TESTLIB_AES_XTS_FULL_SW_CAPS_CHECK(type);

	TESTLIB_AES_XTS_KEY_SIZE_CHECK(size);

	rc = zpc_aes_xts_key_alloc(&xts_key);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_full_alloc(&xts_full);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_xts_key_set_type(xts_key, type);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_key_set_size(xts_key, size);
	EXPECT_EQ(rc, 0);

	rc = testlib_set_aes_xts_key_from_pvsecret(xts_key, size);
	if (rc)
		goto ret;

	rc = zpc_aes_xts_full_set_key(xts_full, xts_key);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_full_set_iv(xts_full, iv);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_xts_full_encrypt(xts_full, c, m, 64);
	EXPECT_EQ(rc, 0);

ret:
	zpc_aes_xts_full_free(&xts_full);
	EXPECT_EQ(xts_full, nullptr);
	zpc_aes_xts_key_free(&xts_key);
	EXPECT_EQ(xts_key, nullptr);
}

TEST(aes_xts_full, decrypt)
{
	struct zpc_aes_xts_key *xts_key;
	struct zpc_aes_xts_full *xts_full;
	u8 iv[16], m[64], c[64];
	int rc, size, type;

	TESTLIB_ENV_AES_XTS_KEY_CHECK();

	TESTLIB_AES_XTS_FULL_HW_CAPS_CHECK();

	type = testlib_env_aes_xts_key_type();
	size = testlib_env_aes_xts_key_size();

	TESTLIB_AES_XTS_FULL_KERNEL_CAPS_CHECK();

	TESTLIB_AES_XTS_FULL_SW_CAPS_CHECK(type);

	TESTLIB_AES_XTS_KEY_SIZE_CHECK(size);

	rc = zpc_aes_xts_key_alloc(&xts_key);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_full_alloc(&xts_full);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_xts_key_set_type(xts_key, type);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_key_set_size(xts_key, size);
	EXPECT_EQ(rc, 0);

	rc = testlib_set_aes_xts_key_from_pvsecret(xts_key, size);
	if (rc)
		goto ret;

	rc = zpc_aes_xts_full_set_key(xts_full, xts_key);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_full_set_iv(xts_full, iv);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_xts_full_decrypt(xts_full, m, c, 64);
	EXPECT_EQ(rc, 0);

ret:
	zpc_aes_xts_full_free(&xts_full);
	EXPECT_EQ(xts_full, nullptr);
	zpc_aes_xts_key_free(&xts_key);
	EXPECT_EQ(xts_key, nullptr);
}

TEST(aes_xts_full, pc)
{
	struct zpc_aes_xts_key *aes_key1, *aes_key2, *aes_key3, *aes_key4;
	struct zpc_aes_xts_full *xts_full1, *xts_full2;
	u8 iv[16], m[96], c[96], key[64], m_bak[96];
	int rc, size, type;

	TESTLIB_ENV_AES_XTS_KEY_CHECK();

	TESTLIB_AES_XTS_FULL_HW_CAPS_CHECK();

	type = testlib_env_aes_xts_key_type();
	size = testlib_env_aes_xts_key_size();

	TESTLIB_AES_XTS_FULL_KERNEL_CAPS_CHECK();

	TESTLIB_AES_XTS_FULL_SW_CAPS_CHECK(type);

	TESTLIB_AES_XTS_KEY_SIZE_CHECK(size);

	memcpy(m_bak, m, 96);

	rc = zpc_aes_xts_key_alloc(&aes_key1);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_key_alloc(&aes_key2);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_full_alloc(&xts_full1);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_full_alloc(&xts_full2);
	EXPECT_EQ(rc, 0);

	/* Create key1 from pvsecret */
	rc = zpc_aes_xts_key_set_size(aes_key1, size);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_key_set_type(aes_key1, type);
	EXPECT_EQ(rc, 0);
	rc = testlib_set_aes_xts_key_from_pvsecret(aes_key1, size);
	if (rc)
		goto ret;
	rc = zpc_aes_xts_full_set_key(xts_full1, aes_key1);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_full_set_iv(xts_full1, iv);
	EXPECT_EQ(rc, 0);

	/* Create key2 from same pvsecret */
	rc = zpc_aes_xts_key_set_size(aes_key2, size);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_key_set_type(aes_key2, type);
	EXPECT_EQ(rc, 0);
	rc = testlib_set_aes_xts_key_from_pvsecret(aes_key2, size);
	if (rc)
		goto ret;
	rc = zpc_aes_xts_full_set_key(xts_full2, aes_key1);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_full_set_iv(xts_full2, iv);
	EXPECT_EQ(rc, 0);

	/* Encrypt with context 1, decrypt with context 2 and vice versa */
	rc = zpc_aes_xts_full_encrypt(xts_full1, c, m, 96);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_full_decrypt(xts_full2, m, c, 96);
	EXPECT_EQ(rc, 0);
	EXPECT_TRUE(memcmp(m, m_bak, 96) == 0);
	rc = zpc_aes_xts_full_encrypt(xts_full2, c, m, 96);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_full_decrypt(xts_full1, m, c, 96);
	EXPECT_EQ(rc, 0);
	EXPECT_TRUE(memcmp(m, m_bak, 96) == 0);

	rc = zpc_aes_xts_full_encrypt(xts_full2, c,  m, 96);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_full_decrypt(xts_full1, m, c, 96);
	EXPECT_EQ(rc, 0);
	EXPECT_TRUE(memcmp(m, m_bak, 96) == 0);
	rc = zpc_aes_xts_full_encrypt(xts_full1, c, m, 96);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_full_decrypt(xts_full2, m, c, 96);
	EXPECT_EQ(rc, 0);
	EXPECT_TRUE(memcmp(m, m_bak, 96) == 0);

	/* Unset keys in contexts */
	rc = zpc_aes_xts_full_set_key(xts_full1, NULL);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_full_set_key(xts_full2, NULL);
	EXPECT_EQ(rc, 0);

	/* Create random protected key3 from clear key (no type set) */
	rc = zpc_aes_xts_key_alloc(&aes_key3);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_key_set_size(aes_key3, size);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_key_import_clear(aes_key3, key);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_full_set_key(xts_full1, aes_key3);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_full_set_iv(xts_full1, iv);
	EXPECT_EQ(rc, 0);

	/* Create random protected key4 from same clear key (no type set) */
	rc = zpc_aes_xts_key_alloc(&aes_key4);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_key_set_size(aes_key4, size);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_key_import_clear(aes_key4, key);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_full_set_key(xts_full2, aes_key4);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_full_set_iv(xts_full2, iv);
	EXPECT_EQ(rc, 0);

	/* Encrypt with context 1, decrypt with context 2 and vice versa */
	rc = zpc_aes_xts_full_encrypt(xts_full1, c, m, 96);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_full_decrypt(xts_full2, m, c, 96);
	EXPECT_EQ(rc, 0);
	EXPECT_TRUE(memcmp(m, m_bak, 96) == 0);
	rc = zpc_aes_xts_full_encrypt(xts_full2, c, m, 96);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_full_decrypt(xts_full1, m, c, 96);
	EXPECT_EQ(rc, 0);
	EXPECT_TRUE(memcmp(m, m_bak, 96) == 0);

	rc = zpc_aes_xts_full_encrypt(xts_full2, c, m, 96);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_full_decrypt(xts_full1, m, c, 96);
	EXPECT_EQ(rc, 0);
	EXPECT_TRUE(memcmp(m, m_bak, 96) == 0);
	rc = zpc_aes_xts_full_encrypt(xts_full1, c, m, 96);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_full_decrypt(xts_full2, m, c, 96);
	EXPECT_EQ(rc, 0);
	EXPECT_TRUE(memcmp(m, m_bak, 96) == 0);

ret:
	zpc_aes_xts_full_free(&xts_full2);
	zpc_aes_xts_full_free(&xts_full1);
	zpc_aes_xts_key_free(&aes_key1);
	EXPECT_EQ(aes_key1, nullptr);
	zpc_aes_xts_key_free(&aes_key2);
	EXPECT_EQ(aes_key2, nullptr);
	zpc_aes_xts_key_free(&aes_key3);
	EXPECT_EQ(aes_key3, nullptr);
	zpc_aes_xts_key_free(&aes_key4);
	EXPECT_EQ(aes_key4, nullptr);
}

TEST(aes_xts_full, stream_inplace_kat1)
{
	TESTLIB_ENV_AES_XTS_KEY_CHECK();

	TESTLIB_AES_XTS_FULL_HW_CAPS_CHECK();

	size_t keylen, msglen, ctlen, ivlen;
	unsigned char buf[4096];
	struct zpc_aes_xts_key *xts_key;
	struct zpc_aes_xts_full *xts_full;
	int type, rc;

	const char *keystr = "88dfd7c83cb121968feb417520555b36c0f63b662570eac12ea96cbe188ad5b1a44db23ac6470316cba0041cadf248f6d9a7713f454e663f3e3987585cebbf96";
	const char *ivstr = "0ee84632b838dd528f1d96c76439805c";
	const char *msgstr = "ec36551c70efcdf85de7a39988978263ad261e83996dad219a0058e02187384f2d0754ff9cfa000bec448fafd2cfa738";
	const char *ctstr = "a55d533c9c5885562b92d4582ea69db8e2ba9c0b967a9f0167700b043525a47bafe7d630774eaf4a1dc9fbcf94a1fda4";

	type = testlib_env_aes_xts_key_type();

	TESTLIB_AES_XTS_FULL_KERNEL_CAPS_CHECK();

	u8 *key1 = testlib_hexstr2buf(keystr, &keylen);
	ASSERT_NE(key1, nullptr);
	u8 *iv = testlib_hexstr2buf(ivstr, &ivlen);
	ASSERT_NE(iv, nullptr);
	u8 *msg = testlib_hexstr2buf(msgstr, &msglen);
	ASSERT_NE(msg, nullptr);
	u8 *ct = testlib_hexstr2buf(ctstr, &ctlen);
	ASSERT_NE(ct, nullptr);

	rc = zpc_aes_xts_key_alloc(&xts_key);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_full_alloc(&xts_full);
	EXPECT_EQ(rc, 0);

	/*
	 * If we're testing pvsecrets, don't set the type, which makes this key obj
	 * effectively a random key. In this case clear import is possible.
	 */
	if (type != ZPC_AES_XTS_KEY_TYPE_PVSECRET) {
		rc = zpc_aes_xts_key_set_type(xts_key, type);
		EXPECT_EQ(rc, 0);
	}

	rc = zpc_aes_xts_key_set_size(xts_key, (keylen * 8) / 2);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_key_import_clear(xts_key, key1);
	EXPECT_EQ(rc, 0);

	/* Encrypt */
	memcpy(buf, msg, msglen);

	rc = zpc_aes_xts_full_set_key(xts_full, xts_key);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_full_set_iv(xts_full, iv);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_xts_full_encrypt(xts_full, buf, buf, 16);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_full_encrypt(xts_full, buf + 16, buf + 16, msglen - 16);
	EXPECT_EQ(rc, 0);

	EXPECT_TRUE(memcmp(buf, ct, ctlen) == 0);

	/* Encrypt */
	memcpy(buf, msg, msglen);

	rc = zpc_aes_xts_full_set_key(xts_full, xts_key);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_full_set_iv(xts_full, iv);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_xts_full_encrypt(xts_full, buf, buf, 16);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_full_encrypt(xts_full, buf + 16, buf + 16, msglen - 16);
	EXPECT_EQ(rc, 0);

	EXPECT_TRUE(memcmp(buf, ct, ctlen) == 0);

	/* Decrypt */
	memcpy(buf, ct, ctlen);

	rc = zpc_aes_xts_full_set_iv(xts_full, iv);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_xts_full_decrypt(xts_full, buf, buf, 16);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_full_decrypt(xts_full, buf + 16, buf + 16, msglen - 16);
	EXPECT_EQ(rc, 0);

	EXPECT_TRUE(memcmp(buf, msg, msglen) == 0);

	/* Decrypt */
	memcpy(buf, ct, ctlen);

	rc = zpc_aes_xts_full_set_iv(xts_full, iv);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_xts_full_decrypt(xts_full, buf, buf, 16);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_full_decrypt(xts_full, buf + 16, buf + 16, msglen - 16);
	EXPECT_EQ(rc, 0);

	EXPECT_TRUE(memcmp(buf, msg, msglen) == 0);

	zpc_aes_xts_full_free(&xts_full);
	EXPECT_EQ(xts_full, nullptr);
	zpc_aes_xts_key_free(&xts_key);
	EXPECT_EQ(xts_key, nullptr);

	free(key1);
	free(iv);
	free(msg);
	free(ct);
}

TEST(aes_xts_full, stream_inplace_kat2)
{
	TESTLIB_ENV_AES_XTS_KEY_CHECK();

	TESTLIB_AES_XTS_FULL_HW_CAPS_CHECK();

	size_t keylen, ivlen, msglen, ctlen;
	unsigned char buf[4096];
	struct zpc_aes_xts_key *xts_key;
	struct zpc_aes_xts_full *xts_full;
	int type, rc;

	const char *keystr = "394c97881abd989d29c703e48a72b397a7acf51b59649eeea9b33274d8541df4";
	const char *ivstr = "4b15c684a152d485fe9937d39b168c29";
	const char *msgstr = "2f3b9dcfbae729583b1d1ffdd16bb6fe2757329435662a78f0";
	const char *ctstr = "f3473802e38a3ffef4d4fb8e6aa266ebde553a64528a06463e";

	type = testlib_env_aes_xts_key_type();

	TESTLIB_AES_XTS_FULL_KERNEL_CAPS_CHECK();

	u8 *key1 = testlib_hexstr2buf(keystr, &keylen);
	ASSERT_NE(key1, nullptr);
	u8 *iv = testlib_hexstr2buf(ivstr, &ivlen);
	ASSERT_NE(iv, nullptr);
	u8 *msg = testlib_hexstr2buf(msgstr, &msglen);
	ASSERT_NE(msg, nullptr);
	u8 *ct = testlib_hexstr2buf(ctstr, &ctlen);
	ASSERT_NE(ct, nullptr);

	rc = zpc_aes_xts_key_alloc(&xts_key);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_full_alloc(&xts_full);
	EXPECT_EQ(rc, 0);

	/*
	 * If we're testing pvsecrets, don't set the type, which makes this key obj
	 * effectively a random key. In this case clear import is possible.
	 */
	if (type != ZPC_AES_XTS_KEY_TYPE_PVSECRET) {
		rc = zpc_aes_xts_key_set_type(xts_key, type);
		EXPECT_EQ(rc, 0);
	}

	rc = zpc_aes_xts_key_set_size(xts_key, (keylen / 2) * 8);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_key_import_clear(xts_key, key1);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_xts_full_set_key(xts_full, xts_key);
	EXPECT_EQ(rc, 0);

	/* Encrypt */
	memcpy(buf, msg, msglen);

	rc = zpc_aes_xts_full_set_iv(xts_full, iv);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_xts_full_encrypt(xts_full, buf, buf, msglen);
	EXPECT_EQ(rc, 0);

	EXPECT_TRUE(memcmp(buf, ct, ctlen) == 0);

	/* Decrypt */
	memcpy(buf, ct, ctlen);

	rc = zpc_aes_xts_full_set_iv(xts_full, iv);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_xts_full_decrypt(xts_full, buf, buf, ctlen);
	EXPECT_EQ(rc, 0);

	EXPECT_TRUE(memcmp(buf, msg, msglen) == 0);

	zpc_aes_xts_full_free(&xts_full);
	EXPECT_EQ(xts_full, nullptr);
	zpc_aes_xts_key_free(&xts_key);
	EXPECT_EQ(xts_key, nullptr);

	free(key1);
	free(iv);
	free(msg);
	free(ct);
}

TEST(aes_xts_full, stream_inplace_kat3)
{
	TESTLIB_ENV_AES_XTS_KEY_CHECK();

	TESTLIB_AES_XTS_FULL_HW_CAPS_CHECK();

	size_t keylen, ivlen, msglen, ctlen;
	unsigned char buf[4096], intermediate_state[32];
	struct zpc_aes_xts_key *xts_key1;
	struct zpc_aes_xts_full *xts_full1, *xts_full2;
	int type, rc, size, i;

	const char *keystr[] = {
		"63f36e9c397c6523c99f1644ecb1a5d9bc0f2f55fbe324444c390fae752ad4d7",
		"88dfd7c83cb121968feb417520555b36c0f63b662570eac12ea96cbe188ad5b1a44db23ac6470316cba0041cadf248f6d9a7713f454e663f3e3987585cebbf96",
	};
	const char *ivstr[] = {
		"cdb1bd3486f353cc160a840beadf0329",
		"0ee84632b838dd528f1d96c76439805c",
	};
	const char *msgstr[] = {
		"9a0149888bf76160a81428bc9140eccd26ed18368e24d49b9cc512929a88ad1e66c763f4f56b63bb9dd9508c5d4df465",
		"ec36551c70efcdf85de7a39988978263ad261e83996dad219a0058e02187384f2d0754ff9cfa000bec448fafd2cfa738",
	};
	const char *ctstr[] = {
		"0eeef28ca159b805f5c215610551678ab772f279374fb140ab550768db42cf6cb73637641934195ffc08cf5a9188b82b",
		"a55d533c9c5885562b92d4582ea69db8e2ba9c0b967a9f0167700b043525a47bafe7d630774eaf4a1dc9fbcf94a1fda4",
	};

	size = testlib_env_aes_xts_key_size();
	type = testlib_env_aes_xts_key_type();

	TESTLIB_AES_XTS_FULL_KERNEL_CAPS_CHECK();

	TESTLIB_AES_XTS_KEY_SIZE_CHECK(size);

	i = size == 128 ? 0 : 1;

	u8 *key1 = testlib_hexstr2buf(keystr[i], &keylen);
	ASSERT_NE(key1, nullptr);
	u8 *iv = testlib_hexstr2buf(ivstr[i], &ivlen);
	ASSERT_NE(iv, nullptr);
	u8 *msg = testlib_hexstr2buf(msgstr[i], &msglen);
	ASSERT_NE(msg, nullptr);
	u8 *ct = testlib_hexstr2buf(ctstr[i], &ctlen);
	ASSERT_NE(ct, nullptr);

	rc = zpc_aes_xts_key_alloc(&xts_key1);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_xts_full_alloc(&xts_full1);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_full_alloc(&xts_full2);
	EXPECT_EQ(rc, 0);

	/*
	 * If we're testing pvsecrets, don't set the type, which makes this key obj
	 * effectively a random key. In this case clear import is possible.
	 */
	if (type != ZPC_AES_XTS_KEY_TYPE_PVSECRET) {
		rc = zpc_aes_xts_key_set_type(xts_key1, type);
		EXPECT_EQ(rc, 0);
	}

	rc = zpc_aes_xts_key_set_size(xts_key1, (keylen / 2) * 8);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_key_import_clear(xts_key1, key1);
	EXPECT_EQ(rc, 0);

	/* Set key in both contexts */
	rc = zpc_aes_xts_full_set_key(xts_full1, xts_key1);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_full_set_key(xts_full2, xts_key1);
	EXPECT_EQ(rc, 0);

	/* Encrypt first chunk with first ctx */
	memcpy(buf, msg, msglen);
	rc = zpc_aes_xts_full_set_iv(xts_full1, iv);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_full_encrypt(xts_full1, buf, buf, 16);
	EXPECT_EQ(rc, 0);

	/* Get intermediate state from first ctx */
	rc = zpc_aes_xts_full_export(xts_full1, intermediate_state);
	EXPECT_EQ(rc, 0);

	/* Encrypt a 2nd chunk with 2nd ctx */
	rc = zpc_aes_xts_full_set_iv(xts_full2, iv);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_full_import(xts_full2, intermediate_state);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_full_encrypt(xts_full2, buf + 16, buf + 16, msglen - 16);
	EXPECT_EQ(rc, 0);

	EXPECT_TRUE(memcmp(buf, ct, msglen) == 0);

	/* Decrypt first chunk with first ctx */
	memcpy(buf, ct, ctlen);
	rc = zpc_aes_xts_full_set_iv(xts_full1, iv);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_full_decrypt(xts_full1, buf, buf, 16);
	EXPECT_EQ(rc, 0);

	/* Get intermediate state from first ctx */
	rc = zpc_aes_xts_full_export(xts_full1, intermediate_state);
	EXPECT_EQ(rc, 0);

	/* Decrypt remaining chunk with 2nd ctx */
	rc = zpc_aes_xts_full_set_iv(xts_full2, iv);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_full_import(xts_full2, intermediate_state);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_full_decrypt(xts_full2, buf + 16, buf + 16, msglen - 16);
	EXPECT_EQ(rc, 0);

	EXPECT_TRUE(memcmp(buf, msg, msglen) == 0);

	zpc_aes_xts_full_free(&xts_full1);
	EXPECT_EQ(xts_full1, nullptr);
	zpc_aes_xts_full_free(&xts_full2);
	EXPECT_EQ(xts_full2, nullptr);
	zpc_aes_xts_key_free(&xts_key1);
	EXPECT_EQ(xts_key1, nullptr);

	free(key1);
	free(iv);
	free(msg);
	free(ct);
}

TEST(aes_xts_full, nist_kat)
{
	TESTLIB_ENV_AES_XTS_KEY_CHECK();

	TESTLIB_AES_XTS_FULL_HW_CAPS_CHECK();

	TESTLIB_AES_XTS_FULL_KERNEL_CAPS_CHECK();

	__run_json("nist_aes_xts.json");
}

static void __run_json(const char *json)
{
	const char *tv = json, *str;
	struct zpc_aes_xts_key *xts_key;
	struct zpc_aes_xts_full *xts_full;
	u8 *double_key = NULL, *iv = NULL;
	u8 *pt = NULL, *pt_out = NULL, *ct = NULL, *ct_out = NULL;
	int rc, keysize = 0;
	size_t ptlen, ctlen, i, j, max;
	json_object *jkey, *jiv, *jmsg, *jct, *jtmp, *jtestgroups, *jfile, *jkeysize, *jtests;
	json_bool b;
	int type;

	type = testlib_env_aes_xts_key_type();

	rc = zpc_aes_xts_key_alloc(&xts_key);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_full_alloc(&xts_full);
	EXPECT_EQ(rc, 0);

	/*
	 * If we're testing pvsecrets, don't set the type, which makes this key obj
	 * effectively a random key. Then clear import is possible.
	 */
	if (type != ZPC_AES_XTS_KEY_TYPE_PVSECRET) {
		rc = zpc_aes_xts_key_set_type(xts_key, type);
		EXPECT_EQ(rc, 0);
	}

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

		rc = zpc_aes_xts_key_set_size(xts_key, keysize);
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
			double_key = testlib_hexstr2buf(str, NULL);
			ASSERT_NE(double_key, nullptr);
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

			rc = zpc_aes_xts_key_import_clear(xts_key, double_key);
			EXPECT_EQ(rc, 0);

			rc = zpc_aes_xts_full_set_key(xts_full, xts_key);
			EXPECT_EQ(rc, 0);

			rc = zpc_aes_xts_full_set_iv(xts_full, iv);
			EXPECT_EQ(rc, 0);
			rc = zpc_aes_xts_full_encrypt(xts_full, ct_out, pt, ptlen);
			EXPECT_EQ(rc, 0);
			EXPECT_TRUE(memcmp(ct_out, ct, ctlen) == 0);

			rc = zpc_aes_xts_full_set_iv(xts_full, iv);
			EXPECT_EQ(rc, 0);
			rc = zpc_aes_xts_full_decrypt(xts_full, pt_out, ct, ctlen);
			EXPECT_EQ(rc, 0);
			EXPECT_TRUE(memcmp(pt_out, pt, ptlen) == 0);

			/* Unset key. */
			rc = zpc_aes_xts_full_set_key(xts_full, NULL);
			EXPECT_EQ(rc, 0);

			free(double_key); double_key = NULL;
			free(iv); iv = NULL;
			free(pt); pt = NULL;
			free(pt_out); pt_out = NULL;
			free(ct); ct = NULL;
			free(ct_out); ct_out = NULL;
		}
	}

	zpc_aes_xts_full_free(&xts_full);
	EXPECT_EQ(xts_full, nullptr);
	zpc_aes_xts_key_free(&xts_key);
	EXPECT_EQ(xts_key, nullptr);
}

TEST(aes_xts_full, rederive_protected_key1)
{
	struct zpc_aes_xts_key *xts_key1, *xts_key2;
	struct zpc_aes_xts_full *xts_full1, *xts_full2, *xts_full3;
	u8 iv[16], m[96], c[96];
	int rc, size;

	TESTLIB_ENV_AES_XTS_KEY_CHECK();

	TESTLIB_AES_XTS_FULL_HW_CAPS_CHECK();

	size = testlib_env_aes_xts_key_size();

	TESTLIB_AES_XTS_FULL_KERNEL_CAPS_CHECK();

	TESTLIB_AES_XTS_KEY_SIZE_CHECK(size);

	rc = zpc_aes_xts_key_alloc(&xts_key1);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_key_alloc(&xts_key2);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_full_alloc(&xts_full1);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_full_alloc(&xts_full2);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_full_alloc(&xts_full3);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_xts_full_set_key(xts_full1, NULL);   /* Unset key. */
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_full_set_key(xts_full2, NULL);   /* Unset key. */
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_full_set_key(xts_full3, NULL);   /* Unset key. */
	EXPECT_EQ(rc, 0);

	/* Random protected keys cannot be re-derived. */

	rc = zpc_aes_xts_key_set_size(xts_key1, size);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_key_generate(xts_key1);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_key_set_size(xts_key2, size);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_key_generate(xts_key2);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_xts_full_set_key(xts_full1, xts_key1);
	EXPECT_EQ(rc, 0);
	memset(xts_full1->param_km + AES_FXTS_WKVP_OFFSET(xts_full1->xts_key->keysize), 0, 32);
	/*
	 * In contrast to aes_xts with two keys, setting the iv in a full-xts
	 * context does not involve a CPACF instruction call. So this always
	 * succeeds.
	 */
	rc = zpc_aes_xts_full_set_iv(xts_full1, iv);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_xts_full_set_key(xts_full2, xts_key2);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_full_set_iv(xts_full2, iv);
	EXPECT_EQ(rc, 0);
	memset(xts_full2->param_km + AES_FXTS_WKVP_OFFSET(xts_full2->xts_key->keysize), 0, 32);
	/*
	 * However, when trying an encrypt or decrypt after corrupting the wkvp,
	 * this fails because there is no persistent key part (e.g. secure key)
	 * to rederive the protected key.
	 */
	rc = zpc_aes_xts_full_encrypt(xts_full2, c, m, 96);
	EXPECT_EQ(rc, ZPC_ERROR_PROTKEYONLY);

	rc = zpc_aes_xts_full_set_key(xts_full3, xts_key2);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_full_set_iv(xts_full3, iv);
	EXPECT_EQ(rc, 0);
	memset(xts_full3->param_km + AES_FXTS_WKVP_OFFSET(xts_full3->xts_key->keysize), 0, 32);
	rc = zpc_aes_xts_full_decrypt(xts_full3, m, c, 96);
	EXPECT_EQ(rc, ZPC_ERROR_PROTKEYONLY);

	zpc_aes_xts_full_free(&xts_full3);
	zpc_aes_xts_full_free(&xts_full2);
	zpc_aes_xts_full_free(&xts_full1);
	zpc_aes_xts_key_free(&xts_key2);
	zpc_aes_xts_key_free(&xts_key1);
	EXPECT_EQ(xts_full3, nullptr);
	EXPECT_EQ(xts_full2, nullptr);
	EXPECT_EQ(xts_full1, nullptr);
	EXPECT_EQ(xts_key2, nullptr);
	EXPECT_EQ(xts_key1, nullptr);
}

TEST(aes_xts_full, rederive_protected_key2)
{
	TESTLIB_ENV_AES_XTS_KEY_CHECK();

	TESTLIB_AES_XTS_FULL_HW_CAPS_CHECK();

	size_t keylen, msglen, ctlen, ivlen;
	unsigned char buf[4096];
	struct zpc_aes_xts_key *xts_key1, *xts_key2;
	struct zpc_aes_xts_full *xts_full;
	int type, rc;

	const char *keystr = "394c97881abd989d29c703e48a72b397a7acf51b59649eeea9b33274d8541df4";
	const char *ivstr = "4b15c684a152d485fe9937d39b168c29";
	const char *msgstr = "2f3b9dcfbae729583b1d1ffdd16bb6fe2757329435662a78f0";
	const char *ctstr = "f3473802e38a3ffef4d4fb8e6aa266ebde553a64528a06463e";

	type = testlib_env_aes_xts_key_type();

	TESTLIB_AES_XTS_FULL_KERNEL_CAPS_CHECK();

	TESTLIB_AES_XTS_FULL_SW_CAPS_CHECK(type);

	u8 *key1 = testlib_hexstr2buf(keystr, &keylen);
	ASSERT_NE(key1, nullptr);
	keylen /= 2;
	u8 *iv = testlib_hexstr2buf(ivstr, &ivlen);
	ASSERT_NE(iv, nullptr);
	u8 *msg = testlib_hexstr2buf(msgstr, &msglen);
	ASSERT_NE(msg, nullptr);
	u8 *ct = testlib_hexstr2buf(ctstr, &ctlen);
	ASSERT_NE(ct, nullptr);

	rc = zpc_aes_xts_key_alloc(&xts_key1);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_key_alloc(&xts_key2);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_full_alloc(&xts_full);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_xts_key_set_type(xts_key1, type);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_xts_key_set_size(xts_key1, keylen * 8);
	EXPECT_EQ(rc, 0);

	rc = testlib_set_aes_xts_key_from_pvsecret(xts_key1, keylen * 8);
	if (rc)
		goto ret;

	rc = zpc_aes_xts_key_set_type(xts_key2, type);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_key_set_size(xts_key2, keylen * 8);
	EXPECT_EQ(rc, 0);

	rc = testlib_set_aes_xts_key_from_pvsecret(xts_key2, keylen * 8);
	if (rc)
		goto ret;

	/* Encrypt */
	memcpy(buf, msg, msglen);

	rc = zpc_aes_xts_full_set_key(xts_full, xts_key1);
	EXPECT_EQ(rc, 0);
	memset(xts_full->param_km + AES_FXTS_WKVP_OFFSET(xts_full->xts_key->keysize), 0, 32); /* force WKaVP mismatch */
	rc = zpc_aes_xts_full_set_iv(xts_full, iv);
	EXPECT_EQ(rc, 0);

	memset(xts_full->param_km + AES_FXTS_WKVP_OFFSET(xts_full->xts_key->keysize), 0, 32); /* force WKaVP mismatch */
	rc = zpc_aes_xts_full_encrypt(xts_full, buf, buf, msglen);
	EXPECT_EQ(rc, 0);

	if (type != ZPC_AES_XTS_KEY_TYPE_PVSECRET) {
		EXPECT_TRUE(memcmp(buf, ct, ctlen) == 0);
	}

	/* Encrypt */
	memcpy(buf, msg, msglen);

	rc = zpc_aes_xts_full_set_key(xts_full, xts_key1);
	EXPECT_EQ(rc, 0);
	memset(xts_full->param_km + AES_FXTS_WKVP_OFFSET(xts_full->xts_key->keysize), 0, 32); /* force WKaVP mismatch */
	rc = zpc_aes_xts_full_set_iv(xts_full, iv);
	EXPECT_EQ(rc, 0);

	memset(xts_full->param_km + AES_FXTS_WKVP_OFFSET(xts_full->xts_key->keysize), 0, 32); /* force WKaVP mismatch */
	rc = zpc_aes_xts_full_encrypt(xts_full, buf, buf, msglen);
	EXPECT_EQ(rc, 0);

	if (type != ZPC_AES_XTS_KEY_TYPE_PVSECRET) {
		EXPECT_TRUE(memcmp(buf, ct, ctlen) == 0);
	}

	/* Decrypt */
	memcpy(buf, ct, ctlen);

	memset(xts_full->param_km + AES_FXTS_WKVP_OFFSET(xts_full->xts_key->keysize), 0, 32); /* force WKaVP mismatch */
	rc = zpc_aes_xts_full_set_iv(xts_full, iv);
	EXPECT_EQ(rc, 0);

	memset(xts_full->param_km + AES_FXTS_WKVP_OFFSET(xts_full->xts_key->keysize), 0, 32); /* force WKaVP mismatch */
	rc = zpc_aes_xts_full_decrypt(xts_full, buf, buf,  msglen);
	EXPECT_EQ(rc, 0);

	if (type != ZPC_AES_XTS_KEY_TYPE_PVSECRET) {
		EXPECT_TRUE(memcmp(buf, msg, msglen) == 0);
	}

	/* Decrypt */
	memcpy(buf, ct, ctlen);

	memset(xts_full->param_km + AES_FXTS_WKVP_OFFSET(xts_full->xts_key->keysize), 0, 32); /* force WKaVP mismatch */
	rc = zpc_aes_xts_full_set_iv(xts_full, iv);
	EXPECT_EQ(rc, 0);

	memset(xts_full->param_km + AES_FXTS_WKVP_OFFSET(xts_full->xts_key->keysize), 0, 32); /* force WKaVP mismatch */
	rc = zpc_aes_xts_full_decrypt(xts_full, buf, buf, msglen);
	EXPECT_EQ(rc, 0);

	if (type != ZPC_AES_XTS_KEY_TYPE_PVSECRET) {
		EXPECT_TRUE(memcmp(buf, msg, msglen) == 0);
	}

ret:
	zpc_aes_xts_full_free(&xts_full);
	EXPECT_EQ(xts_full, nullptr);
	zpc_aes_xts_key_free(&xts_key1);
	EXPECT_EQ(xts_key1, nullptr);
	zpc_aes_xts_key_free(&xts_key2);
	EXPECT_EQ(xts_key2, nullptr);

	free(key1);
	free(iv);
	free(msg);
	free(ct);
}

/*
 * This test is applicable for the 2 AES-XTS secrets: AES-XTS_128-KEY and
 * AES-XTS256-KEY.
 *
 * It assumes that the tester manually added the clear AES XTS key
 * to the pvsecret list file, for example:
 *
 * 2 AES-XTS-128-KEY:
 * 0x8cf9659cd ...   <- secret ID
 * 0x5e511208c7d50 ...  <- clear key value
 *  ...
 *
 * The test creates one pvsecret-type XTS key and two CCA or EP11 type
 * single AES keys with the given clear key material to compare results.
 */
TEST(aes_xts_full, pvsecret_kat)
{
	struct zpc_aes_xts_key *xts_key;
	struct zpc_aes_xts_full *xts_full;
	struct zpc_aes_key *aes_key1, *aes_key2;
	struct zpc_aes_xts *aes_xts;
	u8 iv[16], m[96], c[96], m_bak[96], c_bak[96];
	const char *mkvp, *apqns[257];
	unsigned int flags;
	int type, type2, rc, size;

	TESTLIB_ENV_AES_XTS_KEY_CHECK();

	TESTLIB_ENV_AES_KEY_CHECK();

	TESTLIB_AES_XTS_FULL_HW_CAPS_CHECK();

	TESTLIB_AES_XTS_HW_CAPS_CHECK();

	size = testlib_env_aes_xts_key_size();
	type = testlib_env_aes_xts_key_type();
	type2 = testlib_env_aes_key_type();
	flags = testlib_env_aes_key_flags();
	mkvp = testlib_env_aes_key_mkvp();
	(void)testlib_env_aes_key_apqns(apqns);

	if (type != ZPC_AES_XTS_KEY_TYPE_PVSECRET)
		GTEST_SKIP_("Skipping pvsecret_kat test. Only applicable for UV secrets.");

	TESTLIB_AES_XTS_FULL_KERNEL_CAPS_CHECK();

	TESTLIB_AES_XTS_KEY_SIZE_CHECK(size);

	TESTLIB_AES_XTS_FULL_KERNEL_CAPS_CHECK();

	TESTLIB_AES_XTS_FULL_SW_CAPS_CHECK(type);

	TESTLIB_APQN_CAPS_CHECK(apqns, mkvp, type, size, flags);

	rc = zpc_aes_key_alloc(&aes_key1);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_key_alloc(&aes_key2);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_key_alloc(&xts_key);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_full_alloc(&xts_full);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_alloc(&aes_xts);
	EXPECT_EQ(rc, 0);

	/*
	 * Create one full-xts key from pvsecret for xts_full ctx.
	 */
	rc = zpc_aes_xts_key_set_type(xts_key, type);
	EXPECT_EQ(rc, 0);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_key_set_size(xts_key, size);
	EXPECT_EQ(rc, 0);
	rc = testlib_set_aes_xts_key_from_pvsecret(xts_key, size);
	if (rc)
		goto ret;
	rc = zpc_aes_xts_full_set_key(xts_full, xts_key);
	EXPECT_EQ(rc, 0);

	/*
	 * Create two single AES keys from clear key material from list file
	 * for aes_xts context.
	 */
	rc = zpc_aes_key_set_type(aes_key1, type2);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_key_set_type(aes_key2, type2);
	EXPECT_EQ(rc, 0);
	if (mkvp != NULL) {
		rc = zpc_aes_key_set_mkvp(aes_key1, mkvp);
		EXPECT_EQ(rc, 0);
		rc += zpc_aes_key_set_mkvp(aes_key2, mkvp);
		EXPECT_EQ(rc, 0);
	} else {
		rc = zpc_aes_key_set_apqns(aes_key1, apqns);
		EXPECT_EQ(rc, 0);
		rc = zpc_aes_key_set_apqns(aes_key2, apqns);
		EXPECT_EQ(rc, 0);
	}

	rc = zpc_aes_key_set_flags(aes_key1, flags);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_key_set_flags(aes_key2, flags);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_key_set_size(aes_key1, size);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_key_set_size(aes_key2, size);
	EXPECT_EQ(rc, 0);

	rc = testlib_set_aes_key_from_file(aes_key1, type2, size, 1, 1);
	rc += testlib_set_aes_key_from_file(aes_key2, type2, size, 1, 2);
	if (rc)
		goto ret;

	rc = zpc_aes_xts_set_key(aes_xts, aes_key1, aes_key2);
	EXPECT_EQ(rc, 0);

	memcpy(m_bak, m, 96);

	/* Now encrypt with both ctx and compare result */
	rc = zpc_aes_xts_full_set_iv(xts_full, iv);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_full_encrypt(xts_full, c, m, 96);
	EXPECT_EQ(rc, 0);
	memcpy(c_bak, c, 96);
	rc = zpc_aes_xts_set_iv(aes_xts, iv);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_encrypt(aes_xts, c, m, 96);
	EXPECT_EQ(rc, 0);
	EXPECT_TRUE(memcmp(c, c_bak, 96) == 0);

	/* Now encrypt with xts_full and decrypt with aes_xts */
	rc = zpc_aes_xts_full_set_iv(xts_full, iv);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_full_encrypt(xts_full, c, m, 96);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_set_iv(aes_xts, iv);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_decrypt(aes_xts, m, c, 96);
	EXPECT_EQ(rc, 0);
	EXPECT_TRUE(memcmp(m, m_bak, 96) == 0);

ret:
	zpc_aes_xts_full_free(&xts_full);
	EXPECT_EQ(xts_full, nullptr);
	zpc_aes_xts_free(&aes_xts);
	EXPECT_EQ(aes_xts, nullptr);
	zpc_aes_key_free(&aes_key1);
	EXPECT_EQ(aes_key1, nullptr);
	zpc_aes_key_free(&aes_key2);
	EXPECT_EQ(aes_key2, nullptr);
	zpc_aes_xts_key_free(&xts_key);
	EXPECT_EQ(xts_key, nullptr);
}

static void
__task(struct zpc_aes_xts_key *xts_key)
{
	struct zpc_aes_xts_full *xts_full;
	unsigned char buf[4096];
	size_t ivlen, msglen, ctlen;
	int rc, i;

	const char *ivstr = "4b15c684a152d485fe9937d39b168c29";
	const char *msgstr = "2f3b9dcfbae729583b1d1ffdd16bb6fe2757329435662a78f0";
	const char *ctstr = "f3473802e38a3ffef4d4fb8e6aa266ebde553a64528a06463e";

	u8 *iv = testlib_hexstr2buf(ivstr, &ivlen);
	ASSERT_NE(iv, nullptr);
	u8 *msg = testlib_hexstr2buf(msgstr, &msglen);
	ASSERT_NE(msg, nullptr);
	u8 *ct = testlib_hexstr2buf(ctstr, &ctlen);
	ASSERT_NE(ct, nullptr);

	rc = zpc_aes_xts_full_alloc(&xts_full);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_xts_full_set_key(xts_full, xts_key);
	EXPECT_EQ(rc, 0);

	for (i = 0; i < 1000; i++) {
		/* Encrypt */
		memcpy(buf, msg, msglen);

		memset(xts_full->param_km + AES_FXTS_WKVP_OFFSET(xts_full->xts_key->keysize), 0, 32); /* force WKaVP mismatch */
		rc = zpc_aes_xts_full_set_iv(xts_full, iv);
		EXPECT_EQ(rc, 0);

		memset(xts_full->param_km + AES_FXTS_WKVP_OFFSET(xts_full->xts_key->keysize), 0, 32); /* force WKaVP mismatch */
		rc = zpc_aes_xts_full_encrypt(xts_full, buf, buf, ctlen);
		EXPECT_EQ(rc, 0);

		if (xts_key->type != ZPC_AES_XTS_KEY_TYPE_PVSECRET) {
			EXPECT_TRUE(memcmp(buf, ct, ctlen) == 0);
		}

		/* Decrypt */
		if (xts_key->type != ZPC_AES_XTS_KEY_TYPE_PVSECRET) {
			memcpy(buf, ct, ctlen);
		}

		memset(xts_full->param_km + AES_FXTS_WKVP_OFFSET(xts_full->xts_key->keysize), 0, 32); /* force WKaVP mismatch */
		rc = zpc_aes_xts_full_set_iv(xts_full, iv);
		EXPECT_EQ(rc, 0);

		memset(xts_full->param_km + AES_FXTS_WKVP_OFFSET(xts_full->xts_key->keysize), 0, 32); /* force WKaVP mismatch */
		rc = zpc_aes_xts_full_decrypt(xts_full, buf, buf, msglen);
		EXPECT_EQ(rc, 0);

		EXPECT_TRUE(memcmp(buf, msg, msglen) == 0);
	}

	zpc_aes_xts_full_free(&xts_full);
	EXPECT_EQ(xts_full, nullptr);

	free(iv);
	free(msg);
	free(ct);
}

TEST(aes_xts_full, threads)
{
	TESTLIB_ENV_AES_XTS_KEY_CHECK();

	TESTLIB_AES_XTS_FULL_HW_CAPS_CHECK();

	size_t keylen;
	struct zpc_aes_xts_key *xts_key;
	int type, rc, i;
	std::thread *t[500];

	const char *keystr = "394c97881abd989d29c703e48a72b397a7acf51b59649eeea9b33274d8541df4";

	type = testlib_env_aes_xts_key_type();

	TESTLIB_AES_XTS_FULL_KERNEL_CAPS_CHECK();

	TESTLIB_AES_XTS_FULL_SW_CAPS_CHECK(type);

	u8 *key1 = testlib_hexstr2buf(keystr, &keylen);

	rc = zpc_aes_xts_key_alloc(&xts_key);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_xts_key_set_type(xts_key, type);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_xts_key_set_size(xts_key, keylen * 8);
	EXPECT_EQ(rc, 0);

	rc = testlib_set_aes_xts_key_from_pvsecret(xts_key, keylen * 8);
	if (rc)
		goto ret;

	for (i = 0; i < 500; i++) {
		t[i] = new std::thread(__task, xts_key);
	}

	/*
	 * Do something with key object while threads are working with it.
	 * pvsecret-type full-xts keys can be rederived from their IDs. But their
	 * IDs cannot be restored, aka "reenciphered", if corrupted. Therefore
	 * don't corrupt any IDs here.
	 */
	for (i = 0; i < 500; i++) {
		memset(&xts_key->prot, 0, sizeof(xts_key->prot)); /* destroy cached protected key */
		usleep(1);
	}

	for (i = 0; i < 500; i++) {
		t[i]->join();
		delete t[i];
	}

ret:
	zpc_aes_xts_key_free(&xts_key);
	EXPECT_EQ(xts_key, nullptr);
	free(key1);
}
