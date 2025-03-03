/*
 * Copyright IBM Corp. 2025
 *
 * libzpc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "testlib.h"
#include "gtest/gtest.h"

#include "zpc/hmac_key.h"
#include "zpc/error.h"

const int hfunc2keysize[] {
	512, 512, 1024, 1024,
};

TEST(hmac_key, alloc)
{
	struct zpc_hmac_key *hmac_key;
	int rc;

	TESTLIB_ENV_HMAC_KEY_CHECK();

	rc = zpc_hmac_key_alloc(NULL);
	EXPECT_EQ(rc, ZPC_ERROR_ARG1NULL);

	hmac_key = NULL;
	rc = zpc_hmac_key_alloc(&hmac_key);
	EXPECT_EQ(rc, 0);
	zpc_hmac_key_free(&hmac_key);
	EXPECT_EQ(hmac_key, nullptr);

	hmac_key = (struct zpc_hmac_key *)&hmac_key;
	rc = zpc_hmac_key_alloc(&hmac_key);
	EXPECT_EQ(rc, 0);
	zpc_hmac_key_free(&hmac_key);
	EXPECT_EQ(hmac_key, nullptr);
}

TEST(hmac_key, free)
{
	struct zpc_hmac_key *hmac_key;
	int rc;

	TESTLIB_ENV_HMAC_KEY_CHECK();

	zpc_hmac_key_free(NULL);

	hmac_key = NULL;
	zpc_hmac_key_free(&hmac_key);
	EXPECT_EQ(hmac_key, nullptr);

	rc = zpc_hmac_key_alloc(&hmac_key);
	EXPECT_EQ(rc, 0);
	zpc_hmac_key_free(&hmac_key);
	EXPECT_EQ(hmac_key, nullptr);
}

TEST(hmac_key, set_type)
{
	struct zpc_hmac_key *hmac_key;
	int rc;

	TESTLIB_ENV_HMAC_KEY_CHECK();

	rc = zpc_hmac_key_alloc(&hmac_key);
	EXPECT_EQ(rc, 0);

	rc = zpc_hmac_key_set_type(NULL, -1);
	EXPECT_EQ(rc, ZPC_ERROR_ARG1NULL);
	rc = zpc_hmac_key_set_type(NULL, 0);
	EXPECT_EQ(rc, ZPC_ERROR_ARG1NULL);
	rc = zpc_hmac_key_set_type(NULL, ZPC_HMAC_KEY_TYPE_PVSECRET);
	EXPECT_EQ(rc, ZPC_ERROR_ARG1NULL);
	rc = zpc_hmac_key_set_type(NULL, 4);
	EXPECT_EQ(rc, ZPC_ERROR_ARG1NULL);

	rc = zpc_hmac_key_set_type(hmac_key, -1);
	EXPECT_EQ(rc, ZPC_ERROR_KEYTYPE);
	rc = zpc_hmac_key_set_type(hmac_key, 0);
	EXPECT_EQ(rc, ZPC_ERROR_KEYTYPE);
	rc = zpc_hmac_key_set_type(hmac_key, ZPC_HMAC_KEY_TYPE_PVSECRET);
	EXPECT_TRUE(rc == 0 || rc == ZPC_ERROR_UV_PVSECRETS_NOT_AVAILABLE);
	rc = zpc_hmac_key_set_type(hmac_key, 5);
	EXPECT_EQ(rc, ZPC_ERROR_KEYTYPE);

	zpc_hmac_key_free(&hmac_key);
	EXPECT_EQ(hmac_key, nullptr);
}

TEST(hmac_key, set_hashfunc)
{
	struct zpc_hmac_key *hmac_key;
	int rc;

	TESTLIB_ENV_HMAC_KEY_CHECK();

	rc = zpc_hmac_key_alloc(&hmac_key);
	EXPECT_EQ(rc, 0);

	rc = zpc_hmac_key_set_hash_function(NULL, ZPC_HMAC_HASHFUNC_INVALID);
	EXPECT_EQ(rc, ZPC_ERROR_ARG1NULL);
	rc = zpc_hmac_key_set_hash_function(NULL, ZPC_HMAC_HASHFUNC_NOT_SET);
	EXPECT_EQ(rc, ZPC_ERROR_ARG1NULL);
	rc = zpc_hmac_key_set_hash_function(NULL, ZPC_HMAC_HASHFUNC_SHA_224);
	EXPECT_EQ(rc, ZPC_ERROR_ARG1NULL);

	rc = zpc_hmac_key_set_hash_function(hmac_key, ZPC_HMAC_HASHFUNC_INVALID);
	EXPECT_EQ(rc, ZPC_ERROR_HMAC_HASH_FUNCTION_INVALID);
	rc = zpc_hmac_key_set_hash_function(hmac_key, ZPC_HMAC_HASHFUNC_SHA_224);
	EXPECT_TRUE(rc == 0 || rc == ZPC_ERROR_HWCAPS);

	zpc_hmac_key_free(&hmac_key);
	EXPECT_EQ(hmac_key, nullptr);
}

TEST(hmac_key, import_clear_1)
{
	struct zpc_hmac_key *hmac_key;
	const u8 key[32] = { 0, };
	int rc;
	zpc_hmac_hashfunc_t hfunc;

	TESTLIB_ENV_HMAC_KEY_CHECK();

	hfunc = testlib_env_hmac_hashfunc();

	TESTLIB_HMAC_KERNEL_CAPS_CHECK();

	rc = zpc_hmac_key_alloc(&hmac_key);
	EXPECT_EQ(rc, 0);

	rc = zpc_hmac_key_import_clear(NULL, NULL, 0);
	EXPECT_EQ(rc, ZPC_ERROR_ARG1NULL);
	rc = zpc_hmac_key_import_clear(NULL, key, 0);
	EXPECT_EQ(rc, ZPC_ERROR_ARG1NULL);
	rc = zpc_hmac_key_import_clear(hmac_key, NULL, 0);
	EXPECT_EQ(rc, ZPC_ERROR_ARG2NULL);

	rc = zpc_hmac_key_import_clear(hmac_key, key, 0);
	EXPECT_EQ(rc, ZPC_ERROR_KEYSIZE);

	rc = zpc_hmac_key_import_clear(hmac_key, key, 1);
	EXPECT_EQ(rc, ZPC_ERROR_HMAC_HASH_FUNCTION_NOTSET);

	rc = zpc_hmac_key_set_hash_function(hmac_key, hfunc);
	EXPECT_EQ(rc, 0);

	rc = zpc_hmac_key_import_clear(hmac_key, key, sizeof(key));
	EXPECT_EQ(rc, 0);

	zpc_hmac_key_free(&hmac_key);
	EXPECT_EQ(hmac_key, nullptr);
}

TEST(hmac_key, import_clear_2)
{
	struct zpc_hmac_key *hmac_key;
	u8 clearkey[256];
	int rc;
	zpc_hmac_hashfunc_t hfunc;

	TESTLIB_ENV_HMAC_KEY_CHECK();

	hfunc = testlib_env_hmac_hashfunc();

	TESTLIB_HMAC_KERNEL_CAPS_CHECK();

	rc = zpc_hmac_key_alloc(&hmac_key);
	EXPECT_EQ(rc, 0);

	rc = zpc_hmac_key_set_hash_function(hmac_key, hfunc);
	EXPECT_EQ(rc, 0);

	/*
	 * Keys shorter than the block size of the hash function are padded to the
	 * right up to the block size. The block size of SHA-224 and SHA-256 is
	 * 512 bits (64 bytes) and the bock size of SHA-384 and SHA-512 is 1024
	 * bits (128 bytes).
	 */
	rc = zpc_hmac_key_import_clear(hmac_key, clearkey, 55);
	EXPECT_EQ(rc, 0);

	/*
	 * Keys longer than the block size of the hash function are first hashed
	 * and then padded with binary zeros up to the block size of the digest.
	 */
	rc = zpc_hmac_key_import_clear(hmac_key, clearkey, 222);
	EXPECT_EQ(rc, 0);

	zpc_hmac_key_free(&hmac_key);
	EXPECT_EQ(hmac_key, nullptr);
}

TEST(hmac_key, generate_1)
{
	struct zpc_hmac_key *hmac_key;
	int rc;
	zpc_hmac_hashfunc_t hfunc;

	TESTLIB_ENV_HMAC_KEY_CHECK();

	hfunc = testlib_env_hmac_hashfunc();

	TESTLIB_HMAC_KERNEL_CAPS_CHECK();

	rc = zpc_hmac_key_alloc(&hmac_key);
	EXPECT_EQ(rc, 0);

	rc = zpc_hmac_key_generate(NULL);
	EXPECT_EQ(rc, ZPC_ERROR_ARG1NULL);

	rc = zpc_hmac_key_generate(hmac_key);
	EXPECT_EQ(rc, ZPC_ERROR_HMAC_HASH_FUNCTION_NOTSET);

	rc = zpc_hmac_key_set_hash_function(hmac_key, hfunc);
	EXPECT_EQ(rc, 0);

	rc = zpc_hmac_key_generate(hmac_key);
	EXPECT_EQ(rc, 0);

	zpc_hmac_key_free(&hmac_key);
	EXPECT_EQ(hmac_key, nullptr);
}

TEST(hmac_key, export)
{
	struct zpc_hmac_key *hmac_key;
	u8 buf[10000];
	int rc, type;
	size_t buflen;
	zpc_hmac_hashfunc_t hfunc;

	TESTLIB_ENV_HMAC_KEY_CHECK();

	type = testlib_env_hmac_key_type();
	hfunc = testlib_env_hmac_hashfunc();

	TESTLIB_HMAC_KERNEL_CAPS_CHECK();

	TESTLIB_HMAC_SW_CAPS_CHECK(type);

	rc = zpc_hmac_key_export(NULL, NULL, NULL);
	EXPECT_EQ(rc, ZPC_ERROR_ARG1NULL);

	rc = zpc_hmac_key_alloc(&hmac_key);
	EXPECT_EQ(rc, 0);

	rc = zpc_hmac_key_export(hmac_key, NULL, NULL);
	EXPECT_EQ(rc, ZPC_ERROR_ARG3NULL);

	rc = zpc_hmac_key_export(hmac_key, NULL, &buflen);
	EXPECT_EQ(rc, ZPC_ERROR_KEYNOTSET);

	rc = zpc_hmac_key_set_type(hmac_key, type);
	EXPECT_EQ(rc, 0);
	rc = zpc_hmac_key_set_hash_function(hmac_key, hfunc);
	EXPECT_EQ(rc, 0);

	rc = testlib_set_hmac_key_from_pvsecret(hmac_key, hfunc2keysize[hfunc]);
	if (rc)
		goto ret;

	buflen = 0;
	rc = zpc_hmac_key_export(hmac_key, buf, &buflen);
	EXPECT_EQ(rc, ZPC_ERROR_SMALLOUTBUF);

	rc = zpc_hmac_key_export(hmac_key, NULL, &buflen);
	EXPECT_EQ(rc, 0);
	EXPECT_GT(buflen, 0UL);

	rc = zpc_hmac_key_export(hmac_key, buf, &buflen);
	EXPECT_EQ(rc, 0);

ret:
	zpc_hmac_key_free(&hmac_key);
	EXPECT_EQ(hmac_key, nullptr);
}

TEST(hmac_key, import)
{
	struct zpc_hmac_key *hmac_key, *hmac_key2;
	u8 buf[10000], buf2[10000];
	int rc, type;
	size_t buflen = sizeof(buf);
	size_t buf2len = sizeof(buf2);
	zpc_hmac_hashfunc_t hfunc;

	TESTLIB_ENV_HMAC_KEY_CHECK();

	type = testlib_env_hmac_key_type();
	hfunc = testlib_env_hmac_hashfunc();

	TESTLIB_HMAC_KERNEL_CAPS_CHECK();

	TESTLIB_HMAC_SW_CAPS_CHECK(type);

	rc = zpc_hmac_key_alloc(&hmac_key);
	EXPECT_EQ(rc, 0);
	rc = zpc_hmac_key_alloc(&hmac_key2);
	EXPECT_EQ(rc, 0);

	rc = zpc_hmac_key_import(NULL, NULL, 0);
	EXPECT_EQ(rc, ZPC_ERROR_ARG1NULL);
	rc = zpc_hmac_key_import(hmac_key, NULL, 0);
	EXPECT_EQ(rc, ZPC_ERROR_ARG2NULL);

	rc = zpc_hmac_key_import(hmac_key, buf, 63);
	EXPECT_EQ(rc, ZPC_ERROR_ARG3RANGE);
	rc = zpc_hmac_key_import(hmac_key, buf, 630);
	EXPECT_EQ(rc, ZPC_ERROR_ARG3RANGE);

	rc = zpc_hmac_key_set_hash_function(hmac_key, hfunc);
	EXPECT_EQ(rc, 0);
	rc = zpc_hmac_key_set_hash_function(hmac_key2, hfunc);
	EXPECT_EQ(rc, 0);

	rc = zpc_hmac_key_import(hmac_key, buf, 32);
	EXPECT_EQ(rc, ZPC_ERROR_KEYTYPENOTSET);

	rc = zpc_hmac_key_set_type(hmac_key, type);
	EXPECT_EQ(rc, 0);
	rc = zpc_hmac_key_set_type(hmac_key2, type);
	EXPECT_EQ(rc, 0);

	rc = testlib_set_hmac_key_from_pvsecret(hmac_key, hfunc2keysize[hfunc]);
	if (rc)
		goto ret;

	rc = zpc_hmac_key_export(hmac_key, buf, &buflen);
	EXPECT_EQ(rc, 0);

	rc = zpc_hmac_key_import(hmac_key2, buf, buflen);
	EXPECT_EQ(rc, 0);

	rc = zpc_hmac_key_export(hmac_key2, buf2, &buf2len);
	EXPECT_EQ(rc, 0);

	EXPECT_EQ(buf2len, buflen);
	EXPECT_TRUE(memcmp(buf2, buf, buflen) == 0);

ret:
	zpc_hmac_key_free(&hmac_key);
	EXPECT_EQ(hmac_key, nullptr);
	zpc_hmac_key_free(&hmac_key2);
	EXPECT_EQ(hmac_key2, nullptr);
}
