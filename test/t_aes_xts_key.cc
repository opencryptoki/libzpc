/*
 * Copyright IBM Corp. 2025
 *
 * libzpc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "testlib.h"
#include "gtest/gtest.h"

#include "zpc/aes_xts_key.h"
#include "zpc/error.h"

TEST(aes_xts_key, alloc)
{
	struct zpc_aes_xts_key *xts_key;
	int rc;

	TESTLIB_ENV_AES_XTS_KEY_CHECK();

	rc = zpc_aes_xts_key_alloc(NULL);
	EXPECT_EQ(rc, ZPC_ERROR_ARG1NULL);

	xts_key = NULL;
	rc = zpc_aes_xts_key_alloc(&xts_key);
	EXPECT_EQ(rc, 0);
	zpc_aes_xts_key_free(&xts_key);
	EXPECT_EQ(xts_key, nullptr);

	xts_key = (struct zpc_aes_xts_key *)&xts_key;
	rc = zpc_aes_xts_key_alloc(&xts_key);
	EXPECT_EQ(rc, 0);
	zpc_aes_xts_key_free(&xts_key);
	EXPECT_EQ(xts_key, nullptr);
}

TEST(aes_xts_key, free)
{
	struct zpc_aes_xts_key *xts_key;
	int rc;

	TESTLIB_ENV_AES_XTS_KEY_CHECK();

	zpc_aes_xts_key_free(NULL);

	xts_key = NULL;
	zpc_aes_xts_key_free(&xts_key);
	EXPECT_EQ(xts_key, nullptr);

	rc = zpc_aes_xts_key_alloc(&xts_key);
	EXPECT_EQ(rc, 0);
	zpc_aes_xts_key_free(&xts_key);
	EXPECT_EQ(xts_key, nullptr);
}

TEST(aes_xts_key, set_keysize)
{
	struct zpc_aes_xts_key *xts_key;
	int rc;

	TESTLIB_ENV_AES_XTS_KEY_CHECK();

	rc = zpc_aes_xts_key_alloc(&xts_key);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_xts_key_set_size(NULL, -1);
	EXPECT_EQ(rc, ZPC_ERROR_ARG1NULL);
	rc = zpc_aes_xts_key_set_size(NULL, 0);
	EXPECT_EQ(rc, ZPC_ERROR_ARG1NULL);
	rc = zpc_aes_xts_key_set_size(NULL, 1);
	EXPECT_EQ(rc, ZPC_ERROR_ARG1NULL);
	rc = zpc_aes_xts_key_set_size(NULL, 128);
	EXPECT_EQ(rc, ZPC_ERROR_ARG1NULL);
	rc = zpc_aes_xts_key_set_size(NULL, 192);
	EXPECT_EQ(rc, ZPC_ERROR_ARG1NULL);
	rc = zpc_aes_xts_key_set_size(NULL, 256);
	EXPECT_EQ(rc, ZPC_ERROR_ARG1NULL);

	rc = zpc_aes_xts_key_set_size(xts_key, -1);
	EXPECT_EQ(rc, ZPC_ERROR_KEYSIZE);
	rc = zpc_aes_xts_key_set_size(xts_key, 0);
	EXPECT_EQ(rc, ZPC_ERROR_KEYSIZE);
	rc = zpc_aes_xts_key_set_size(xts_key, 1);
	EXPECT_EQ(rc, ZPC_ERROR_KEYSIZE);
	rc = zpc_aes_xts_key_set_size(xts_key, 128);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_key_set_size(xts_key, 192);
	EXPECT_EQ(rc, ZPC_ERROR_KEYSIZE);
	rc = zpc_aes_xts_key_set_size(xts_key, 256);
	EXPECT_EQ(rc, 0);

	zpc_aes_xts_key_free(&xts_key);
	EXPECT_EQ(xts_key, nullptr);
}

TEST(aes_xts_key, set_type)
{
	struct zpc_aes_xts_key *xts_key;
	int rc;

	TESTLIB_ENV_AES_XTS_KEY_CHECK();

	rc = zpc_aes_xts_key_alloc(&xts_key);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_xts_key_set_type(NULL, -1);
	EXPECT_EQ(rc, ZPC_ERROR_ARG1NULL);
	rc = zpc_aes_xts_key_set_type(NULL, 0);
	EXPECT_EQ(rc, ZPC_ERROR_ARG1NULL);
	rc = zpc_aes_xts_key_set_type(NULL, 4);
	EXPECT_EQ(rc, ZPC_ERROR_ARG1NULL);

	rc = zpc_aes_xts_key_set_type(xts_key, -1);
	EXPECT_EQ(rc, ZPC_ERROR_KEYTYPE);
	rc = zpc_aes_xts_key_set_type(xts_key, 0);
	EXPECT_EQ(rc, ZPC_ERROR_KEYTYPE);
	rc = zpc_aes_xts_key_set_type(xts_key, ZPC_AES_XTS_KEY_TYPE_PVSECRET);
	EXPECT_TRUE(rc == 0 || rc == ZPC_ERROR_UV_PVSECRETS_NOT_AVAILABLE);
	rc = zpc_aes_xts_key_set_type(xts_key, 5);
	EXPECT_EQ(rc, ZPC_ERROR_KEYTYPE);

	zpc_aes_xts_key_free(&xts_key);
	EXPECT_EQ(xts_key, nullptr);
}

TEST(aes_xts_key, import_clear_1)
{
	struct zpc_aes_xts_key *xts_key;
	const u8 key[64] = { 0, };
	int rc, size;

	TESTLIB_ENV_AES_XTS_KEY_CHECK();

	size = testlib_env_aes_xts_key_size();

	TESTLIB_AES_XTS_FULL_KERNEL_CAPS_CHECK();

	rc = zpc_aes_xts_key_alloc(&xts_key);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_xts_key_import_clear(NULL, NULL);
	EXPECT_EQ(rc, ZPC_ERROR_ARG1NULL);
	rc = zpc_aes_xts_key_import_clear(NULL, key);
	EXPECT_EQ(rc, ZPC_ERROR_ARG1NULL);

	rc = zpc_aes_xts_key_import_clear(xts_key, NULL);
	EXPECT_EQ(rc, ZPC_ERROR_ARG2NULL);
	rc = zpc_aes_xts_key_import_clear(xts_key, key);
	EXPECT_EQ(rc, ZPC_ERROR_KEYSIZENOTSET);

	rc = zpc_aes_xts_key_set_size(xts_key, size);
	EXPECT_EQ(rc, 0);

	/*
	 * import_clear is possible, because no type set. This will effectively
	 * be a random protected key, because the clear key data is not kept.
	 */
	rc = zpc_aes_xts_key_import_clear(xts_key, key);
	EXPECT_EQ(rc, 0);

	zpc_aes_xts_key_free(&xts_key);
	EXPECT_EQ(xts_key, nullptr);
}

TEST(aes_xts_key, generate_1)
{
	struct zpc_aes_xts_key *xts_key;
	int rc, size;

	TESTLIB_ENV_AES_XTS_KEY_CHECK();

	size = testlib_env_aes_xts_key_size();

	TESTLIB_AES_XTS_FULL_KERNEL_CAPS_CHECK();

	rc = zpc_aes_xts_key_alloc(&xts_key);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_xts_key_generate(NULL);
	EXPECT_EQ(rc, ZPC_ERROR_ARG1NULL);

	rc = zpc_aes_xts_key_generate(xts_key);
	EXPECT_EQ(rc, ZPC_ERROR_KEYSIZENOTSET);

	rc = zpc_aes_xts_key_set_size(xts_key, size);
	EXPECT_EQ(rc, 0);

	/*
	 * generate is possible, because no type set. This will effectively
	 * be a random protected key.
	 */
	rc = zpc_aes_xts_key_generate(xts_key);
	EXPECT_EQ(rc, 0);

	zpc_aes_xts_key_free(&xts_key);
	EXPECT_EQ(xts_key, nullptr);
}

TEST(aes_xts_key, export)
{
	struct zpc_aes_xts_key *xts_key;
	u8 buf[1024];
	int rc, size, type;
	size_t buflen;

	TESTLIB_ENV_AES_XTS_KEY_CHECK();

	size = testlib_env_aes_xts_key_size();
	type = testlib_env_aes_xts_key_type();

	TESTLIB_AES_XTS_FULL_KERNEL_CAPS_CHECK();

	TESTLIB_AES_XTS_FULL_SW_CAPS_CHECK(type);

	rc = zpc_aes_xts_key_export(NULL, NULL, NULL);
	EXPECT_EQ(rc, ZPC_ERROR_ARG1NULL);

	rc = zpc_aes_xts_key_alloc(&xts_key);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_xts_key_export(xts_key, NULL, NULL);
	EXPECT_EQ(rc, ZPC_ERROR_ARG3NULL);

	rc = zpc_aes_xts_key_export(xts_key, NULL, &buflen);
	EXPECT_EQ(rc, ZPC_ERROR_KEYNOTSET);

	rc = zpc_aes_xts_key_set_type(xts_key, type);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_xts_key_set_size(xts_key, size);
	EXPECT_EQ(rc, 0);

	rc = testlib_set_aes_xts_key_from_pvsecret(xts_key, size);
	if (rc)
		goto ret;

	buflen = 0;
	rc = zpc_aes_xts_key_export(xts_key, buf, &buflen);
	EXPECT_EQ(rc, ZPC_ERROR_SMALLOUTBUF);

	rc = zpc_aes_xts_key_export(xts_key, NULL, &buflen);
	EXPECT_EQ(rc, 0);
	EXPECT_GT(buflen, 0UL);

	rc = zpc_aes_xts_key_export(xts_key, buf, &buflen);
	EXPECT_EQ(rc, 0);

ret:
	zpc_aes_xts_key_free(&xts_key);
	EXPECT_EQ(xts_key, nullptr);
}

TEST(aes_xts_key, import)
{
	struct zpc_aes_xts_key *xts_key, *xts_key2;
	u8 buf[1024], buf2[1024];
	int rc, size, type;
	size_t buflen = sizeof(buf);
	size_t buf2len = sizeof(buf2);

	TESTLIB_ENV_AES_XTS_KEY_CHECK();

	size = testlib_env_aes_xts_key_size();
	type = testlib_env_aes_xts_key_type();

	TESTLIB_AES_XTS_FULL_KERNEL_CAPS_CHECK();

	TESTLIB_AES_XTS_FULL_SW_CAPS_CHECK(type);

	rc = zpc_aes_xts_key_alloc(&xts_key);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_key_alloc(&xts_key2);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_xts_key_import(NULL, NULL, 0);
	EXPECT_EQ(rc, ZPC_ERROR_ARG1NULL);

	rc = zpc_aes_xts_key_import(xts_key, NULL, 0);
	EXPECT_EQ(rc, ZPC_ERROR_ARG2NULL);

	rc = zpc_aes_xts_key_import(xts_key, buf, 63);
	EXPECT_EQ(rc, ZPC_ERROR_ARG3RANGE);
	rc = zpc_aes_xts_key_import(xts_key, buf, 630);
	EXPECT_EQ(rc, ZPC_ERROR_ARG3RANGE);
	
	rc = zpc_aes_xts_key_set_size(xts_key, size);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_key_set_size(xts_key2, size);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_xts_key_import(xts_key, buf, 32);
	EXPECT_EQ(rc, ZPC_ERROR_KEYTYPENOTSET);

	rc = zpc_aes_xts_key_set_type(xts_key, type);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_key_set_type(xts_key2, type);
	EXPECT_EQ(rc, 0);

	rc = testlib_set_aes_xts_key_from_pvsecret(xts_key, size);
	if (rc)
		goto ret;

	rc = zpc_aes_xts_key_export(xts_key, buf, &buflen);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_xts_key_import(xts_key2, buf, buflen);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_xts_key_export(xts_key2, buf2, &buf2len);
	EXPECT_EQ(rc, 0);

	EXPECT_EQ(buf2len, buflen);
	EXPECT_TRUE(memcmp(buf2, buf, buflen) == 0);

ret:
	zpc_aes_xts_key_free(&xts_key);
	EXPECT_EQ(xts_key, nullptr);
	zpc_aes_xts_key_free(&xts_key2);
	EXPECT_EQ(xts_key2, nullptr);
}
