/*
 * Copyright IBM Corp. 2021
 *
 * libzpc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "testlib.h"

#include "gtest/gtest.h"
#include "zpc/aes_key.h"
#include "zpc/error.h"

TEST(aes_key, alloc)
{
	struct zpc_aes_key *aes_key;
	int rc;

	TESTLIB_ENV_AES_KEY_CHECK();

	rc = zpc_aes_key_alloc(NULL);
	EXPECT_EQ(rc, ZPC_ERROR_ARG1NULL);

	aes_key = NULL;
	rc = zpc_aes_key_alloc(&aes_key);
	EXPECT_EQ(rc, 0);
	zpc_aes_key_free(&aes_key);
	EXPECT_EQ(aes_key, nullptr);

	aes_key = (struct zpc_aes_key *)&aes_key;
	rc = zpc_aes_key_alloc(&aes_key);
	EXPECT_EQ(rc, 0);
	zpc_aes_key_free(&aes_key);
	EXPECT_EQ(aes_key, nullptr);
}

TEST(aes_key, free)
{
	struct zpc_aes_key *aes_key;
	int rc;

	TESTLIB_ENV_AES_KEY_CHECK();

	zpc_aes_key_free(NULL);

	aes_key = NULL;
	zpc_aes_key_free(&aes_key);
	EXPECT_EQ(aes_key, nullptr);

	rc = zpc_aes_key_alloc(&aes_key);
	EXPECT_EQ(rc, 0);
	zpc_aes_key_free(&aes_key);
	EXPECT_EQ(aes_key, nullptr);
}

TEST(aes_key, set_keysize)
{
	struct zpc_aes_key *aes_key;
	int rc;

	TESTLIB_ENV_AES_KEY_CHECK();

	rc = zpc_aes_key_alloc(&aes_key);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_key_set_size(NULL, -1);
	EXPECT_EQ(rc, ZPC_ERROR_ARG1NULL);
	rc = zpc_aes_key_set_size(NULL, 0);
	EXPECT_EQ(rc, ZPC_ERROR_ARG1NULL);
	rc = zpc_aes_key_set_size(NULL, 1);
	EXPECT_EQ(rc, ZPC_ERROR_ARG1NULL);
	rc = zpc_aes_key_set_size(NULL, 128);
	EXPECT_EQ(rc, ZPC_ERROR_ARG1NULL);
	rc = zpc_aes_key_set_size(NULL, 192);
	EXPECT_EQ(rc, ZPC_ERROR_ARG1NULL);
	rc = zpc_aes_key_set_size(NULL, 256);
	EXPECT_EQ(rc, ZPC_ERROR_ARG1NULL);

	rc = zpc_aes_key_set_size(aes_key, -1);
	EXPECT_EQ(rc, ZPC_ERROR_KEYSIZE);
	rc = zpc_aes_key_set_size(aes_key, 0);
	EXPECT_EQ(rc, ZPC_ERROR_KEYSIZE);
	rc = zpc_aes_key_set_size(aes_key, 1);
	EXPECT_EQ(rc, ZPC_ERROR_KEYSIZE);
	rc = zpc_aes_key_set_size(aes_key, 128);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_key_set_size(aes_key, 192);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_key_set_size(aes_key, 256);
	EXPECT_EQ(rc, 0);

	zpc_aes_key_free(&aes_key);
	EXPECT_EQ(aes_key, nullptr);
}

TEST(aes_key, set_type)
{
	struct zpc_aes_key *aes_key;
	int rc;

	TESTLIB_ENV_AES_KEY_CHECK();

	rc = zpc_aes_key_alloc(&aes_key);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_key_set_type(NULL, -1);
	EXPECT_EQ(rc, ZPC_ERROR_ARG1NULL);
	rc = zpc_aes_key_set_type(NULL, 0);
	EXPECT_EQ(rc, ZPC_ERROR_ARG1NULL);
	rc = zpc_aes_key_set_type(NULL, ZPC_AES_KEY_TYPE_CCA_DATA);
	EXPECT_EQ(rc, ZPC_ERROR_ARG1NULL);
	rc = zpc_aes_key_set_type(NULL, ZPC_AES_KEY_TYPE_CCA_CIPHER);
	EXPECT_EQ(rc, ZPC_ERROR_ARG1NULL);
	rc = zpc_aes_key_set_type(NULL, ZPC_AES_KEY_TYPE_EP11);
	EXPECT_EQ(rc, ZPC_ERROR_ARG1NULL);
	rc = zpc_aes_key_set_type(NULL, 4);
	EXPECT_EQ(rc, ZPC_ERROR_ARG1NULL);

	rc = zpc_aes_key_set_type(aes_key, -1);
	EXPECT_EQ(rc, ZPC_ERROR_KEYTYPE);
	rc = zpc_aes_key_set_type(aes_key, 0);
	EXPECT_EQ(rc, ZPC_ERROR_KEYTYPE);
	rc = zpc_aes_key_set_type(aes_key, ZPC_AES_KEY_TYPE_CCA_DATA);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_key_set_type(aes_key, ZPC_AES_KEY_TYPE_CCA_CIPHER);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_key_set_type(aes_key, ZPC_AES_KEY_TYPE_EP11);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_key_set_type(aes_key, 4);
	EXPECT_EQ(rc, ZPC_ERROR_KEYTYPE);

	zpc_aes_key_free(&aes_key);
	EXPECT_EQ(aes_key, nullptr);
}

TEST(aes_key, set_flags)
{
	struct zpc_aes_key *aes_key;
	int rc;

	TESTLIB_ENV_AES_KEY_CHECK();

	rc = zpc_aes_key_alloc(&aes_key);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_key_set_flags(NULL, 0);
	EXPECT_EQ(rc, ZPC_ERROR_ARG1NULL);
	rc = zpc_aes_key_set_flags(aes_key, -1);
	EXPECT_EQ(rc, 0);

	zpc_aes_key_free(&aes_key);
	EXPECT_EQ(aes_key, nullptr);
}

TEST(aes_key, set_mkvp)
{
	struct zpc_aes_key *aes_key;
	const char *mkvp;
	unsigned int flags;
	int rc, type;

	TESTLIB_ENV_AES_KEY_CHECK();
	type = testlib_env_aes_key_type();
	flags = testlib_env_aes_key_flags();
	mkvp = testlib_env_aes_key_mkvp();

	rc = zpc_aes_key_alloc(&aes_key);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_key_set_mkvp(NULL, NULL);
	EXPECT_EQ(rc, ZPC_ERROR_ARG1NULL);
	rc = zpc_aes_key_set_mkvp(NULL, mkvp);
	EXPECT_EQ(rc, ZPC_ERROR_ARG1NULL);

	rc = zpc_aes_key_set_mkvp(aes_key, NULL);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_key_set_flags(aes_key, flags);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_key_set_mkvp(aes_key, mkvp);
	if (mkvp != NULL)
		EXPECT_EQ(rc, ZPC_ERROR_KEYTYPENOTSET);
	else
		EXPECT_EQ(rc, 0);
	rc = zpc_aes_key_set_type(aes_key, type);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_key_set_mkvp(aes_key, mkvp);
	EXPECT_EQ(rc, 0);

	zpc_aes_key_free(&aes_key);
	EXPECT_EQ(aes_key, nullptr);
}

TEST(aes_key, set_apqns)
{
	struct zpc_aes_key *aes_key;
	const char *apqns[] = {"01.0037", "\n01.0037\t ", NULL}; /* apqn example */
	int rc;

	TESTLIB_ENV_AES_KEY_CHECK();

	rc = zpc_aes_key_alloc(&aes_key);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_key_set_apqns(NULL, NULL);
	EXPECT_EQ(rc, ZPC_ERROR_ARG1NULL);
	rc = zpc_aes_key_set_apqns(NULL, apqns);
	EXPECT_EQ(rc, ZPC_ERROR_ARG1NULL);

	rc = zpc_aes_key_set_apqns(aes_key, NULL);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_key_set_apqns(aes_key, apqns);
	EXPECT_EQ(rc, 0);

	zpc_aes_key_free(&aes_key);
	EXPECT_EQ(aes_key, nullptr);
}

TEST(aes_key, import_clear_1)
{
	struct zpc_aes_key *aes_key;
	const u8 key[32] = {0};
	const char *apqns[257];
	unsigned int flags;
	int rc, type, size;
	const char *mkvp;

	TESTLIB_ENV_AES_KEY_CHECK();

	TESTLIB_AES_KERNEL_CAPS_CHECK();

	size = testlib_env_aes_key_size();
	type = testlib_env_aes_key_type();
	flags = testlib_env_aes_key_flags();
	mkvp = testlib_env_aes_key_mkvp();
	(void)testlib_env_aes_key_apqns(apqns);

	rc = zpc_aes_key_alloc(&aes_key);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_key_import_clear(NULL, NULL);
	EXPECT_EQ(rc, ZPC_ERROR_ARG1NULL);
	rc = zpc_aes_key_import_clear(NULL, key);
	EXPECT_EQ(rc, ZPC_ERROR_ARG1NULL);

	rc = zpc_aes_key_import_clear(aes_key, NULL);
	EXPECT_EQ(rc, ZPC_ERROR_ARG2NULL);
	rc = zpc_aes_key_import_clear(aes_key, key);
	EXPECT_EQ(rc, ZPC_ERROR_APQNSNOTSET);

	if (mkvp == NULL) {
		rc = zpc_aes_key_set_apqns(aes_key, apqns);
		EXPECT_EQ(rc, 0);
		rc = zpc_aes_key_import_clear(aes_key, key);
		EXPECT_EQ(rc, ZPC_ERROR_KEYSIZENOTSET);
	}

	rc = zpc_aes_key_set_size(aes_key, size);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_key_set_flags(aes_key, flags);
	EXPECT_EQ(rc, 0);

	if (mkvp == NULL) {
		rc = zpc_aes_key_import_clear(aes_key, key);
		EXPECT_EQ(rc, ZPC_ERROR_KEYTYPENOTSET);
	}

	rc = zpc_aes_key_set_type(aes_key, type);
	EXPECT_EQ(rc, 0);
	if (mkvp != NULL) {
		rc = zpc_aes_key_set_mkvp(aes_key, mkvp);
		EXPECT_EQ(rc, 0);
	}
	rc = zpc_aes_key_import_clear(aes_key, key);
	EXPECT_EQ(rc, 0);

	zpc_aes_key_free(&aes_key);
	EXPECT_EQ(aes_key, nullptr);
}

TEST(aes_key, import_clear_2)
{
	struct zpc_aes_key *aes_key;
	u8 clearkey[32];
	const char *apqns[257];
	unsigned int flags;
	int rc, size, type;
	const char *mkvp;

	TESTLIB_ENV_AES_KEY_CHECK();

	TESTLIB_AES_KERNEL_CAPS_CHECK();

	size = testlib_env_aes_key_size();
	type = testlib_env_aes_key_type();
	flags= testlib_env_aes_key_type();
	mkvp = testlib_env_aes_key_mkvp();
	(void)testlib_env_aes_key_apqns(apqns);

	rc = zpc_aes_key_alloc(&aes_key);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_key_set_size(aes_key, size);
	EXPECT_EQ(rc, 0);

	/* mkvp */
	rc = zpc_aes_key_set_flags(aes_key, flags);
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

	rc = zpc_aes_key_import_clear(aes_key, clearkey);
	EXPECT_EQ(rc, 0);

	zpc_aes_key_free(&aes_key);
	EXPECT_EQ(aes_key, nullptr);
}

TEST(aes_key, generate_1)
{
	struct zpc_aes_key *aes_key;
	unsigned int flags;
	const char *apqns[257];
	int rc, size, type;
	const char *mkvp;

	TESTLIB_ENV_AES_KEY_CHECK();

	TESTLIB_AES_KERNEL_CAPS_CHECK();

	size = testlib_env_aes_key_size();
	type = testlib_env_aes_key_type();
	flags= testlib_env_aes_key_flags();
	mkvp = testlib_env_aes_key_mkvp();
	(void)testlib_env_aes_key_apqns(apqns);

	rc = zpc_aes_key_alloc(&aes_key);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_key_generate(NULL);
	EXPECT_EQ(rc, ZPC_ERROR_ARG1NULL);

	rc = zpc_aes_key_generate(aes_key);
	EXPECT_EQ(rc, ZPC_ERROR_KEYSIZENOTSET);

	if (mkvp == NULL) {
		rc = zpc_aes_key_set_apqns(aes_key, apqns);
		EXPECT_EQ(rc, 0);

		rc = zpc_aes_key_generate(aes_key);
		EXPECT_EQ(rc, ZPC_ERROR_KEYSIZENOTSET);
	}

	rc = zpc_aes_key_set_size(aes_key, size);
	EXPECT_EQ(rc, 0);

	if (mkvp == NULL) {
		rc = zpc_aes_key_generate(aes_key);
		EXPECT_EQ(rc, ZPC_ERROR_KEYTYPENOTSET);
	}

	rc = zpc_aes_key_set_type(aes_key, type);
	EXPECT_EQ(rc, 0);
	if (mkvp != NULL) {
		rc = zpc_aes_key_set_mkvp(aes_key, mkvp);
		EXPECT_EQ(rc, 0);
	}
	rc = zpc_aes_key_set_flags(aes_key, flags);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_key_generate(aes_key);
	EXPECT_EQ(rc, 0);

	zpc_aes_key_free(&aes_key);
	EXPECT_EQ(aes_key, nullptr);
}

TEST(aes_key, generate_2)
{
	struct zpc_aes_key *aes_key;
	unsigned int flags;
	const char *apqns[257];
	int rc, size, type;
	const char *mkvp;

	TESTLIB_ENV_AES_KEY_CHECK();

	TESTLIB_AES_KERNEL_CAPS_CHECK();

	size = testlib_env_aes_key_size();
	type = testlib_env_aes_key_type();
	flags= testlib_env_aes_key_flags();
	mkvp = testlib_env_aes_key_mkvp();
	(void)testlib_env_aes_key_apqns(apqns);

	rc = zpc_aes_key_alloc(&aes_key);
	EXPECT_EQ(rc, 0);

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

	zpc_aes_key_free(&aes_key);
	EXPECT_EQ(aes_key, nullptr);
}

TEST(aes_key, reencipher)
{
	struct zpc_aes_key *aes_key;
	unsigned int flags;
	const char *apqns[257];
	int rc, size, type;
	const char *mkvp;

	TESTLIB_ENV_AES_KEY_CHECK();

	TESTLIB_AES_KERNEL_CAPS_CHECK();

	size = testlib_env_aes_key_size();
	type = testlib_env_aes_key_type();
	flags= testlib_env_aes_key_flags();
	mkvp = testlib_env_aes_key_mkvp();
	(void)testlib_env_aes_key_apqns(apqns);

	TESTLIB_AES_SW_CAPS_CHECK(type);

	TESTLIB_AES_NEW_MK_CHECK(type, mkvp, apqns);

	rc = zpc_aes_key_alloc(&aes_key);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_key_set_flags(aes_key, flags);
	EXPECT_EQ(rc, 0);

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

	rc = zpc_aes_key_generate(aes_key);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_key_reencipher(aes_key, ZPC_AES_KEY_REENCIPHER_CURRENT_TO_NEW);
	EXPECT_EQ(rc, 0);

	zpc_aes_key_free(&aes_key);
	EXPECT_EQ(aes_key, nullptr);
}

TEST(aes_key, export)
{
	struct zpc_aes_key *aes_key;
	u8 buf[10000];
	unsigned int flags;
	const char *apqns[257];
	int rc, size, type;
	size_t buflen;
	const char *mkvp;

	TESTLIB_ENV_AES_KEY_CHECK();

	TESTLIB_AES_KERNEL_CAPS_CHECK();

	size = testlib_env_aes_key_size();
	type = testlib_env_aes_key_type();
	flags= testlib_env_aes_key_flags();
	mkvp = testlib_env_aes_key_mkvp();
	(void)testlib_env_aes_key_apqns(apqns);

	rc = zpc_aes_key_export(NULL, NULL, NULL);
	EXPECT_EQ(rc, ZPC_ERROR_ARG1NULL);

	rc = zpc_aes_key_alloc(&aes_key);
	EXPECT_EQ(rc, 0);
	
	rc = zpc_aes_key_export(aes_key, NULL, NULL);
	EXPECT_EQ(rc, ZPC_ERROR_ARG3NULL);
	
	rc = zpc_aes_key_export(aes_key, NULL, &buflen);
	EXPECT_EQ(rc, ZPC_ERROR_KEYNOTSET);

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
	rc = zpc_aes_key_set_size(aes_key, size);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_key_generate(aes_key);
	EXPECT_EQ(rc, 0);

	buflen = 0;
	rc = zpc_aes_key_export(aes_key, buf, &buflen);
	EXPECT_EQ(rc, ZPC_ERROR_SMALLOUTBUF);

	rc = zpc_aes_key_export(aes_key, NULL, &buflen);
	EXPECT_EQ(rc, 0);
	EXPECT_GT(buflen, 0UL);

	rc = zpc_aes_key_export(aes_key, buf, &buflen);
	EXPECT_EQ(rc, 0);

	zpc_aes_key_free(&aes_key);
	EXPECT_EQ(aes_key, nullptr);
}

TEST(aes_key, import)
{
	struct zpc_aes_key *aes_key, *aes_key2;
	u8 buf[10000], buf2[10000];
	unsigned int flags;
	const char *apqns[257];
	int rc, size, type;
	size_t buflen = sizeof(buf);
	size_t buf2len = sizeof(buf2);
	const char *mkvp;

	TESTLIB_ENV_AES_KEY_CHECK();
	size = testlib_env_aes_key_size();
	type = testlib_env_aes_key_type();
	flags= testlib_env_aes_key_flags();
	mkvp = testlib_env_aes_key_mkvp();
	(void)testlib_env_aes_key_apqns(apqns);

	rc = zpc_aes_key_alloc(&aes_key);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_key_alloc(&aes_key2);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_key_import(NULL, NULL, 0);
	EXPECT_EQ(rc, ZPC_ERROR_ARG1NULL);

	rc = zpc_aes_key_import(aes_key, NULL, 0);
	EXPECT_EQ(rc, ZPC_ERROR_ARG2NULL);

	rc = zpc_aes_key_import(aes_key, buf, 63);
	EXPECT_EQ(rc, ZPC_ERROR_ARG3RANGE);
	rc = zpc_aes_key_import(aes_key, buf, 630);
	EXPECT_EQ(rc, ZPC_ERROR_ARG3RANGE);
	
	rc = zpc_aes_key_set_size(aes_key, size);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_key_set_size(aes_key2, size);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_key_import(aes_key, buf, 64);
	EXPECT_EQ(rc, ZPC_ERROR_KEYTYPENOTSET);

	rc = zpc_aes_key_set_type(aes_key, type);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_key_set_type(aes_key2, type);
	EXPECT_EQ(rc, 0);

	if (mkvp != NULL) {
		rc = zpc_aes_key_set_mkvp(aes_key, mkvp);
		EXPECT_EQ(rc, 0);
		rc = zpc_aes_key_set_mkvp(aes_key2, mkvp);
		EXPECT_EQ(rc, 0);
	} else {
		rc = zpc_aes_key_set_apqns(aes_key, apqns);
		EXPECT_EQ(rc, 0);
		rc = zpc_aes_key_set_apqns(aes_key2, apqns);
		EXPECT_EQ(rc, 0);
	}

	rc = zpc_aes_key_set_flags(aes_key, flags);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_key_generate(aes_key);
	EXPECT_EQ(rc, 0);
	
	rc = zpc_aes_key_export(aes_key, buf, &buflen);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_key_import(aes_key2, buf, buflen);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_key_export(aes_key2, buf2, &buf2len);
	EXPECT_EQ(rc, 0);

	EXPECT_EQ(buf2len, buflen);
	EXPECT_TRUE(memcmp(buf2, buf, buflen) == 0);

	zpc_aes_key_free(&aes_key);
	EXPECT_EQ(aes_key, nullptr);
	zpc_aes_key_free(&aes_key2);
	EXPECT_EQ(aes_key2, nullptr);
}
