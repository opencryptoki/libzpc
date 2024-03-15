/*
 * Copyright IBM Corp. 2021
 *
 * libzpc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "testlib.h"

#include "gtest/gtest.h"
#include "zpc/aes_gcm.h"
#include "zpc/error.h"

#include "aes_key_local.h"  /* de-opaquify struct zpc_aes_key */
#include "aes_gcm_local.h"  /* de-opaquify struct zpc_aes_gcm */

#include <json-c/json.h>
#include <stdio.h>
#include <thread>
#include <unistd.h>

static void __run_json(const char *json);

TEST(aes_gcm, alloc)
{
	struct zpc_aes_gcm *aes_gcm;
	int rc;

	TESTLIB_ENV_AES_KEY_CHECK();

	TESTLIB_AES_GCM_HW_CAPS_CHECK();

	rc = zpc_aes_gcm_alloc(NULL);
	EXPECT_EQ(rc, ZPC_ERROR_ARG1NULL);

	aes_gcm = NULL;
	rc = zpc_aes_gcm_alloc(&aes_gcm);
	EXPECT_EQ(rc, 0);
	zpc_aes_gcm_free(&aes_gcm);
	EXPECT_EQ(aes_gcm, nullptr);

	aes_gcm = (struct zpc_aes_gcm *)&aes_gcm;
	rc = zpc_aes_gcm_alloc(&aes_gcm);
	EXPECT_EQ(rc, 0);
	zpc_aes_gcm_free(&aes_gcm);
	EXPECT_EQ(aes_gcm, nullptr);
}

TEST(aes_gcm, free)
{
	struct zpc_aes_gcm *aes_gcm;
	int rc;

	TESTLIB_ENV_AES_KEY_CHECK();

	TESTLIB_AES_GCM_HW_CAPS_CHECK();

	zpc_aes_gcm_free(NULL);

	aes_gcm = NULL;
	zpc_aes_gcm_free(&aes_gcm);
	EXPECT_EQ(aes_gcm, nullptr);

	rc = zpc_aes_gcm_alloc(&aes_gcm);
	EXPECT_EQ(rc, 0);
	zpc_aes_gcm_free(&aes_gcm);
	EXPECT_EQ(aes_gcm, nullptr);
}

TEST(aes_gcm, set_key)
{
	struct zpc_aes_key *aes_key;
	struct zpc_aes_gcm *aes_gcm;
	u8 clearkey[32], iv[12];
	unsigned int flags = 0;
	const char *mkvp, *apqns[257];
	int rc, size, type;

	TESTLIB_ENV_AES_KEY_CHECK();

	TESTLIB_AES_GCM_HW_CAPS_CHECK();

	TESTLIB_AES_KERNEL_CAPS_CHECK();

	size = testlib_env_aes_key_size();
	type = testlib_env_aes_key_type();
	flags = testlib_env_aes_key_flags();
	mkvp = testlib_env_aes_key_mkvp();
	(void)testlib_env_aes_key_apqns(apqns);

	TESTLIB_AES_SW_CAPS_CHECK(type);

	TESTLIB_APQN_CAPS_CHECK(apqns, mkvp, type, size, flags);

	rc = zpc_aes_key_alloc(&aes_key);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_gcm_alloc(&aes_gcm);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_gcm_set_key(aes_gcm, aes_key);
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

	rc = zpc_aes_gcm_set_key(NULL, NULL);
	EXPECT_EQ(rc, ZPC_ERROR_ARG1NULL);
	rc = zpc_aes_gcm_set_key(NULL, aes_key);
	EXPECT_EQ(rc, ZPC_ERROR_ARG1NULL);

	rc = zpc_aes_gcm_set_key(aes_gcm, NULL);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_gcm_set_iv(aes_gcm, iv, 12);
	EXPECT_EQ(rc, ZPC_ERROR_KEYNOTSET);
	rc = zpc_aes_gcm_set_key(aes_gcm, aes_key);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_gcm_set_iv(aes_gcm, iv, 12);
	EXPECT_EQ(rc, 0);

	zpc_aes_gcm_free(&aes_gcm);
	EXPECT_EQ(aes_gcm, nullptr);
	zpc_aes_key_free(&aes_key);
	EXPECT_EQ(aes_key, nullptr);
}

TEST(aes_gcm, set_iv)
{
	struct zpc_aes_key *aes_key;
	struct zpc_aes_gcm *aes_gcm;
	const char *mkvp, *apqns[257];
	u8 iv[16];
	int rc, size, type;
	unsigned int flags;

	TESTLIB_ENV_AES_KEY_CHECK();

	TESTLIB_AES_GCM_HW_CAPS_CHECK();

	TESTLIB_AES_KERNEL_CAPS_CHECK();

	size = testlib_env_aes_key_size();
	type = testlib_env_aes_key_type();
	flags = testlib_env_aes_key_flags();
	mkvp = testlib_env_aes_key_mkvp();
	(void)testlib_env_aes_key_apqns(apqns);

	TESTLIB_AES_SW_CAPS_CHECK(type);

	TESTLIB_APQN_CAPS_CHECK(apqns, mkvp, type, size, flags);

	rc = zpc_aes_key_alloc(&aes_key);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_gcm_alloc(&aes_gcm);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_gcm_set_iv(NULL, NULL, 0);
	EXPECT_EQ(rc, ZPC_ERROR_ARG1NULL);
	rc = zpc_aes_gcm_set_iv(NULL, iv, 12);
	EXPECT_EQ(rc, ZPC_ERROR_ARG1NULL);

	rc = zpc_aes_gcm_set_iv(aes_gcm, NULL, 0);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_gcm_set_iv(aes_gcm, iv, 12);
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

	rc = zpc_aes_gcm_set_iv(aes_gcm, iv, 12);
	EXPECT_EQ(rc, ZPC_ERROR_KEYNOTSET);

	rc = zpc_aes_gcm_set_key(aes_gcm, aes_key);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_gcm_set_iv(aes_gcm, iv, 0);
	EXPECT_EQ(rc, ZPC_ERROR_IVSIZE);
	rc = zpc_aes_gcm_set_iv(aes_gcm, iv, SIZE_MAX);
	EXPECT_EQ(rc, ZPC_ERROR_IVSIZE);
	rc = zpc_aes_gcm_set_iv(aes_gcm, iv, 12);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_gcm_set_iv(aes_gcm, iv, 16);
	EXPECT_EQ(rc, 0);

	zpc_aes_gcm_free(&aes_gcm);
	EXPECT_EQ(aes_gcm, nullptr);
	zpc_aes_key_free(&aes_key);
	EXPECT_EQ(aes_key, nullptr);
}

TEST(aes_gcm, create_iv)
{
	struct zpc_aes_key *aes_key;
	struct zpc_aes_gcm *aes_gcm1, *aes_gcm2;
	const char *mkvp, *apqns[257];
	u8 aad[99], m[99], tag[16], tmp_tag[16], buf[99], pt[99];
	u8 iv_buf[4096];
	int rc, size, type;
	unsigned int flags;

	TESTLIB_ENV_AES_KEY_CHECK();

	TESTLIB_AES_GCM_HW_CAPS_CHECK();

	TESTLIB_AES_KERNEL_CAPS_CHECK();

	size = testlib_env_aes_key_size();
	type = testlib_env_aes_key_type();
	flags = testlib_env_aes_key_flags();
	mkvp = testlib_env_aes_key_mkvp();
	(void)testlib_env_aes_key_apqns(apqns);

	TESTLIB_AES_SW_CAPS_CHECK(type);

	TESTLIB_APQN_CAPS_CHECK(apqns, mkvp, type, size, flags);

	rc = zpc_aes_key_alloc(&aes_key);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_gcm_alloc(&aes_gcm1);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_gcm_alloc(&aes_gcm2);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_gcm_create_iv(aes_gcm1, iv_buf, 0);
	EXPECT_EQ(rc, ZPC_ERROR_IVSIZE);
	rc = zpc_aes_gcm_create_iv(aes_gcm1, iv_buf, 1234);
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
	rc = zpc_aes_gcm_set_key(aes_gcm1, aes_key);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_gcm_set_key(aes_gcm2, aes_key);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_gcm_create_iv(aes_gcm1, iv_buf, SIZE_MAX);
	EXPECT_EQ(rc, ZPC_ERROR_IVSIZE);
	rc = zpc_aes_gcm_create_iv(aes_gcm1, iv_buf, 11);
	EXPECT_EQ(rc, ZPC_ERROR_IVSIZE);
	rc = zpc_aes_gcm_create_iv(aes_gcm1, iv_buf, 12);
	EXPECT_EQ(rc, 0);

	/* Create internal iv for encrypt/decrypt */
	rc = zpc_aes_gcm_create_iv(aes_gcm1, iv_buf, 1234);
	EXPECT_EQ(rc, 0);

	/* Encrypt in-place with internally created iv */
	rc = zpc_aes_gcm_encrypt(aes_gcm1, buf, tag, sizeof(tag), aad, sizeof(aad), m, sizeof(m));
	EXPECT_EQ(rc, 0);

	/*
	 * Try to use set_iv on first ctx with already created internal iv. This
	 * fails because it is not allowed to overwrite an internal iv.
	 */
	rc = zpc_aes_gcm_set_iv(aes_gcm1, iv_buf, 78);
	EXPECT_EQ(rc, ZPC_ERROR_GCM_IV_CREATED_INTERNALLY);

	/*
	 * Try to use same ctx for decrypt: this fails, because the initial iv
	 * is not available because set_iv is not allowed on this ctx after
	 * creating an internal iv.
	 */
	memcpy(tmp_tag, tag, sizeof(tag));
	rc = zpc_aes_gcm_decrypt(aes_gcm1, pt, tmp_tag, sizeof(tmp_tag), aad, sizeof(aad), buf, sizeof(buf));
	EXPECT_EQ(rc, ZPC_ERROR_GCM_IV_CREATED_INTERNALLY);

	/* Decrypt in-place with internally created iv and 2nd ctx */
	rc = zpc_aes_gcm_set_iv(aes_gcm2, iv_buf, 1234);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_gcm_decrypt(aes_gcm2, pt, tag, sizeof(tag), aad, sizeof(aad), buf, sizeof(buf));
	EXPECT_EQ(rc, 0);
	EXPECT_TRUE(memcmp(pt, m, sizeof(m)) == 0);

	zpc_aes_gcm_free(&aes_gcm1);
	EXPECT_EQ(aes_gcm1, nullptr);
	zpc_aes_gcm_free(&aes_gcm2);
	EXPECT_EQ(aes_gcm2, nullptr);
	zpc_aes_key_free(&aes_key);
	EXPECT_EQ(aes_key, nullptr);
}

TEST(aes_gcm, encrypt)
{
	struct zpc_aes_key *aes_key;
	struct zpc_aes_gcm *aes_gcm;
	const char *mkvp, *apqns[257];
	u8 iv[12], aad[99], m[99], tag[12], c[99];
	unsigned int flags;
	int rc, size, type;

	TESTLIB_ENV_AES_KEY_CHECK();

	TESTLIB_AES_GCM_HW_CAPS_CHECK();

	TESTLIB_AES_KERNEL_CAPS_CHECK();

	size = testlib_env_aes_key_size();
	type = testlib_env_aes_key_type();
	flags = testlib_env_aes_key_flags();
	mkvp = testlib_env_aes_key_mkvp();
	(void)testlib_env_aes_key_apqns(apqns);

	TESTLIB_AES_SW_CAPS_CHECK(type);

	TESTLIB_APQN_CAPS_CHECK(apqns, mkvp, type, size, flags);

	rc = zpc_aes_key_alloc(&aes_key);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_gcm_alloc(&aes_gcm);
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

	rc = zpc_aes_gcm_set_key(aes_gcm, aes_key);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_gcm_set_iv(aes_gcm, iv, 12);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_gcm_encrypt(aes_gcm, c, tag, 12, aad, 99, m, 99);
	EXPECT_EQ(rc, 0);

	zpc_aes_gcm_free(&aes_gcm);
	EXPECT_EQ(aes_gcm, nullptr);
	zpc_aes_key_free(&aes_key);
	EXPECT_EQ(aes_key, nullptr);
}

TEST(aes_gcm, decrypt)
{
	struct zpc_aes_key *aes_key;
	struct zpc_aes_gcm *aes_gcm;
	const char *mkvp, *apqns[257];
	u8 iv[12], aad[99], m[99], tag[12], c[99];
	unsigned int flags;
	int rc, size, type;

	TESTLIB_ENV_AES_KEY_CHECK();

	TESTLIB_AES_GCM_HW_CAPS_CHECK();

	TESTLIB_AES_KERNEL_CAPS_CHECK();

	size = testlib_env_aes_key_size();
	type = testlib_env_aes_key_type();
	flags = testlib_env_aes_key_flags();
	mkvp = testlib_env_aes_key_mkvp();
	(void)testlib_env_aes_key_apqns(apqns);

	TESTLIB_AES_SW_CAPS_CHECK(type);

	TESTLIB_APQN_CAPS_CHECK(apqns, mkvp, type, size, flags);

	rc = zpc_aes_key_alloc(&aes_key);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_gcm_alloc(&aes_gcm);
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
	rc = zpc_aes_gcm_set_key(aes_gcm, aes_key);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_gcm_set_iv(aes_gcm, iv, 12);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_gcm_decrypt(aes_gcm, m, tag, 12, aad, 99, c, 99);
	EXPECT_EQ(rc, ZPC_ERROR_TAGMISMATCH);

	zpc_aes_gcm_free(&aes_gcm);
	EXPECT_EQ(aes_gcm, nullptr);
	zpc_aes_key_free(&aes_key);
	EXPECT_EQ(aes_key, nullptr);
}

TEST(aes_gcm, pc)
{
	struct zpc_aes_key *aes_key1, *aes_key2;
	struct zpc_aes_gcm *aes_gcm1, *aes_gcm2;
	const char *mkvp, *apqns[257];
	u8 iv[12], aad[99], m[99], tag[12], c[99], key[32], m_bak[99];
	unsigned int flags;
	int rc, size, type;

	TESTLIB_ENV_AES_KEY_CHECK();

	TESTLIB_AES_GCM_HW_CAPS_CHECK();

	TESTLIB_AES_KERNEL_CAPS_CHECK();

	size = testlib_env_aes_key_size();
	type = testlib_env_aes_key_type();
	flags = testlib_env_aes_key_flags();
	mkvp = testlib_env_aes_key_mkvp();
	(void)testlib_env_aes_key_apqns(apqns);

	TESTLIB_AES_SW_CAPS_CHECK(type);

	TESTLIB_APQN_CAPS_CHECK(apqns, mkvp, type, size, flags);

	memcpy(m_bak, m, 99);

	rc = zpc_aes_key_alloc(&aes_key1);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_key_alloc(&aes_key2);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_gcm_alloc(&aes_gcm1);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_gcm_alloc(&aes_gcm2);
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
	rc = zpc_aes_gcm_set_key(aes_gcm1, aes_key1);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_gcm_set_iv(aes_gcm1, iv, 12);
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
	rc = zpc_aes_gcm_set_key(aes_gcm2, aes_key2);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_gcm_set_iv(aes_gcm2, iv, 12);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_gcm_encrypt(aes_gcm1, c, tag, 12, aad, 99, m, 99);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_gcm_decrypt(aes_gcm2, m, tag, 12, aad, 99, c, 99);
	EXPECT_EQ(rc, 0);
	EXPECT_TRUE(memcmp(m, m_bak, 99) == 0);
	rc = zpc_aes_gcm_encrypt(aes_gcm2, c, tag, 12, aad, 99, m, 99);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_gcm_decrypt(aes_gcm1, m, tag, 12, aad, 99, c, 99);
	EXPECT_EQ(rc, 0);
	EXPECT_TRUE(memcmp(m, m_bak, 99) == 0);

	rc = zpc_aes_gcm_encrypt(aes_gcm2, c, tag, 12, aad, 99, m, 99);
	EXPECT_EQ(rc, 0);
	c[0] ^= 1;
	rc = zpc_aes_gcm_decrypt(aes_gcm1, m, tag, 12, aad, 99, c, 99);
	EXPECT_EQ(rc, ZPC_ERROR_TAGMISMATCH);
	rc = zpc_aes_gcm_encrypt(aes_gcm1, c, tag, 12, aad, 99, m, 99);
	EXPECT_EQ(rc, 0);
	tag[0] ^= 1;
	rc = zpc_aes_gcm_decrypt(aes_gcm2, m, tag, 12, aad, 99, c, 99);
	EXPECT_EQ(rc, ZPC_ERROR_TAGMISMATCH);

	memcpy(m_bak, m, 99);

	/* Random protected key */
	rc = zpc_aes_gcm_set_key(aes_gcm1, NULL);   /* Unset key. */
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_gcm_set_key(aes_gcm2, NULL);   /* Unset key. */
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_key_set_mkvp(aes_key1, NULL);   /* Unset apqns. */
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_key_set_size(aes_key1, size);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_key_generate(aes_key1);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_gcm_set_key(aes_gcm1, aes_key1);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_gcm_set_iv(aes_gcm1, iv, 12);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_gcm_set_key(aes_gcm2, aes_key1);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_gcm_set_iv(aes_gcm2, iv, 12);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_gcm_encrypt(aes_gcm1, c, tag, 12, aad, 99, m, 99);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_gcm_decrypt(aes_gcm2, m, tag, 12, aad, 99, c, 99);
	EXPECT_EQ(rc, 0);
	EXPECT_TRUE(memcmp(m, m_bak, 99) == 0);
	rc = zpc_aes_gcm_encrypt(aes_gcm2, c, tag, 12, aad, 99, m, 99);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_gcm_decrypt(aes_gcm1, m, tag, 12, aad, 99, c, 99);
	EXPECT_EQ(rc, 0);
	EXPECT_TRUE(memcmp(m, m_bak, 99) == 0);

	rc = zpc_aes_gcm_encrypt(aes_gcm2, c, tag, 12, aad, 99, m, 99);
	EXPECT_EQ(rc, 0);
	c[0] ^= 1;
	rc = zpc_aes_gcm_decrypt(aes_gcm1, m, tag, 12, aad, 99, c, 99);
	EXPECT_EQ(rc, ZPC_ERROR_TAGMISMATCH);
	rc = zpc_aes_gcm_encrypt(aes_gcm1, c, tag, 12, aad, 99, m, 99);
	EXPECT_EQ(rc, 0);
	tag[0] ^= 1;
	rc = zpc_aes_gcm_decrypt(aes_gcm2, m, tag, 12, aad, 99, c, 99);
	EXPECT_EQ(rc, ZPC_ERROR_TAGMISMATCH);

	zpc_aes_gcm_free(&aes_gcm2);
	zpc_aes_gcm_free(&aes_gcm1);
	zpc_aes_key_free(&aes_key2);
	EXPECT_EQ(aes_key2, nullptr);
	zpc_aes_key_free(&aes_key1);
	EXPECT_EQ(aes_key1, nullptr);
}

TEST(aes_gcm, stream_inplace_kat1)
{
	TESTLIB_ENV_AES_KEY_CHECK();

	TESTLIB_AES_GCM_HW_CAPS_CHECK();

	TESTLIB_AES_KERNEL_CAPS_CHECK();

	size_t keylen, ivlen, msglen, ctlen, taglen, aadlen;
	unsigned char buf[4096], mac[16];
	const char *mkvp, *apqns[257];
	struct zpc_aes_key *aes_key;
	struct zpc_aes_gcm *aes_gcm;
	unsigned int flags;
	int type, rc;

	const char *keystr = "c4b03435b91fc52e09eff27e4dc3fb42";
	const char *ivstr = "5046e7e08f0747e1efccb09e";
	const char *aadstr = "75fc9078b488e9503dcb568c882c9eec24d80b04f0958c82aac8484f025c90434148db8e9bfe29c7e071b797457cb1695a5e5a6317b83690ba0538fb11e325ca";
	const char *msgstr = "8e887b224e8b89c82e9a641cf579e6879e1111c7";
	const char *ctstr = "b6786812574a254eb43b1cb1d1753564c6b520e9";
	const char *tagstr = "ad8c09610d508f3d0f03cc523c0d5fcc";

	type = testlib_env_aes_key_type();
	flags = testlib_env_aes_key_flags();
	mkvp = testlib_env_aes_key_mkvp();
	(void)testlib_env_aes_key_apqns(apqns);

	TESTLIB_AES_SW_CAPS_CHECK(type);

	TESTLIB_APQN_CAPS_CHECK(apqns, mkvp, type, 256, flags);

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

	rc = zpc_aes_key_alloc(&aes_key);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_gcm_alloc(&aes_gcm);
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

	rc = zpc_aes_gcm_set_key(aes_gcm, aes_key);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_gcm_set_iv(aes_gcm, iv, ivlen);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_gcm_encrypt(aes_gcm, NULL, NULL, 0, aad, 32, NULL, 0);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_gcm_encrypt(aes_gcm, NULL, NULL, 0, aad + 32, aadlen - 31, NULL, 0);   /* Works iff aadlen - 32 == 0 mod 16 */
	EXPECT_EQ(rc, ZPC_ERROR_ARG6RANGE);
	rc = zpc_aes_gcm_encrypt(aes_gcm, NULL, NULL, 0, aad + 32, aadlen - 32, NULL, 0);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_gcm_encrypt(aes_gcm, buf, NULL, 0, NULL, 0, buf, 16);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_gcm_encrypt(aes_gcm, buf + 16, mac, taglen, NULL, 0, buf + 16, msglen - 16);
	EXPECT_EQ(rc, 0);

	EXPECT_TRUE(memcmp(buf, ct, ctlen) == 0);
	EXPECT_TRUE(memcmp(mac, tag, taglen) == 0);

	/* Encrypt */
	memcpy(buf, msg, msglen);

	rc = zpc_aes_gcm_set_key(aes_gcm, aes_key);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_gcm_set_iv(aes_gcm, iv, ivlen);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_gcm_encrypt(aes_gcm, NULL, NULL, 0, aad, 32, NULL, 0);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_gcm_encrypt(aes_gcm, buf, NULL, 0, aad + 32, aadlen - 32, buf, 16);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_gcm_encrypt(aes_gcm, buf + 16, NULL, 0, NULL, 0, buf + 16, msglen - 16);   /* Works iff msglen - 16 == 0 mod 16 */
	EXPECT_EQ(rc, ZPC_ERROR_ARG8RANGE);
	rc = zpc_aes_gcm_encrypt(aes_gcm, buf + 16, mac, taglen, NULL, 0, buf + 16, msglen - 16);
	EXPECT_EQ(rc, 0);

	EXPECT_TRUE(memcmp(buf, ct, ctlen) == 0);
	EXPECT_TRUE(memcmp(mac, tag, taglen) == 0);

	/* Decrypt */
	memcpy(buf, ct, ctlen);

	rc = zpc_aes_gcm_set_iv(aes_gcm, iv, ivlen);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_gcm_decrypt(aes_gcm, NULL, NULL, 0, aad, 16, NULL, 0);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_gcm_decrypt(aes_gcm, NULL, NULL, 0, aad + 16, aadlen - 15, NULL, 0);    /* Works iff aadlen - 16 == 0 mod 16 */
	EXPECT_EQ(rc, ZPC_ERROR_ARG6RANGE);
	rc = zpc_aes_gcm_decrypt(aes_gcm, buf, NULL, 0, aad + 16, aadlen - 16, buf, 16);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_gcm_decrypt(aes_gcm, buf + 16, tag, taglen, NULL, 0, buf + 16, msglen - 16);
	EXPECT_EQ(rc, 0);

	EXPECT_TRUE(memcmp(buf, msg, msglen) == 0);

	/* Decrypt */
	memcpy(buf, ct, ctlen);

	rc = zpc_aes_gcm_set_iv(aes_gcm, iv, ivlen);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_gcm_decrypt(aes_gcm, NULL, NULL, 0, aad, 16, NULL, 0);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_gcm_decrypt(aes_gcm, NULL, NULL, 0, aad + 16, aadlen - 16, NULL, 0);    /* Works iff aadlen - 16 == 0 mod 16 */
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_gcm_decrypt(aes_gcm, buf, NULL, 0, NULL, 0, buf, 16);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_gcm_decrypt(aes_gcm, buf + 16, NULL, 0, NULL, 0, buf + 16, msglen - 16);   /* Works iff msglen - 16 == 0 mod 16 */
	EXPECT_EQ(rc, ZPC_ERROR_ARG8RANGE);
	rc = zpc_aes_gcm_decrypt(aes_gcm, buf + 16, tag, taglen, NULL, 0, buf + 16, msglen - 16);
	EXPECT_EQ(rc, 0);

	EXPECT_TRUE(memcmp(buf, msg, msglen) == 0);

	zpc_aes_gcm_free(&aes_gcm);
	EXPECT_EQ(aes_gcm, nullptr);
	zpc_aes_key_free(&aes_key);
	EXPECT_EQ(aes_key, nullptr);

	free(key);
	free(iv);
	free(aad);
	free(msg);
	free(ct);
	free(tag);
}

TEST(aes_gcm, stream_inplace_kat2)
{
	TESTLIB_ENV_AES_KEY_CHECK();

	TESTLIB_AES_GCM_HW_CAPS_CHECK();

	TESTLIB_AES_KERNEL_CAPS_CHECK();

	size_t keylen, ivlen, msglen, ctlen, taglen, aadlen;
	unsigned char buf[4096], mac[16];
	const char *mkvp, *apqns[257];
	struct zpc_aes_key *aes_key;
	struct zpc_aes_gcm *aes_gcm;
	unsigned int flags;
	int type, rc;

	const char *keystr = "deb62233559b57476602b5adac57c77f";
	const char *ivstr = "d084547de55bbc15";
	const char *aadstr = "";
	const char *msgstr = "d8986df0241ed3297582c0c239c724cb";
	const char *ctstr = "03e1a168a7e377a913879b296a1b5f9c";
	const char *tagstr = "3290aa95af505a742f517fabcc9b2094";

	type = testlib_env_aes_key_type();
	flags = testlib_env_aes_key_flags();
	mkvp = testlib_env_aes_key_mkvp();
	(void)testlib_env_aes_key_apqns(apqns);

	TESTLIB_AES_SW_CAPS_CHECK(type);

	TESTLIB_APQN_CAPS_CHECK(apqns, mkvp, type, 256, flags);

	u8 *key = testlib_hexstr2buf(keystr, &keylen);
	ASSERT_NE(key, nullptr);
	u8 *iv = testlib_hexstr2buf(ivstr, &ivlen);
	ASSERT_NE(iv, nullptr);
	u8 *aad = testlib_hexstr2buf(aadstr, &aadlen);
	ASSERT_EQ(aad, nullptr);
	u8 *msg = testlib_hexstr2buf(msgstr, &msglen);
	ASSERT_NE(msg, nullptr);
	u8 *ct = testlib_hexstr2buf(ctstr, &ctlen);
	ASSERT_NE(ct, nullptr);
	u8 *tag = testlib_hexstr2buf(tagstr, &taglen);
	ASSERT_NE(tag, nullptr);

	rc = zpc_aes_key_alloc(&aes_key);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_gcm_alloc(&aes_gcm);
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

	rc = zpc_aes_gcm_set_key(aes_gcm, aes_key);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_gcm_set_iv(aes_gcm, iv, ivlen);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_gcm_encrypt(aes_gcm, NULL, NULL, 0, aad, aadlen, NULL, 0); /* Works iff aadlen == 0 mod 16 */
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_gcm_encrypt(aes_gcm, buf, NULL, 0, NULL, 0, buf, msglen);  /* Works iff msglen == 0 mod 16 */
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_gcm_encrypt(aes_gcm, NULL, mac, taglen, NULL, 0, NULL, 0);
	EXPECT_EQ(rc, 0);

	EXPECT_TRUE(memcmp(buf, ct, ctlen) == 0);
	EXPECT_TRUE(memcmp(mac, tag, taglen) == 0);

	/* Decrypt */
	memcpy(buf, ct, ctlen);

	rc = zpc_aes_gcm_set_iv(aes_gcm, iv, ivlen);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_gcm_decrypt(aes_gcm, NULL, NULL, 0, aad, aadlen, NULL, 0); /* Works iff aadlen == 0 mod 16 */
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_gcm_decrypt(aes_gcm, buf, NULL, 0, NULL, 0, buf, msglen);  /* Works iff msglen == 0 mod 16 */
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_gcm_decrypt(aes_gcm, NULL, tag, taglen, NULL, 0, NULL, 0);
	EXPECT_EQ(rc, 0);

	EXPECT_TRUE(memcmp(buf, msg, msglen) == 0);

	zpc_aes_gcm_free(&aes_gcm);
	EXPECT_EQ(aes_gcm, nullptr);
	zpc_aes_key_free(&aes_key);
	EXPECT_EQ(aes_key, nullptr);

	free(key);
	free(iv);
	free(aad);
	free(msg);
	free(ct);
	free(tag);
}

TEST(aes_gcm, wycheproof_kat)
{
	TESTLIB_ENV_AES_KEY_CHECK();

	TESTLIB_AES_GCM_HW_CAPS_CHECK();

	TESTLIB_AES_KERNEL_CAPS_CHECK();

	__run_json("wycheproof/src/wycheproof/testvectors/aes_gcm_test.json");
}

TEST(aes_gcm, nist_kat)
{
	TESTLIB_ENV_AES_KEY_CHECK();

	TESTLIB_AES_GCM_HW_CAPS_CHECK();

	TESTLIB_AES_KERNEL_CAPS_CHECK();

	__run_json("nist_aes_gcm.json");
}

static void __run_json(const char *json)
{
	const char *tv = json, *str;
	const char *mkvp, *apqns[257];
	struct zpc_aes_key *aes_key;
	struct zpc_aes_gcm *aes_gcm;
	unsigned int flags;
	u8 *key = NULL, *iv = NULL, *aad = NULL;
	u8 *pt = NULL, *pt_out = NULL, *ct = NULL, *ct_out = NULL;
	u8 *tag = NULL, *tag_out = NULL;
	int rc, tagsize = 0, ivsize = 0, keysize = 0;
	int valid = 0, ivlen0 = 0, deconly = 0;
	size_t aadlen, ptlen, ctlen, taglen, i, j, k, max;
	json_object *jkey, *jiv, *jtag, *jaad, *jmsg, *jct, *jresult, *jflags, *jtmp, *jtestgroups, *jfile, *jkeysize, *jivsize, *jtagsize, *jtests;
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
	rc = zpc_aes_gcm_alloc(&aes_gcm);
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
				if (strcmp(str, "ZeroLengthIv") == 0)
					ivlen0 = 1;
				else
					ivlen0 = 0;
				str = json_object_get_string(jtmp);
				if (strcmp(str, "DecryptOnly") == 0)
					deconly = 1;
				else
					deconly = 0;
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

			rc = zpc_aes_gcm_set_key(aes_gcm, aes_key);
			EXPECT_EQ(rc, 0);
			rc = zpc_aes_gcm_set_iv(aes_gcm, ivlen0 ? (unsigned char *)1 : iv, ivsize / 8);
			EXPECT_EQ(rc, ivlen0 ? ZPC_ERROR_IVSIZE : 0);

			if (!ivlen0 && !deconly) {
				rc = zpc_aes_gcm_encrypt(aes_gcm, ct_out, tag_out, tagsize / 8, aad, aadlen, pt, ptlen);
				EXPECT_EQ(rc, 0);
				EXPECT_TRUE(memcmp(ct_out, ct, ctlen) == 0);
				if (valid) {
					EXPECT_TRUE(memcmp(tag_out, tag, tagsize / 8) == 0);
				}

				rc = zpc_aes_gcm_set_iv(aes_gcm, iv, ivsize / 8);
				EXPECT_EQ(rc, 0);
			} else if (!ivlen0) {
				rc = zpc_aes_gcm_decrypt(aes_gcm, pt_out, tag, tagsize / 8, aad, aadlen, ct, ctlen);
				EXPECT_EQ(rc, valid ? 0 : ZPC_ERROR_TAGMISMATCH);
				EXPECT_TRUE(memcmp(pt_out, pt, ptlen) == 0);
			}

			/* Unset key. */
			rc = zpc_aes_gcm_set_key(aes_gcm, NULL);
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
	zpc_aes_gcm_free(&aes_gcm);
	EXPECT_EQ(aes_gcm, nullptr);
	zpc_aes_key_free(&aes_key);
	EXPECT_EQ(aes_key, nullptr);
}

TEST(aes_gcm, rederive_protected_key1)
{
	struct zpc_aes_key *aes_key1;
	struct zpc_aes_gcm *aes_gcm1, *aes_gcm2, *aes_gcm3;
	u8 iv[16], aad[99], m[99], tag[16], c[99]; /* use ivlen != 12 bytes such that it must be processed by kma */
	int rc, size;

	TESTLIB_ENV_AES_KEY_CHECK();

	TESTLIB_AES_GCM_HW_CAPS_CHECK();

	TESTLIB_AES_KERNEL_CAPS_CHECK();

	size = testlib_env_aes_key_size();

	rc = zpc_aes_key_alloc(&aes_key1);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_gcm_alloc(&aes_gcm1);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_gcm_alloc(&aes_gcm2);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_gcm_alloc(&aes_gcm3);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_gcm_set_key(aes_gcm1, NULL);   /* Unset key. */
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_gcm_set_key(aes_gcm2, NULL);   /* Unset key. */
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_gcm_set_key(aes_gcm3, NULL);   /* Unset key. */
	EXPECT_EQ(rc, 0);

	/* Random protected keys cannot be re-derived. */

	rc = zpc_aes_key_set_mkvp(aes_key1, NULL);   /* Unset apqns. */
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_key_set_size(aes_key1, size);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_key_generate(aes_key1);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_gcm_set_key(aes_gcm1, aes_key1);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_gcm_set_iv(aes_gcm1, iv, sizeof(iv));
	EXPECT_EQ(rc, 0);
	memset(aes_gcm1->param.protkey, 0, sizeof(aes_gcm1->param.protkey)); 
	rc = zpc_aes_gcm_set_iv(aes_gcm1, iv, sizeof(iv));
	EXPECT_EQ(rc, ZPC_ERROR_PROTKEYONLY);

	rc = zpc_aes_gcm_set_key(aes_gcm2, aes_key1);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_gcm_set_iv(aes_gcm2, iv, sizeof(iv));
	EXPECT_EQ(rc, 0);
	memset(aes_gcm2->param.protkey, 0, sizeof(aes_gcm2->param.protkey));
	rc = zpc_aes_gcm_encrypt(aes_gcm2, c, tag, 12, aad, 99, m, 99);
	EXPECT_EQ(rc, ZPC_ERROR_PROTKEYONLY);

	rc = zpc_aes_gcm_set_key(aes_gcm3, aes_key1);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_gcm_set_iv(aes_gcm3, iv, sizeof(iv));
	EXPECT_EQ(rc, 0);
	memset(aes_gcm3->param.protkey, 0, sizeof(aes_gcm3->param.protkey));
	rc = zpc_aes_gcm_decrypt(aes_gcm3, m, tag, 12, aad, 99, c, 99);
	EXPECT_EQ(rc, ZPC_ERROR_PROTKEYONLY);

	rc = zpc_aes_gcm_set_key(aes_gcm1, aes_key1);
	EXPECT_EQ(rc, 0);
	memset(aes_gcm1->param.protkey, 0, sizeof(aes_gcm1->param.protkey));
	rc = zpc_aes_gcm_set_iv(aes_gcm1, iv, sizeof(iv));
	EXPECT_EQ(rc, ZPC_ERROR_PROTKEYONLY);

	zpc_aes_gcm_free(&aes_gcm3);
	zpc_aes_gcm_free(&aes_gcm2);
	zpc_aes_gcm_free(&aes_gcm1);
	zpc_aes_key_free(&aes_key1);
	EXPECT_EQ(aes_gcm3, nullptr);
	EXPECT_EQ(aes_gcm2, nullptr);
	EXPECT_EQ(aes_gcm1, nullptr);
	EXPECT_EQ(aes_key1, nullptr);
}

TEST(aes_gcm, rederive_protected_key2)
{
	TESTLIB_ENV_AES_KEY_CHECK();

	TESTLIB_AES_GCM_HW_CAPS_CHECK();

	TESTLIB_AES_KERNEL_CAPS_CHECK();

	size_t keylen, ivlen, msglen, ctlen, taglen, aadlen;
	unsigned char buf[4096], mac[16];
	const char *mkvp, *apqns[257];
	struct zpc_aes_key *aes_key;
	struct zpc_aes_gcm *aes_gcm;
	unsigned int flags;
	int type, rc;

	const char *keystr = "2034a82547276c83dd3212a813572bce";
	const char *ivstr = "3254202d854734812398127a3d134421"; /* use ivlen != 12 bytes such that it must be processed by kma */
	const char *aadstr = "1a0293d8f90219058902139013908190bc490890d3ff12a3";
	const char *msgstr = "02efd2e5782312827ed5d230189a2a342b277ce048462193";
	const char *ctstr = "64069c2d58690561f27ee199e6b479b6369eec688672bde9";
	const char *tagstr = "9b7abadd6e69c1d9ec925786534f5075";

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

	TESTLIB_AES_SW_CAPS_CHECK(type);

	TESTLIB_APQN_CAPS_CHECK(apqns, mkvp, type, 256, flags);

	rc = zpc_aes_key_alloc(&aes_key);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_gcm_alloc(&aes_gcm);
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

	rc = zpc_aes_gcm_set_key(aes_gcm, aes_key);
	EXPECT_EQ(rc, 0);
	memset(aes_gcm->param.protkey, 0, sizeof(aes_gcm->param.protkey));    /* force WKaVP mismatch */
	rc = zpc_aes_gcm_set_iv(aes_gcm, iv, ivlen);
	EXPECT_EQ(rc, 0);

	memset(aes_gcm->param.protkey, 0, sizeof(aes_gcm->param.protkey));    /* force WKaVP mismatch */
	rc = zpc_aes_gcm_encrypt(aes_gcm, NULL, NULL, 0, aad, 16, NULL, 0);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_gcm_encrypt(aes_gcm, NULL, NULL, 0, aad + 16, aadlen - 15, NULL, 0);   /* Works iff aadlen - 16 == 0 mod 16 */
	EXPECT_EQ(rc, ZPC_ERROR_ARG6RANGE);
	rc = zpc_aes_gcm_encrypt(aes_gcm, buf, NULL, 0, aad + 16, aadlen - 16, buf, 16);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_gcm_encrypt(aes_gcm, buf + 16, mac, taglen, NULL, 0, buf + 16, msglen - 16);
	EXPECT_EQ(rc, 0);

	EXPECT_TRUE(memcmp(buf, ct, ctlen) == 0);
	EXPECT_TRUE(memcmp(mac, tag, taglen) == 0);

	/* Encrypt */
	memcpy(buf, msg, msglen);

	rc = zpc_aes_gcm_set_key(aes_gcm, aes_key);
	EXPECT_EQ(rc, 0);
	memset(aes_gcm->param.protkey, 0, sizeof(aes_gcm->param.protkey));    /* force WKaVP mismatch */
	rc = zpc_aes_gcm_set_iv(aes_gcm, iv, ivlen);
	EXPECT_EQ(rc, 0);

	memset(aes_gcm->param.protkey, 0, sizeof(aes_gcm->param.protkey));    /* force WKaVP mismatch */
	rc = zpc_aes_gcm_encrypt(aes_gcm, NULL, NULL, 0, aad, 16, NULL, 0);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_gcm_encrypt(aes_gcm, buf, NULL, 0, aad + 16, aadlen - 16, buf, 16);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_gcm_encrypt(aes_gcm, buf + 16, NULL, 0, NULL, 0, buf + 16, msglen - 16);   /* Works iff msglen - 16 == 0 mod 16 */
	EXPECT_EQ(rc, ZPC_ERROR_ARG8RANGE);
	memset(aes_gcm->param.protkey, 0, sizeof(aes_gcm->param.protkey));    /* force WKaVP mismatch */
	rc = zpc_aes_gcm_encrypt(aes_gcm, buf + 16, mac, taglen, NULL, 0, buf + 16, msglen - 16);
	EXPECT_EQ(rc, 0);

	EXPECT_TRUE(memcmp(buf, ct, ctlen) == 0);
	EXPECT_TRUE(memcmp(mac, tag, taglen) == 0);

	/* Decrypt */
	memcpy(buf, ct, ctlen);

	memset(aes_gcm->param.protkey, 0, sizeof(aes_gcm->param.protkey));    /* force WKaVP mismatch */
	rc = zpc_aes_gcm_set_iv(aes_gcm, iv, ivlen);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_gcm_decrypt(aes_gcm, NULL, NULL, 0, aad, 16, NULL, 0);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_gcm_decrypt(aes_gcm, NULL, NULL, 0, aad + 16, aadlen - 15, NULL, 0);    /* Works iff aadlen - 16 == 0 mod 16 */
	EXPECT_EQ(rc, ZPC_ERROR_ARG6RANGE);
	memset(aes_gcm->param.protkey, 0, sizeof(aes_gcm->param.protkey));    /* force WKaVP mismatch */
	rc = zpc_aes_gcm_decrypt(aes_gcm, buf, NULL, 0, aad + 16, aadlen - 16, buf, 16);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_gcm_decrypt(aes_gcm, buf + 16, tag, taglen, NULL, 0, buf + 16, msglen - 16);
	EXPECT_EQ(rc, 0);

	EXPECT_TRUE(memcmp(buf, msg, msglen) == 0);

	/* Decrypt */
	memcpy(buf, ct, ctlen);

	memset(aes_gcm->param.protkey, 0, sizeof(aes_gcm->param.protkey));    /* force WKaVP mismatch */
	rc = zpc_aes_gcm_set_iv(aes_gcm, iv, ivlen);
	EXPECT_EQ(rc, 0);

	memset(aes_gcm->param.protkey, 0, sizeof(aes_gcm->param.protkey));    /* force WKaVP mismatch */
	rc = zpc_aes_gcm_decrypt(aes_gcm, NULL, NULL, 0, aad, 16, NULL, 0);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_gcm_decrypt(aes_gcm, buf, NULL, 0, aad + 16, aadlen - 16, buf, 16);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_gcm_decrypt(aes_gcm, buf + 16, NULL, 0, NULL, 0, buf + 16, msglen - 16);   /* Works iff msglen - 16 == 0 mod 16 */
	EXPECT_EQ(rc, ZPC_ERROR_ARG8RANGE);
	rc = zpc_aes_gcm_decrypt(aes_gcm, buf + 16, tag, taglen, NULL, 0, buf + 16, msglen - 16);
	EXPECT_EQ(rc, 0);

	EXPECT_TRUE(memcmp(buf, msg, msglen) == 0);

	zpc_aes_gcm_free(&aes_gcm);
	EXPECT_EQ(aes_gcm, nullptr);
	zpc_aes_key_free(&aes_key);
	EXPECT_EQ(aes_key, nullptr);

	free(key);
	free(iv);
	free(aad);
	free(msg);
	free(ct);
	free(tag);
}

TEST(aes_gcm, reencipher)
{
	TESTLIB_ENV_AES_KEY_CHECK();

	TESTLIB_AES_GCM_HW_CAPS_CHECK();

	TESTLIB_AES_KERNEL_CAPS_CHECK();

	size_t keylen, ivlen, msglen, ctlen, taglen, aadlen;
	unsigned char buf[4096], mac[16];
	const char *mkvp, *apqns[257];
	struct zpc_aes_key *aes_key;
	struct zpc_aes_gcm *aes_gcm;
	unsigned int flags;
	int type, rc;

	const char *keystr = "2034a82547276c83dd3212a813572bce";
	const char *ivstr = "3254202d854734812398127a3d134421"; /* use ivlen != 12 bytes such that it must be processed by kma */
	const char *aadstr = "1a0293d8f90219058902139013908190bc490890d3ff12a3";
	const char *msgstr = "02efd2e5782312827ed5d230189a2a342b277ce048462193";
	const char *ctstr = "64069c2d58690561f27ee199e6b479b6369eec688672bde9";
	const char *tagstr = "9b7abadd6e69c1d9ec925786534f5075";

	type = testlib_env_aes_key_type();
	flags = testlib_env_aes_key_flags();
	mkvp = testlib_env_aes_key_mkvp();
	(void)testlib_env_aes_key_apqns(apqns);

	TESTLIB_AES_SW_CAPS_CHECK(type);

	TESTLIB_APQN_CAPS_CHECK(apqns, mkvp, type, 256, flags);

	TESTLIB_AES_NEW_MK_CHECK(type, mkvp, apqns);

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

	rc = zpc_aes_key_alloc(&aes_key);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_gcm_alloc(&aes_gcm);
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

	rc = zpc_aes_gcm_set_key(aes_gcm, aes_key);
	EXPECT_EQ(rc, 0);
	memset(&aes_key->prot, 0, sizeof(aes_key->prot));    /* destroy cached protected key */
	memset(aes_gcm->param.protkey, 0, sizeof(aes_gcm->param.protkey));    /* force WKaVP mismatch */
	rc = zpc_aes_gcm_set_iv(aes_gcm, iv, ivlen);
	EXPECT_EQ(rc, 0);

	memset(&aes_key->prot, 0, sizeof(aes_key->prot));    /* destroy cached protected key */
	memset(aes_gcm->param.protkey, 0, sizeof(aes_gcm->param.protkey));    /* force WKaVP mismatch */
	rc = zpc_aes_gcm_encrypt(aes_gcm, NULL, NULL, 0, aad, 16, NULL, 0);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_gcm_encrypt(aes_gcm, NULL, NULL, 0, aad + 16, aadlen - 15, NULL, 0);   /* Works iff aadlen - 16 == 0 mod 16 */
	EXPECT_EQ(rc, ZPC_ERROR_ARG6RANGE);
	rc = zpc_aes_gcm_encrypt(aes_gcm, buf, NULL, 0, aad + 16, aadlen - 16, buf, 16);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_gcm_encrypt(aes_gcm, buf + 16, mac, taglen, NULL, 0, buf + 16, msglen - 16);
	EXPECT_EQ(rc, 0);

	EXPECT_TRUE(memcmp(buf, ct, ctlen) == 0);
	EXPECT_TRUE(memcmp(mac, tag, taglen) == 0);

	/* Encrypt */
	memcpy(buf, msg, msglen);

	rc = zpc_aes_gcm_set_key(aes_gcm, aes_key);
	EXPECT_EQ(rc, 0);
	memset(&aes_key->prot, 0, sizeof(aes_key->prot));    /* destroy cached protected key */
	memset(aes_gcm->param.protkey, 0, sizeof(aes_gcm->param.protkey));    /* force WKaVP mismatch */
	rc = zpc_aes_gcm_set_iv(aes_gcm, iv, ivlen);
	EXPECT_EQ(rc, 0);

	memset(&aes_key->prot, 0, sizeof(aes_key->prot));    /* destroy cached protected key */
	memset(aes_gcm->param.protkey, 0, sizeof(aes_gcm->param.protkey));    /* force WKaVP mismatch */
	rc = zpc_aes_gcm_encrypt(aes_gcm, NULL, NULL, 0, aad, 16, NULL, 0);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_gcm_encrypt(aes_gcm, buf, NULL, 0, aad + 16, aadlen - 16, buf, 16);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_gcm_encrypt(aes_gcm, buf + 16, NULL, 0, NULL, 0, buf + 16, msglen - 16);   /* Works iff msglen - 16 == 0 mod 16 */
	EXPECT_EQ(rc, ZPC_ERROR_ARG8RANGE);
	memset(&aes_key->prot, 0, sizeof(aes_key->prot));    /* destroy cached protected key */
	memset(aes_gcm->param.protkey, 0, sizeof(aes_gcm->param.protkey));    /* force WKaVP mismatch */
	rc = zpc_aes_gcm_encrypt(aes_gcm, buf + 16, mac, taglen, NULL, 0, buf + 16, msglen - 16);
	EXPECT_EQ(rc, 0);

	EXPECT_TRUE(memcmp(buf, ct, ctlen) == 0);
	EXPECT_TRUE(memcmp(mac, tag, taglen) == 0);

	/* Decrypt */
	memcpy(buf, ct, ctlen);

	memset(&aes_key->prot, 0, sizeof(aes_key->prot));    /* destroy cached protected key */
	memset(aes_gcm->param.protkey, 0, sizeof(aes_gcm->param.protkey));    /* force WKaVP mismatch */
	rc = zpc_aes_gcm_set_iv(aes_gcm, iv, ivlen);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_gcm_decrypt(aes_gcm, NULL, NULL, 0, aad, 16, NULL, 0);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_gcm_decrypt(aes_gcm, NULL, NULL, 0, aad + 16, aadlen - 15, NULL, 0);    /* Works iff aadlen - 16 == 0 mod 16 */
	EXPECT_EQ(rc, ZPC_ERROR_ARG6RANGE);
	memset(&aes_key->prot, 0, sizeof(aes_key->prot));    /* destroy cached protected key */
	memset(aes_gcm->param.protkey, 0, sizeof(aes_gcm->param.protkey));    /* force WKaVP mismatch */
	rc = zpc_aes_gcm_decrypt(aes_gcm, buf, NULL, 0, aad + 16, aadlen - 16, buf, 16);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_gcm_decrypt(aes_gcm, buf + 16, tag, taglen, NULL, 0, buf + 16, msglen - 16);
	EXPECT_EQ(rc, 0);

	EXPECT_TRUE(memcmp(buf, msg, msglen) == 0);

	/* Decrypt */
	memcpy(buf, ct, ctlen);

	memset(&aes_key->prot, 0, sizeof(aes_key->prot));    /* destroy cached protected key */
	memset(aes_gcm->param.protkey, 0, sizeof(aes_gcm->param.protkey));    /* force WKaVP mismatch */
	rc = zpc_aes_gcm_set_iv(aes_gcm, iv, ivlen);
	EXPECT_EQ(rc, 0);

	memset(&aes_key->prot, 0, sizeof(aes_key->prot));    /* destroy cached protected key */
	memset(aes_gcm->param.protkey, 0, sizeof(aes_gcm->param.protkey));    /* force WKaVP mismatch */
	rc = zpc_aes_gcm_decrypt(aes_gcm, NULL, NULL, 0, aad, 16, NULL, 0);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_gcm_decrypt(aes_gcm, buf, NULL, 0, aad + 16, aadlen - 16, buf, 16);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_gcm_decrypt(aes_gcm, buf + 16, NULL, 0, NULL, 0, buf + 16, msglen - 16);   /* Works iff msglen - 16 == 0 mod 16 */
	EXPECT_EQ(rc, ZPC_ERROR_ARG8RANGE);
	rc = zpc_aes_gcm_decrypt(aes_gcm, buf + 16, tag, taglen, NULL, 0, buf + 16, msglen - 16);
	EXPECT_EQ(rc, 0);

	EXPECT_TRUE(memcmp(buf, msg, msglen) == 0);

	zpc_aes_gcm_free(&aes_gcm);
	EXPECT_EQ(aes_gcm, nullptr);
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
	struct zpc_aes_gcm *aes_gcm;
	unsigned char buf[4096], mac[16];
	size_t ivlen, msglen, ctlen, taglen, aadlen;
	int rc, i;

	const char *ivstr = "3254202d854734812398127a3d134421"; /* use ivlen != 12 bytes such that it must be processed by kma */
	const char *aadstr = "1a0293d8f90219058902139013908190bc490890d3ff12a3";
	const char *msgstr = "02efd2e5782312827ed5d230189a2a342b277ce048462193";
	const char *ctstr = "64069c2d58690561f27ee199e6b479b6369eec688672bde9";
	const char *tagstr = "9b7abadd6e69c1d9ec925786534f5075";

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

	rc = zpc_aes_gcm_alloc(&aes_gcm);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_gcm_set_key(aes_gcm, aes_key);
	EXPECT_EQ(rc, 0);

	for (i = 0; i < 1000; i++) {
		/* Encrypt */
		memcpy(buf, msg, msglen);

		memset(aes_gcm->param.protkey, 0, sizeof(aes_gcm->param.protkey));    /* force WKaVP mismatch */
		rc = zpc_aes_gcm_set_iv(aes_gcm, iv, ivlen);
		EXPECT_EQ(rc, 0);

		memset(aes_gcm->param.protkey, 0, sizeof(aes_gcm->param.protkey));    /* force WKaVP mismatch */
		rc = zpc_aes_gcm_encrypt(aes_gcm, NULL, NULL, 0, aad, 16, NULL, 0);
		EXPECT_EQ(rc, 0);
		rc = zpc_aes_gcm_encrypt(aes_gcm, buf, NULL, 0, aad + 16, aadlen - 16, buf, 16);
		EXPECT_EQ(rc, 0);
		rc = zpc_aes_gcm_encrypt(aes_gcm, buf + 16, mac, taglen, NULL, 0, buf + 16, msglen - 16);
		EXPECT_EQ(rc, 0);

		EXPECT_TRUE(memcmp(buf, ct, ctlen) == 0);
		EXPECT_TRUE(memcmp(mac, tag, taglen) == 0);

		/* Decrypt */
		memcpy(buf, ct, ctlen);

		rc = zpc_aes_gcm_set_iv(aes_gcm, iv, ivlen);
		EXPECT_EQ(rc, 0);

		memset(aes_gcm->param.protkey, 0, sizeof(aes_gcm->param.protkey));    /* force WKaVP mismatch */
		rc = zpc_aes_gcm_decrypt(aes_gcm, NULL, NULL, 0, aad, 16, NULL, 0);
		EXPECT_EQ(rc, 0);
		rc = zpc_aes_gcm_decrypt(aes_gcm, buf, NULL, 0, aad + 16, aadlen - 16, buf, 16);
		EXPECT_EQ(rc, 0);
		rc = zpc_aes_gcm_decrypt(aes_gcm, buf + 16, tag, taglen, NULL, 0, buf + 16, msglen - 16);
		EXPECT_EQ(rc, 0);

		EXPECT_TRUE(memcmp(buf, msg, msglen) == 0);
	}

	zpc_aes_gcm_free(&aes_gcm);
	EXPECT_EQ(aes_gcm, nullptr);

	free(iv);
	free(aad);
	free(msg);
	free(ct);
	free(tag);
}

TEST(aes_gcm, threads)
{
	TESTLIB_ENV_AES_KEY_CHECK();

	TESTLIB_AES_GCM_HW_CAPS_CHECK();

	TESTLIB_AES_KERNEL_CAPS_CHECK();

	size_t keylen;
	const char *mkvp, *apqns[257];
	struct zpc_aes_key *aes_key;
	unsigned int flags;
	int type, rc, i;
	std::thread *t[500];

	const char *keystr = "2034a82547276c83dd3212a813572bce";

	type = testlib_env_aes_key_type();
	flags = testlib_env_aes_key_flags();
	mkvp = testlib_env_aes_key_mkvp();
	(void)testlib_env_aes_key_apqns(apqns);

	TESTLIB_AES_SW_CAPS_CHECK(type);

	TESTLIB_APQN_CAPS_CHECK(apqns, mkvp, type, 256, flags);

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
