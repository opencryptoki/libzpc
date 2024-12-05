/*
 * Copyright IBM Corp. 2021
 *
 * libzpc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "testlib.h"

#include "gtest/gtest.h"
#include "zpc/aes_cmac.h"
#include "zpc/error.h"

#include "aes_key_local.h"  /* de-opaquify struct zpc_aes_key */
#include "aes_cmac_local.h"  /* de-opaquify struct zpc_aes_cmac */

#include <json-c/json.h>
#include <stdio.h>
#include <thread>
#include <unistd.h>

static void __run_json(const char *json);

TEST(aes_cmac, alloc)
{
	struct zpc_aes_cmac *aes_cmac;
	int rc;

	TESTLIB_ENV_AES_KEY_CHECK();

	TESTLIB_AES_CMAC_HW_CAPS_CHECK();

	rc = zpc_aes_cmac_alloc(NULL);
	EXPECT_EQ(rc, ZPC_ERROR_ARG1NULL);

	aes_cmac = NULL;
	rc = zpc_aes_cmac_alloc(&aes_cmac);
	EXPECT_EQ(rc, 0);
	zpc_aes_cmac_free(&aes_cmac);
	EXPECT_EQ(aes_cmac, nullptr);

	aes_cmac = (struct zpc_aes_cmac *)&aes_cmac;
	rc = zpc_aes_cmac_alloc(&aes_cmac);
	EXPECT_EQ(rc, 0);
	zpc_aes_cmac_free(&aes_cmac);
	EXPECT_EQ(aes_cmac, nullptr);
}

TEST(aes_cmac, free)
{
	struct zpc_aes_cmac *aes_cmac;
	int rc;

	TESTLIB_ENV_AES_KEY_CHECK();

	TESTLIB_AES_CMAC_HW_CAPS_CHECK();

	zpc_aes_cmac_free(NULL);

	aes_cmac = NULL;
	zpc_aes_cmac_free(&aes_cmac);
	EXPECT_EQ(aes_cmac, nullptr);

	rc = zpc_aes_cmac_alloc(&aes_cmac);
	EXPECT_EQ(rc, 0);
	zpc_aes_cmac_free(&aes_cmac);
	EXPECT_EQ(aes_cmac, nullptr);
}

TEST(aes_cmac, set_key)
{
	struct zpc_aes_key *aes_key;
	struct zpc_aes_cmac *aes_cmac;
	u8 clearkey[32];
	unsigned int flags = 0;
	const char *mkvp, *apqns[257];
	int rc, size, type;

	TESTLIB_ENV_AES_KEY_CHECK();

	TESTLIB_AES_CMAC_HW_CAPS_CHECK();

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
	rc = zpc_aes_cmac_alloc(&aes_cmac);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_cmac_set_key(aes_cmac, aes_key);
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

	rc = zpc_aes_cmac_set_key(NULL, NULL);
	EXPECT_EQ(rc, ZPC_ERROR_ARG1NULL);
	rc = zpc_aes_cmac_set_key(NULL, aes_key);
	EXPECT_EQ(rc, ZPC_ERROR_ARG1NULL);

	rc = zpc_aes_cmac_set_key(aes_cmac, NULL);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_cmac_set_key(aes_cmac, aes_key);
	EXPECT_EQ(rc, 0);

	zpc_aes_cmac_free(&aes_cmac);
	EXPECT_EQ(aes_cmac, nullptr);
	zpc_aes_key_free(&aes_key);
	EXPECT_EQ(aes_key, nullptr);
}

TEST(aes_cmac, sign)
{
	struct zpc_aes_key *aes_key;
	struct zpc_aes_cmac *aes_cmac;
	const char *mkvp, *apqns[257];
	u8  m[99], tag[16];
	unsigned int flags;
	int rc, size, type;

	TESTLIB_ENV_AES_KEY_CHECK();

	TESTLIB_AES_CMAC_HW_CAPS_CHECK();

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
	rc = zpc_aes_cmac_alloc(&aes_cmac);
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

	rc = zpc_aes_cmac_set_key(aes_cmac, aes_key);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_cmac_sign(aes_cmac, tag, 16, m, 99);
	EXPECT_EQ(rc, 0);

	zpc_aes_cmac_free(&aes_cmac);
	EXPECT_EQ(aes_cmac, nullptr);
	zpc_aes_key_free(&aes_key);
	EXPECT_EQ(aes_key, nullptr);
}

TEST(aes_cmac, verify)
{
	struct zpc_aes_key *aes_key;
	struct zpc_aes_cmac *aes_cmac;
	const char *mkvp, *apqns[257];
	u8 m[99], tag[16];
	unsigned int flags;
	int rc, size, type;

	TESTLIB_ENV_AES_KEY_CHECK();

	TESTLIB_AES_CMAC_HW_CAPS_CHECK();

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
	rc = zpc_aes_cmac_alloc(&aes_cmac);
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
	rc = zpc_aes_cmac_set_key(aes_cmac, aes_key);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_cmac_verify(aes_cmac, tag, 16, m, 99);
	EXPECT_EQ(rc, ZPC_ERROR_TAGMISMATCH);

	zpc_aes_cmac_free(&aes_cmac);
	EXPECT_EQ(aes_cmac, nullptr);
	zpc_aes_key_free(&aes_key);
	EXPECT_EQ(aes_key, nullptr);
}

TEST(aes_cmac, pc)
{
	struct zpc_aes_key *aes_key1, *aes_key2;
	struct zpc_aes_cmac *aes_cmac1, *aes_cmac2;
	const char *mkvp, *apqns[257];
	u8 m[99], tag[16], key[32];
	unsigned int flags;
	int rc, size, type;

	TESTLIB_ENV_AES_KEY_CHECK();

	TESTLIB_AES_CMAC_HW_CAPS_CHECK();

	TESTLIB_AES_KERNEL_CAPS_CHECK();

	size = testlib_env_aes_key_size();
	type = testlib_env_aes_key_type();
	flags = testlib_env_aes_key_flags();
	mkvp = testlib_env_aes_key_mkvp();
	(void)testlib_env_aes_key_apqns(apqns);

	TESTLIB_AES_SW_CAPS_CHECK(type);

	TESTLIB_APQN_CAPS_CHECK(apqns, mkvp, type, size, flags);

	rc = zpc_aes_key_alloc(&aes_key1);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_key_alloc(&aes_key2);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_cmac_alloc(&aes_cmac1);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_cmac_alloc(&aes_cmac2);
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
	rc = zpc_aes_cmac_set_key(aes_cmac1, aes_key1);
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
	rc = zpc_aes_cmac_set_key(aes_cmac2, aes_key2);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_cmac_sign(aes_cmac1, tag, 16, m, 99);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_cmac_verify(aes_cmac2, tag, 16, m, 99);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_cmac_sign(aes_cmac2, tag, 16, m, 99);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_cmac_verify(aes_cmac1, tag, 16, m, 99);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_cmac_sign(aes_cmac2, tag, 16, m, 99);
	EXPECT_EQ(rc, 0);
	tag[0] ^= 1;
	rc = zpc_aes_cmac_verify(aes_cmac1, tag, 16, m, 99);
	EXPECT_EQ(rc, ZPC_ERROR_TAGMISMATCH);
	rc = zpc_aes_cmac_sign(aes_cmac1, tag, 16, m, 99);
	EXPECT_EQ(rc, 0);
	tag[0] ^= 1;
	rc = zpc_aes_cmac_verify(aes_cmac2, tag, 16, m, 99);
	EXPECT_EQ(rc, ZPC_ERROR_TAGMISMATCH);

	/* Random protected key */
	rc = zpc_aes_cmac_set_key(aes_cmac1, NULL);   /* Unset key. */
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_cmac_set_key(aes_cmac2, NULL);   /* Unset key. */
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_key_set_mkvp(aes_key1, NULL);   /* Unset apqns. */
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_key_set_size(aes_key1, size);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_key_generate(aes_key1);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_cmac_set_key(aes_cmac1, aes_key1);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_cmac_set_key(aes_cmac2, aes_key1);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_cmac_sign(aes_cmac1, tag, 16, m, 99);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_cmac_verify(aes_cmac2, tag, 16, m, 99);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_cmac_sign(aes_cmac2, tag, 16, m, 99);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_cmac_verify(aes_cmac1, tag, 16, m, 99);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_cmac_sign(aes_cmac2, tag, 16, m, 99);
	EXPECT_EQ(rc, 0);
	tag[0] ^= 1;
	rc = zpc_aes_cmac_verify(aes_cmac1, tag, 16, m, 99);
	EXPECT_EQ(rc, ZPC_ERROR_TAGMISMATCH);
	rc = zpc_aes_cmac_sign(aes_cmac1, tag, 16, m, 99);
	EXPECT_EQ(rc, 0);
	tag[0] ^= 1;
	rc = zpc_aes_cmac_verify(aes_cmac2, tag, 16, m, 99);
	EXPECT_EQ(rc, ZPC_ERROR_TAGMISMATCH);

	zpc_aes_cmac_free(&aes_cmac2);
	zpc_aes_cmac_free(&aes_cmac1);
	zpc_aes_key_free(&aes_key2);
	EXPECT_EQ(aes_key2, nullptr);
	zpc_aes_key_free(&aes_key1);
	EXPECT_EQ(aes_key1, nullptr);
}

TEST(aes_cmac, stream_inplace_kat1)
{
	TESTLIB_ENV_AES_KEY_CHECK();

	TESTLIB_AES_CMAC_HW_CAPS_CHECK();

	TESTLIB_AES_KERNEL_CAPS_CHECK();

	size_t keylen, msglen, taglen;
	unsigned char mac[16];
	const char *mkvp, *apqns[257];
	struct zpc_aes_key *aes_key;
	struct zpc_aes_cmac *aes_cmac;
	unsigned int flags;
	int type, rc;

	const char *keystr = "648a44468d67bb6744b235ee7a3fcd6ed4bdc29ec5b5fa1a";
	const char *msgstr = "c59d0d6981cca1be1d5519fc7881e6d230f39f6c12a9e827";
	const char *tagstr = "a1b96272ae7f9aef567271795f21d1d3";

	type = testlib_env_aes_key_type();
	flags = testlib_env_aes_key_flags();
	mkvp = testlib_env_aes_key_mkvp();
	(void)testlib_env_aes_key_apqns(apqns);

	TESTLIB_AES_SW_CAPS_CHECK(type);

	TESTLIB_APQN_CAPS_CHECK(apqns, mkvp, type, 256, flags);

	u8 *key = testlib_hexstr2buf(keystr, &keylen);
	ASSERT_NE(key, nullptr);
	u8 *msg = testlib_hexstr2buf(msgstr, &msglen);
	ASSERT_NE(msg, nullptr);
	u8 *tag = testlib_hexstr2buf(tagstr, &taglen);
	ASSERT_NE(tag, nullptr);

	rc = zpc_aes_key_alloc(&aes_key);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_cmac_alloc(&aes_cmac);
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

	/* Sign */

	rc = zpc_aes_cmac_set_key(aes_cmac, aes_key);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_cmac_sign(aes_cmac, NULL, 0, msg, 16);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_cmac_sign(aes_cmac, mac, taglen, msg + 16, msglen - 16);
	EXPECT_EQ(rc, 0);
	EXPECT_TRUE(memcmp(mac, tag, taglen) == 0);

	rc = zpc_aes_cmac_sign(aes_cmac, mac, taglen, msg, msglen);
	EXPECT_EQ(rc, 0);
	EXPECT_TRUE(memcmp(mac, tag, taglen) == 0);

	/* Verify */

	rc = zpc_aes_cmac_verify(aes_cmac, NULL, 0, msg, 16);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_cmac_verify(aes_cmac, tag, taglen, msg + 16, msglen - 16);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_cmac_verify(aes_cmac, tag, taglen, msg, msglen);
	EXPECT_EQ(rc, 0);

	zpc_aes_cmac_free(&aes_cmac);
	EXPECT_EQ(aes_cmac, nullptr);
	zpc_aes_key_free(&aes_key);
	EXPECT_EQ(aes_key, nullptr);

	free(key);
	free(msg);
	free(tag);
}

TEST(aes_cmac, stream_inplace_kat2)
{
	TESTLIB_ENV_AES_KEY_CHECK();

	TESTLIB_AES_CMAC_HW_CAPS_CHECK();

	TESTLIB_AES_KERNEL_CAPS_CHECK();

	size_t keylen, msglen, taglen;
	unsigned char mac[16];
	const char *mkvp, *apqns[257];
	struct zpc_aes_key *aes_key;
	struct zpc_aes_cmac *aes_cmac;
	unsigned int flags;
	int type, rc;

	const char *keystr = "648a44468d67bb6744b235ee7a3fcd6ed4bdc29ec5b5fa1a";
	const char *msgstr = "c59d0d6981cca1be1d5519fc7881e6d230f39f6c12a9e827";
	const char *tagstr = "a1b96272ae7f9aef567271795f21d1d3";

	type = testlib_env_aes_key_type();
	flags = testlib_env_aes_key_flags();
	mkvp = testlib_env_aes_key_mkvp();
	(void)testlib_env_aes_key_apqns(apqns);

	TESTLIB_AES_SW_CAPS_CHECK(type);

	TESTLIB_APQN_CAPS_CHECK(apqns, mkvp, type, 256, flags);

	u8 *key = testlib_hexstr2buf(keystr, &keylen);
	ASSERT_NE(key, nullptr);
	u8 *msg = testlib_hexstr2buf(msgstr, &msglen);
	ASSERT_NE(msg, nullptr);
	u8 *tag = testlib_hexstr2buf(tagstr, &taglen);
	ASSERT_NE(tag, nullptr);

	rc = zpc_aes_key_alloc(&aes_key);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_cmac_alloc(&aes_cmac);
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

	/* Sign */

	rc = zpc_aes_cmac_set_key(aes_cmac, aes_key);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_cmac_sign(aes_cmac, NULL, 0, msg, 16);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_cmac_sign(aes_cmac, NULL, 0, NULL, 0);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_cmac_sign(aes_cmac, mac, taglen, msg + 16, msglen - 16);
	EXPECT_EQ(rc, 0);

	EXPECT_TRUE(memcmp(mac, tag, taglen) == 0);

	/* Verify */

	rc = zpc_aes_cmac_verify(aes_cmac, NULL, 0, msg, 16);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_cmac_verify(aes_cmac, NULL, 0, NULL, 0);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_cmac_verify(aes_cmac, tag, taglen, msg + 16, msglen - 16);
	EXPECT_EQ(rc, 0);

	zpc_aes_cmac_free(&aes_cmac);
	EXPECT_EQ(aes_cmac, nullptr);
	zpc_aes_key_free(&aes_key);
	EXPECT_EQ(aes_key, nullptr);

	free(key);
	free(msg);
	free(tag);
}

TEST(aes_cmac, wycheproof_kat)
{
	TESTLIB_ENV_AES_KEY_CHECK();

	TESTLIB_AES_CMAC_HW_CAPS_CHECK();

	TESTLIB_AES_KERNEL_CAPS_CHECK();

	__run_json("wycheproof/src/wycheproof/testvectors/aes_cmac_test.json");
}

static void __run_json(const char *json)
{
	const char *tv = json, *str;
	const char *mkvp, *apqns[257];
	struct zpc_aes_key *aes_key;
	struct zpc_aes_cmac *aes_cmac;
	unsigned int flags;
	u8 *key = NULL;
	u8 *pt = NULL;
	u8 *tag = NULL, *tag_out = NULL;
	int rc, tagsize = 0, keysize = 0;
	int valid = 0;
	size_t ptlen, taglen, i, j;
	json_object *jkey, *jtag, *jmsg, *jresult, *jtmp, *jtestgroups, *jfile, *jkeysize, *jtagsize, *jtests;
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
	rc = zpc_aes_cmac_alloc(&aes_cmac);
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
		b = json_object_object_get_ex(jtmp, "tagSize", &jtagsize);
		ASSERT_TRUE(b);
		b = json_object_object_get_ex(jtmp, "tests", &jtests);
		ASSERT_TRUE(b);

		keysize = json_object_get_int(jkeysize);
		tagsize = json_object_get_int(jtagsize);

		rc = zpc_aes_key_set_size(aes_key, keysize);
		if (keysize != 128 && keysize != 192 && keysize != 256) {
			EXPECT_EQ(rc, ZPC_ERROR_KEYSIZE);
			continue;
		} else {
			EXPECT_EQ(rc, 0);
		}

		for (j = 0; j < (size_t)json_object_array_length(jtests); j++) {
			jtmp = json_object_array_get_idx(jtests, j);
			ASSERT_NE(jtmp, nullptr);

			b = json_object_object_get_ex(jtmp, "key", &jkey);
			ASSERT_TRUE(b);
			b = json_object_object_get_ex(jtmp, "tag", &jtag);
			ASSERT_TRUE(b);
			b = json_object_object_get_ex(jtmp, "msg", &jmsg);
			ASSERT_TRUE(b);
			b = json_object_object_get_ex(jtmp, "result", &jresult);
			ASSERT_TRUE(b);

			str = json_object_get_string(jkey);
			ASSERT_NE(str, nullptr);
			key = testlib_hexstr2buf(str, NULL);
			ASSERT_NE(key, nullptr);
			str = json_object_get_string(jtag);
			ASSERT_NE(str, nullptr);
			tag = testlib_hexstr2buf(str, &taglen);
			ASSERT_NE(tag, nullptr);
			tag_out = (unsigned char *)calloc(1, taglen);
			ASSERT_NE(tag_out, nullptr);
			str = json_object_get_string(jmsg);
			ASSERT_NE(str, nullptr);
			pt = testlib_hexstr2buf(str, &ptlen);
			str = json_object_get_string(jresult);
			ASSERT_NE(str, nullptr);
			if (strcmp(str, "valid") == 0)
				valid = 1;
			else if (strcmp(str, "invalid") == 0)
				valid = 0;
			else
				assert(strcmp(str, "invalid") == 0 || strcmp(str, "valid") == 0);

			rc = zpc_aes_key_import_clear(aes_key, key);
			EXPECT_EQ(rc, 0);

			rc = zpc_aes_cmac_set_key(aes_cmac, aes_key);
			EXPECT_EQ(rc, 0);

			rc = zpc_aes_cmac_sign(aes_cmac, tag_out, tagsize / 8, pt, ptlen);
			EXPECT_EQ(rc, 0);
			if (valid) {
				  EXPECT_TRUE(memcmp(tag_out, tag, tagsize / 8) == 0);
			}
	
			rc = zpc_aes_cmac_verify(aes_cmac, tag, tagsize / 8, pt, ptlen);
			EXPECT_EQ(rc, valid ? 0 : ZPC_ERROR_TAGMISMATCH);


			/* Unset key. */
			rc = zpc_aes_cmac_set_key(aes_cmac, NULL);
			EXPECT_EQ(rc, 0);

			free(key); key = NULL;
			free(pt); pt = NULL;
			free(tag); tag = NULL;
			free(tag_out); tag_out = NULL;
		}
	}
	zpc_aes_cmac_free(&aes_cmac);
	EXPECT_EQ(aes_cmac, nullptr);
	zpc_aes_key_free(&aes_key);
	EXPECT_EQ(aes_key, nullptr);
}

TEST(aes_cmac, rederive_protected_key1)
{
	struct zpc_aes_key *aes_key1;
	struct zpc_aes_cmac *aes_cmac1, *aes_cmac2, *aes_cmac3;
	u8 m[99], tag[16];
	int rc, size;

	TESTLIB_ENV_AES_KEY_CHECK();

	TESTLIB_AES_CMAC_HW_CAPS_CHECK();

	TESTLIB_AES_KERNEL_CAPS_CHECK();

	size = testlib_env_aes_key_size();

	rc = zpc_aes_key_alloc(&aes_key1);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_cmac_alloc(&aes_cmac1);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_cmac_alloc(&aes_cmac2);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_cmac_alloc(&aes_cmac3);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_cmac_set_key(aes_cmac1, NULL);   /* Unset key. */
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_cmac_set_key(aes_cmac2, NULL);   /* Unset key. */
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_cmac_set_key(aes_cmac3, NULL);   /* Unset key. */
	EXPECT_EQ(rc, 0);

	/* Random protected keys cannot be re-derived. */

	rc = zpc_aes_key_set_mkvp(aes_key1, NULL);   /* Unset apqns. */
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_key_set_size(aes_key1, size);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_key_generate(aes_key1);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_cmac_set_key(aes_cmac1, aes_key1);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_cmac_set_key(aes_cmac2, aes_key1);
	EXPECT_EQ(rc, 0);

	memset(aes_cmac2->param_kmac.protkey, 0, sizeof(aes_cmac2->param_kmac.protkey));
	memset(aes_cmac2->param_pcc.protkey, 0, sizeof(aes_cmac2->param_pcc.protkey));
	rc = zpc_aes_cmac_sign(aes_cmac2, tag, 16, m, 99);
	EXPECT_EQ(rc, ZPC_ERROR_PROTKEYONLY);

	rc = zpc_aes_cmac_set_key(aes_cmac3, aes_key1);
	EXPECT_EQ(rc, 0);

	memset(aes_cmac3->param_kmac.protkey, 0, sizeof(aes_cmac3->param_kmac.protkey));
	memset(aes_cmac2->param_pcc.protkey, 0, sizeof(aes_cmac2->param_pcc.protkey));
	rc = zpc_aes_cmac_verify(aes_cmac3, tag, 16, m, 99);
	EXPECT_EQ(rc, ZPC_ERROR_PROTKEYONLY);

	rc = zpc_aes_cmac_set_key(aes_cmac1, aes_key1);
	EXPECT_EQ(rc, 0);

	zpc_aes_cmac_free(&aes_cmac3);
	zpc_aes_cmac_free(&aes_cmac2);
	zpc_aes_cmac_free(&aes_cmac1);
	zpc_aes_key_free(&aes_key1);
	EXPECT_EQ(aes_cmac3, nullptr);
	EXPECT_EQ(aes_cmac2, nullptr);
	EXPECT_EQ(aes_cmac1, nullptr);
	EXPECT_EQ(aes_key1, nullptr);
}

TEST(aes_cmac, rederive_protected_key2)
{
	TESTLIB_ENV_AES_KEY_CHECK();

	TESTLIB_AES_CMAC_HW_CAPS_CHECK();

	TESTLIB_AES_KERNEL_CAPS_CHECK();

	size_t keylen, msglen, taglen;
	unsigned char mac[16];
	const char *mkvp, *apqns[257];
	struct zpc_aes_key *aes_key;
	struct zpc_aes_cmac *aes_cmac;
	unsigned int flags;
	int type, rc;

	const char *keystr = "648a44468d67bb6744b235ee7a3fcd6ed4bdc29ec5b5fa1a";
	const char *msgstr = "c59d0d6981cca1be1d5519fc7881e6d230f39f6c12a9e827";
	const char *tagstr = "a1b96272ae7f9aef567271795f21d1d3";

	type = testlib_env_aes_key_type();
	flags = testlib_env_aes_key_flags();
	mkvp = testlib_env_aes_key_mkvp();
	(void)testlib_env_aes_key_apqns(apqns);

	TESTLIB_AES_SW_CAPS_CHECK(type);

	TESTLIB_APQN_CAPS_CHECK(apqns, mkvp, type, 256, flags);

	u8 *key = testlib_hexstr2buf(keystr, &keylen);
	ASSERT_NE(key, nullptr);
	u8 *msg = testlib_hexstr2buf(msgstr, &msglen);
	ASSERT_NE(msg, nullptr);
	u8 *tag = testlib_hexstr2buf(tagstr, &taglen);
	ASSERT_NE(tag, nullptr);

	rc = zpc_aes_key_alloc(&aes_key);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_cmac_alloc(&aes_cmac);
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

	/* Sign */

	rc = zpc_aes_cmac_set_key(aes_cmac, aes_key);
	EXPECT_EQ(rc, 0);

	memset(aes_cmac->param_kmac.protkey, 0, sizeof(aes_cmac->param_kmac.protkey));    /* force WKaVP mismatch */
	memset(aes_cmac->param_pcc.protkey, 0, sizeof(aes_cmac->param_pcc.protkey));    /* force WKaVP mismatch */
	rc = zpc_aes_cmac_sign(aes_cmac, NULL, 0, msg, 16);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_cmac_sign(aes_cmac, mac, taglen, msg + 16, msglen - 16);
	EXPECT_EQ(rc, 0);

	EXPECT_TRUE(memcmp(mac, tag, taglen) == 0);

	/* Sign*/

	memset(aes_cmac->param_kmac.protkey, 0, sizeof(aes_cmac->param_kmac.protkey));    /* force WKaVP mismatch */
	memset(aes_cmac->param_pcc.protkey, 0, sizeof(aes_cmac->param_pcc.protkey));    /* force WKaVP mismatch */
	rc = zpc_aes_cmac_sign(aes_cmac, NULL, 0, msg, 16);
	EXPECT_EQ(rc, 0);
	memset(aes_cmac->param_kmac.protkey, 0, sizeof(aes_cmac->param_kmac.protkey));    /* force WKaVP mismatch */
	memset(aes_cmac->param_pcc.protkey, 0, sizeof(aes_cmac->param_pcc.protkey));    /* force WKaVP mismatch */
	rc = zpc_aes_cmac_sign(aes_cmac, mac, taglen, msg + 16, msglen - 16);
	EXPECT_EQ(rc, 0);

	EXPECT_TRUE(memcmp(mac, tag, taglen) == 0);

	/* Verify */

	rc = zpc_aes_cmac_verify(aes_cmac, NULL, 0, msg, 16);
	EXPECT_EQ(rc, 0);
	memset(aes_cmac->param_kmac.protkey, 0, sizeof(aes_cmac->param_kmac.protkey));    /* force WKaVP mismatch */
	memset(aes_cmac->param_pcc.protkey, 0, sizeof(aes_cmac->param_pcc.protkey));    /* force WKaVP mismatch */
	rc = zpc_aes_cmac_verify(aes_cmac, mac, taglen, msg + 16, msglen - 16);
	EXPECT_EQ(rc, 0);

	/* Verify */

	memset(aes_cmac->param_kmac.protkey, 0, sizeof(aes_cmac->param_kmac.protkey));    /* force WKaVP mismatch */
	memset(aes_cmac->param_pcc.protkey, 0, sizeof(aes_cmac->param_pcc.protkey));    /* force WKaVP mismatch */
	rc = zpc_aes_cmac_verify(aes_cmac, NULL, 0, msg, 16);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_cmac_verify(aes_cmac, mac, taglen, msg + 16, msglen - 16);
	EXPECT_EQ(rc, 0);

	zpc_aes_cmac_free(&aes_cmac);
	EXPECT_EQ(aes_cmac, nullptr);
	zpc_aes_key_free(&aes_key);
	EXPECT_EQ(aes_key, nullptr);

	free(key);
	free(msg);
	free(tag);
}

TEST(aes_cmac, reencipher)
{
	TESTLIB_ENV_AES_KEY_CHECK();

	TESTLIB_AES_CMAC_HW_CAPS_CHECK();

	TESTLIB_AES_KERNEL_CAPS_CHECK();

	size_t keylen, msglen, taglen;
	unsigned char mac[16];
	const char *mkvp, *apqns[257];
	struct zpc_aes_key *aes_key;
	struct zpc_aes_cmac *aes_cmac;
	unsigned int flags;
	int type, rc;

	const char *keystr = "648a44468d67bb6744b235ee7a3fcd6ed4bdc29ec5b5fa1a";
	const char *msgstr = "c59d0d6981cca1be1d5519fc7881e6d230f39f6c12a9e827";
	const char *tagstr = "a1b96272ae7f9aef567271795f21d1d3";

	type = testlib_env_aes_key_type();
	flags = testlib_env_aes_key_flags();
	mkvp = testlib_env_aes_key_mkvp();
	(void)testlib_env_aes_key_apqns(apqns);

	TESTLIB_AES_SW_CAPS_CHECK(type);

	TESTLIB_APQN_CAPS_CHECK(apqns, mkvp, type, 256, flags);

	TESTLIB_AES_NEW_MK_CHECK(type, mkvp, apqns);

	u8 *key = testlib_hexstr2buf(keystr, &keylen);
	ASSERT_NE(key, nullptr);
	u8 *msg = testlib_hexstr2buf(msgstr, &msglen);
	ASSERT_NE(msg, nullptr);
	u8 *tag = testlib_hexstr2buf(tagstr, &taglen);
	ASSERT_NE(tag, nullptr);

	rc = zpc_aes_key_alloc(&aes_key);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_cmac_alloc(&aes_cmac);
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

	rc = zpc_aes_cmac_set_key(aes_cmac, aes_key);
	EXPECT_EQ(rc, 0);

	memset(&aes_key->prot, 0, sizeof(aes_key->prot));    /* destroy cached protected key */
	memset(aes_cmac->param_kmac.protkey, 0, sizeof(aes_cmac->param_kmac.protkey));    /* force WKaVP mismatch */
	memset(aes_cmac->param_pcc.protkey, 0, sizeof(aes_cmac->param_pcc.protkey));    /* force WKaVP mismatch */
	rc = zpc_aes_cmac_sign(aes_cmac, NULL, 0, msg, 16);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_cmac_sign(aes_cmac, mac, taglen, msg + 16, msglen - 16);
	EXPECT_EQ(rc, 0);

	EXPECT_TRUE(memcmp(mac, tag, taglen) == 0);

	/* Encrypt */

	rc = zpc_aes_cmac_set_key(aes_cmac, aes_key);
	EXPECT_EQ(rc, 0);

	memset(&aes_key->prot, 0, sizeof(aes_key->prot));    /* destroy cached protected key */
	memset(aes_cmac->param_kmac.protkey, 0, sizeof(aes_cmac->param_kmac.protkey));    /* force WKaVP mismatch */
	memset(aes_cmac->param_pcc.protkey, 0, sizeof(aes_cmac->param_pcc.protkey));    /* force WKaVP mismatch */
	rc = zpc_aes_cmac_sign(aes_cmac, NULL, 0, msg, 16);
	EXPECT_EQ(rc, 0);
	memset(&aes_key->prot, 0, sizeof(aes_key->prot));    /* destroy cached protected key */
	memset(aes_cmac->param_pcc.protkey, 0, sizeof(aes_cmac->param_pcc.protkey));    /* force WKaVP mismatch */
	memset(aes_cmac->param_kmac.protkey, 0, sizeof(aes_cmac->param_kmac.protkey));    /* force WKaVP mismatch */
	rc = zpc_aes_cmac_sign(aes_cmac, mac, taglen, msg + 16, msglen - 16);
	EXPECT_EQ(rc, 0);

	EXPECT_TRUE(memcmp(mac, tag, taglen) == 0);

	/* Decrypt */

	rc = zpc_aes_cmac_verify(aes_cmac, NULL, 0, msg, 16);
	EXPECT_EQ(rc, 0);
	memset(&aes_key->prot, 0, sizeof(aes_key->prot));    /* destroy cached protected key */
	memset(aes_cmac->param_kmac.protkey, 0, sizeof(aes_cmac->param_kmac.protkey));    /* force WKaVP mismatch */
	memset(aes_cmac->param_pcc.protkey, 0, sizeof(aes_cmac->param_pcc.protkey));    /* force WKaVP mismatch */
	rc = zpc_aes_cmac_verify(aes_cmac, mac, taglen, msg + 16, msglen - 16);
	EXPECT_EQ(rc, 0);

	/* Decrypt */

	memset(&aes_key->prot, 0, sizeof(aes_key->prot));    /* destroy cached protected key */
	memset(aes_cmac->param_kmac.protkey, 0, sizeof(aes_cmac->param_kmac.protkey));    /* force WKaVP mismatch */
	memset(aes_cmac->param_pcc.protkey, 0, sizeof(aes_cmac->param_pcc.protkey));    /* force WKaVP mismatch */
	rc = zpc_aes_cmac_verify(aes_cmac, NULL, 0, msg, 16);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_cmac_verify(aes_cmac, mac, taglen, msg + 16, msglen - 16);
	EXPECT_EQ(rc, 0);

	zpc_aes_cmac_free(&aes_cmac);
	EXPECT_EQ(aes_cmac, nullptr);
	zpc_aes_key_free(&aes_key);
	EXPECT_EQ(aes_key, nullptr);

	free(key);
	free(msg);
	free(tag);
}

static void
__task(struct zpc_aes_key *aes_key)
{
	struct zpc_aes_cmac *aes_cmac;
	unsigned char mac[16];
	size_t msglen, taglen;
	int rc, i;

	const char *msgstr = "c59d0d6981cca1be1d5519fc7881e6d230f39f6c12a9e827";
	const char *tagstr = "a1b96272ae7f9aef567271795f21d1d3";

	u8 *msg = testlib_hexstr2buf(msgstr, &msglen);
	ASSERT_NE(msg, nullptr);
	u8 *tag = testlib_hexstr2buf(tagstr, &taglen);
	ASSERT_NE(tag, nullptr);

	rc = zpc_aes_cmac_alloc(&aes_cmac);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_cmac_set_key(aes_cmac, aes_key);
	EXPECT_EQ(rc, 0);

	for (i = 0; i < 1000; i++) {
		/* Sign */
	
		memset(aes_cmac->param_kmac.protkey, 0, sizeof(aes_cmac->param_kmac.protkey));    /* force WKaVP mismatch */
		memset(aes_cmac->param_pcc.protkey, 0, sizeof(aes_cmac->param_pcc.protkey));    /* force WKaVP mismatch */
		rc = zpc_aes_cmac_sign(aes_cmac, NULL, 0, msg, 16);
		EXPECT_EQ(rc, 0);
		rc = zpc_aes_cmac_sign(aes_cmac, mac, taglen, msg + 16, msglen - 16);
		EXPECT_EQ(rc, 0);

		EXPECT_TRUE(memcmp(mac, tag, taglen) == 0);

		/* Verify */

		memset(aes_cmac->param_kmac.protkey, 0, sizeof(aes_cmac->param_kmac.protkey));    /* force WKaVP mismatch */
		memset(aes_cmac->param_pcc.protkey, 0, sizeof(aes_cmac->param_pcc.protkey));    /* force WKaVP mismatch */
		rc = zpc_aes_cmac_verify(aes_cmac, NULL, 0, msg, 16);
		EXPECT_EQ(rc, 0);
		rc = zpc_aes_cmac_verify(aes_cmac, mac, taglen, msg + 16, msglen - 16);
		EXPECT_EQ(rc, 0);
	}

	zpc_aes_cmac_free(&aes_cmac);
	EXPECT_EQ(aes_cmac, nullptr);

	free(msg);
	free(tag);
}

TEST(aes_cmac, threads)
{
	TESTLIB_ENV_AES_KEY_CHECK();

	TESTLIB_AES_CMAC_HW_CAPS_CHECK();

	TESTLIB_AES_KERNEL_CAPS_CHECK();

	size_t keylen;
	const char *mkvp, *apqns[257];
	struct zpc_aes_key *aes_key;
	unsigned int flags;
	int type, rc, i;
	std::thread *t[500];

	const char *keystr = "648a44468d67bb6744b235ee7a3fcd6ed4bdc29ec5b5fa1a";

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
