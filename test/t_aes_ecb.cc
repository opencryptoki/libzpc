/*
 * Copyright IBM Corp. 2021
 *
 * libzpc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "testlib.h"

#include "gtest/gtest.h"
#include "zpc/aes_ecb.h"
#include "zpc/error.h"

#include "aes_key_local.h"  /* de-opaquify struct zpc_aes_key */
#include "aes_ecb_local.h"  /* de-opaquify struct zpc_aes_ecb */

#include <json-c/json.h>
#include <stdio.h>
#include <thread>
#include <unistd.h>

static void __run_json(const char *json);

TEST(aes_ecb, alloc)
{
	struct zpc_aes_ecb *aes_ecb;
	int rc;

	TESTLIB_ENV_AES_KEY_CHECK();

	rc = zpc_aes_ecb_alloc(NULL);
	EXPECT_EQ(rc, ZPC_ERROR_ARG1NULL);

	aes_ecb = NULL;
	rc = zpc_aes_ecb_alloc(&aes_ecb);
	EXPECT_EQ(rc, 0);
	zpc_aes_ecb_free(&aes_ecb);
	EXPECT_EQ(aes_ecb, nullptr);

	aes_ecb = (struct zpc_aes_ecb *)&aes_ecb;
	rc = zpc_aes_ecb_alloc(&aes_ecb);
	EXPECT_EQ(rc, 0);
	zpc_aes_ecb_free(&aes_ecb);
	EXPECT_EQ(aes_ecb, nullptr);
}

TEST(aes_ecb, free)
{
	struct zpc_aes_ecb *aes_ecb;
	int rc;

	TESTLIB_ENV_AES_KEY_CHECK();

	zpc_aes_ecb_free(NULL);

	aes_ecb = NULL;
	zpc_aes_ecb_free(&aes_ecb);
	EXPECT_EQ(aes_ecb, nullptr);

	rc = zpc_aes_ecb_alloc(&aes_ecb);
	EXPECT_EQ(rc, 0);
	zpc_aes_ecb_free(&aes_ecb);
	EXPECT_EQ(aes_ecb, nullptr);
}

TEST(aes_ecb, set_key)
{
	struct zpc_aes_key *aes_key;
	struct zpc_aes_ecb *aes_ecb;
	u8 clearkey[32];
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
	rc = zpc_aes_ecb_alloc(&aes_ecb);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_ecb_set_key(aes_ecb, aes_key);
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

	rc = zpc_aes_ecb_set_key(NULL, NULL);
	EXPECT_EQ(rc, ZPC_ERROR_ARG1NULL);
	rc = zpc_aes_ecb_set_key(NULL, aes_key);
	EXPECT_EQ(rc, ZPC_ERROR_ARG1NULL);

	rc = zpc_aes_ecb_set_key(aes_ecb, NULL);
	EXPECT_EQ(rc, 0);

	zpc_aes_ecb_free(&aes_ecb);
	EXPECT_EQ(aes_ecb, nullptr);
	zpc_aes_key_free(&aes_key);
	EXPECT_EQ(aes_key, nullptr);
}

TEST(aes_ecb, encrypt)
{
	struct zpc_aes_key *aes_key;
	struct zpc_aes_ecb *aes_ecb;
	const char *mkvp, *apqns[257];
	u8 m[64], c[64];
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
	rc = zpc_aes_ecb_alloc(&aes_ecb);
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

	rc = zpc_aes_ecb_set_key(aes_ecb, aes_key);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_ecb_encrypt(aes_ecb, c, m, 64);
	EXPECT_EQ(rc, 0);

	zpc_aes_ecb_free(&aes_ecb);
	EXPECT_EQ(aes_ecb, nullptr);
	zpc_aes_key_free(&aes_key);
	EXPECT_EQ(aes_key, nullptr);
}

TEST(aes_ecb, decrypt)
{
	struct zpc_aes_key *aes_key;
	struct zpc_aes_ecb *aes_ecb;
	const char *mkvp, *apqns[257];
	u8 m[64], c[64];
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
	rc = zpc_aes_ecb_alloc(&aes_ecb);
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
	rc = zpc_aes_ecb_set_key(aes_ecb, aes_key);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_ecb_decrypt(aes_ecb, m, c, 64);
	EXPECT_EQ(rc, 0);

	zpc_aes_ecb_free(&aes_ecb);
	EXPECT_EQ(aes_ecb, nullptr);
	zpc_aes_key_free(&aes_key);
	EXPECT_EQ(aes_key, nullptr);
}

TEST(aes_ecb, pc)
{
	struct zpc_aes_key *aes_key1, *aes_key2;
	struct zpc_aes_ecb *aes_ecb1, *aes_ecb2;
	const char *mkvp, *apqns[257];
	u8 m[80], c[80], key[32], m_bak[80];
	unsigned int flags;
	int rc, size, type;

	TESTLIB_ENV_AES_KEY_CHECK();
	size = testlib_env_aes_key_size();
	type = testlib_env_aes_key_type();
	flags = testlib_env_aes_key_flags();
	mkvp = testlib_env_aes_key_mkvp();
	(void)testlib_env_aes_key_apqns(apqns);

	memcpy(m_bak, m, 80);

	rc = zpc_aes_key_alloc(&aes_key1);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_key_alloc(&aes_key2);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_ecb_alloc(&aes_ecb1);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_ecb_alloc(&aes_ecb2);
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
	rc = zpc_aes_ecb_set_key(aes_ecb1, aes_key1);
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
	rc = zpc_aes_ecb_set_key(aes_ecb2, aes_key2);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_ecb_encrypt(aes_ecb1, c, m, 80);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_ecb_decrypt(aes_ecb2, m, c, 80);
	EXPECT_EQ(rc, 0);
	EXPECT_TRUE(memcmp(m, m_bak, 80) == 0);
	rc = zpc_aes_ecb_encrypt(aes_ecb2, c, m, 80);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_ecb_decrypt(aes_ecb1, m, c, 80);
	EXPECT_EQ(rc, 0);
	EXPECT_TRUE(memcmp(m, m_bak, 80) == 0);

	/* Random protected key */
	rc = zpc_aes_ecb_set_key(aes_ecb1, NULL);   /* Unset key. */
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_ecb_set_key(aes_ecb2, NULL);   /* Unset key. */
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_key_set_mkvp(aes_key1, NULL);   /* Unset apqns. */
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_key_set_size(aes_key1, size);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_key_generate(aes_key1);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_ecb_set_key(aes_ecb1, aes_key1);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_ecb_set_key(aes_ecb2, aes_key1);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_ecb_encrypt(aes_ecb1, c, m, 80);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_ecb_decrypt(aes_ecb2, m, c, 80);
	EXPECT_EQ(rc, 0);
	EXPECT_TRUE(memcmp(m, m_bak, 80) == 0);
	rc = zpc_aes_ecb_encrypt(aes_ecb2, c, m, 80);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_ecb_decrypt(aes_ecb1, m, c, 80);
	EXPECT_EQ(rc, 0);
	EXPECT_TRUE(memcmp(m, m_bak, 80) == 0);

	zpc_aes_ecb_free(&aes_ecb2);
	zpc_aes_ecb_free(&aes_ecb1);
	zpc_aes_key_free(&aes_key2);
	EXPECT_EQ(aes_key2, nullptr);
	zpc_aes_key_free(&aes_key1);
	EXPECT_EQ(aes_key1, nullptr);
}

TEST(aes_ecb, stream_inplace_kat)
{
	TESTLIB_ENV_AES_KEY_CHECK();

	size_t keylen, msglen, ctlen;
	unsigned char buf[4096];
	const char *mkvp, *apqns[257];
	struct zpc_aes_key *aes_key;
	struct zpc_aes_ecb *aes_ecb;
	unsigned int flags;
	int type, rc;

	const char *keystr = "605c4139c961b496ca5148f1bdb1bb1901f2101943a0ec10fcdc403d3b0c285a";
	const char *msgstr = "68c9885ba2be03181f65f1e04e83d6ba6880467550bcf099be26dc9d9c0af15ab02abac07c116ac862a41da90cfa604f";
	const char *ctstr = "a7603d29bbba4c77208bf2f3df9f5ec85204adce012299f2cce7b326ce78f5cf8040343dd291e8cf9f3645726368dc20";

	u8 *key = testlib_hexstr2buf(keystr, &keylen);
	ASSERT_NE(key, nullptr);
	u8 *msg = testlib_hexstr2buf(msgstr, &msglen);
	ASSERT_NE(msg, nullptr);
	u8 *ct = testlib_hexstr2buf(ctstr, &ctlen);
	ASSERT_NE(ct, nullptr);

	type = testlib_env_aes_key_type();
	flags = testlib_env_aes_key_flags();
	mkvp = testlib_env_aes_key_mkvp();
	(void)testlib_env_aes_key_apqns(apqns);

	rc = zpc_aes_key_alloc(&aes_key);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_ecb_alloc(&aes_ecb);
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

	rc = zpc_aes_ecb_set_key(aes_ecb, aes_key);
	EXPECT_EQ(rc, 0);

	/* Encrypt */
	memcpy(buf, msg, msglen);
	rc = zpc_aes_ecb_encrypt(aes_ecb, buf, buf, 16);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_ecb_encrypt(aes_ecb, buf + 16, buf + 16, msglen - 16);
	EXPECT_EQ(rc, 0);
	EXPECT_TRUE(memcmp(buf, ct, ctlen) == 0);

	/* Encrypt */
	memcpy(buf, msg, msglen);
	rc = zpc_aes_ecb_encrypt(aes_ecb, buf, buf, 32);
	rc = zpc_aes_ecb_encrypt(aes_ecb, buf + 32, buf + 32, msglen - 32);
	EXPECT_EQ(rc, 0);
	EXPECT_TRUE(memcmp(buf, ct, ctlen) == 0);

	/* Decrypt */
	memcpy(buf, ct, ctlen);
	rc = zpc_aes_ecb_decrypt(aes_ecb, buf, buf, 16);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_ecb_decrypt(aes_ecb, buf + 16, buf + 16, msglen - 16);
	EXPECT_EQ(rc, 0);
	EXPECT_TRUE(memcmp(buf, msg, msglen) == 0);

	/* Decrypt */
	memcpy(buf, ct, ctlen);
	rc = zpc_aes_ecb_decrypt(aes_ecb, buf,  buf, 32);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_ecb_decrypt(aes_ecb, buf + 32, buf + 32, msglen - 32);
	EXPECT_EQ(rc, 0);
	EXPECT_TRUE(memcmp(buf, msg, msglen) == 0);

	zpc_aes_ecb_free(&aes_ecb);
	EXPECT_EQ(aes_ecb, nullptr);
	zpc_aes_key_free(&aes_key);
	EXPECT_EQ(aes_key, nullptr);

	free(key);
	free(msg);
	free(ct);
}

TEST(aes_ecb, nist_kat)
{
	TESTLIB_ENV_AES_KEY_CHECK();
	__run_json("nist_aes_ecb.json");
}

static void __run_json(const char *json)
{
	const char *tv = json, *str;
	const char *mkvp, *apqns[257];
	struct zpc_aes_key *aes_key;
	struct zpc_aes_ecb *aes_ecb;
	unsigned int flags;
	u8 *key = NULL;
	u8 *pt = NULL, *pt_out = NULL, *ct = NULL, *ct_out = NULL;
	int rc, keysize = 0;
	size_t ptlen, ctlen, i, j, max;
	json_object *jkey, *jmsg, *jct, *jtmp, *jtestgroups, *jfile, *jkeysize, *jtests;
	json_bool b;
	int type;

	type = testlib_env_aes_key_type();
	flags = testlib_env_aes_key_flags();
	mkvp = testlib_env_aes_key_mkvp();
	(void)testlib_env_aes_key_apqns(apqns);

	rc = zpc_aes_key_alloc(&aes_key);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_ecb_alloc(&aes_ecb);
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
			b = json_object_object_get_ex(jtmp, "msg", &jmsg);
			ASSERT_TRUE(b);
			b = json_object_object_get_ex(jtmp, "ct", &jct);
			ASSERT_TRUE(b);

			str = json_object_get_string(jkey);
			ASSERT_NE(str, nullptr);
			key = testlib_hexstr2buf(str, NULL);
			ASSERT_NE(key, nullptr);
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

			rc = zpc_aes_ecb_set_key(aes_ecb, aes_key);
			EXPECT_EQ(rc, 0);

			rc = zpc_aes_ecb_decrypt(aes_ecb, pt_out, ct, ctlen);
			EXPECT_EQ(rc, 0);
			EXPECT_TRUE(memcmp(pt_out, pt, ptlen) == 0);

			rc = zpc_aes_ecb_encrypt(aes_ecb, ct_out, pt, ptlen);
			EXPECT_EQ(rc, 0);
			EXPECT_TRUE(memcmp(ct_out, ct, ctlen) == 0);

			/* Unset key. */
			rc = zpc_aes_ecb_set_key(aes_ecb, NULL);
			EXPECT_EQ(rc, 0);

			free(key); key = NULL;
			free(pt); pt = NULL;
			free(pt_out); pt_out = NULL;
			free(ct); ct = NULL;
			free(ct_out); ct_out = NULL;
		}
	}
	zpc_aes_ecb_free(&aes_ecb);
	EXPECT_EQ(aes_ecb, nullptr);
	zpc_aes_key_free(&aes_key);
	EXPECT_EQ(aes_key, nullptr);
}

TEST(aes_ecb, rederive_protected_key1)
{
	struct zpc_aes_key *aes_key1;
	struct zpc_aes_ecb *aes_ecb1, *aes_ecb2, *aes_ecb3;
	u8 m[96], c[96];
	int rc, size;

	TESTLIB_ENV_AES_KEY_CHECK();
	size = testlib_env_aes_key_size();

	rc = zpc_aes_key_alloc(&aes_key1);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_ecb_alloc(&aes_ecb1);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_ecb_alloc(&aes_ecb2);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_ecb_alloc(&aes_ecb3);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_ecb_set_key(aes_ecb1, NULL);   /* Unset key. */
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_ecb_set_key(aes_ecb2, NULL);   /* Unset key. */
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_ecb_set_key(aes_ecb3, NULL);   /* Unset key. */
	EXPECT_EQ(rc, 0);

	/* Random protected keys cannot rbe re-derived. */

	rc = zpc_aes_key_set_mkvp(aes_key1, NULL);   /* Unset apqns. */
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_key_set_size(aes_key1, size);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_key_generate(aes_key1);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_ecb_set_key(aes_ecb1, aes_key1);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_ecb_set_key(aes_ecb2, aes_key1);
	EXPECT_EQ(rc, 0);
	memset(aes_ecb2->param.protkey, 0, sizeof(aes_ecb2->param.protkey));
	rc = zpc_aes_ecb_encrypt(aes_ecb2, c, m, 96);
	EXPECT_EQ(rc, ZPC_ERROR_PROTKEYONLY);

	rc = zpc_aes_ecb_set_key(aes_ecb3, aes_key1);
	EXPECT_EQ(rc, 0);
	memset(aes_ecb3->param.protkey, 0, sizeof(aes_ecb3->param.protkey));
	rc = zpc_aes_ecb_decrypt(aes_ecb3, m, c, 96);
	EXPECT_EQ(rc, ZPC_ERROR_PROTKEYONLY);

	zpc_aes_ecb_free(&aes_ecb3);
	zpc_aes_ecb_free(&aes_ecb2);
	zpc_aes_ecb_free(&aes_ecb1);
	zpc_aes_key_free(&aes_key1);
	EXPECT_EQ(aes_ecb3, nullptr);
	EXPECT_EQ(aes_ecb2, nullptr);
	EXPECT_EQ(aes_ecb1, nullptr);
	EXPECT_EQ(aes_key1, nullptr);
}

TEST(aes_ecb, rederive_protected_key2)
{
	TESTLIB_ENV_AES_KEY_CHECK();

	size_t keylen, msglen, ctlen;
	unsigned char buf[4096];
	const char *mkvp, *apqns[257];
	struct zpc_aes_key *aes_key;
	struct zpc_aes_ecb *aes_ecb;
	unsigned int flags;
	int type, rc;

	const char *keystr = "605c4139c961b496ca5148f1bdb1bb1901f2101943a0ec10fcdc403d3b0c285a";
	const char *msgstr = "68c9885ba2be03181f65f1e04e83d6ba6880467550bcf099be26dc9d9c0af15ab02abac07c116ac862a41da90cfa604f";
	const char *ctstr = "a7603d29bbba4c77208bf2f3df9f5ec85204adce012299f2cce7b326ce78f5cf8040343dd291e8cf9f3645726368dc20";

	u8 *key = testlib_hexstr2buf(keystr, &keylen);
	ASSERT_NE(key, nullptr);
	u8 *msg = testlib_hexstr2buf(msgstr, &msglen);
	ASSERT_NE(msg, nullptr);
	u8 *ct = testlib_hexstr2buf(ctstr, &ctlen);
	ASSERT_NE(ct, nullptr);

	type = testlib_env_aes_key_type();
	flags = testlib_env_aes_key_flags();
	mkvp = testlib_env_aes_key_mkvp();
	(void)testlib_env_aes_key_apqns(apqns);

	rc = zpc_aes_key_alloc(&aes_key);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_ecb_alloc(&aes_ecb);
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

	rc = zpc_aes_ecb_set_key(aes_ecb, aes_key);
	EXPECT_EQ(rc, 0);

	memset(aes_ecb->param.protkey, 0, sizeof(aes_ecb->param.protkey));    /* force WKaVP mismatch */
	rc = zpc_aes_ecb_encrypt(aes_ecb, buf, buf, 16);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_ecb_encrypt(aes_ecb, buf + 16, buf + 16, msglen - 16);
	EXPECT_EQ(rc, 0);

	EXPECT_TRUE(memcmp(buf, ct, ctlen) == 0);

	/* Encrypt */
	memcpy(buf, msg, msglen);

	rc = zpc_aes_ecb_set_key(aes_ecb, aes_key);
	EXPECT_EQ(rc, 0);

	memset(aes_ecb->param.protkey, 0, sizeof(aes_ecb->param.protkey));    /* force WKaVP mismatch */
	rc = zpc_aes_ecb_encrypt(aes_ecb, buf,  buf, 16);
	EXPECT_EQ(rc, 0);
	memset(aes_ecb->param.protkey, 0, sizeof(aes_ecb->param.protkey));    /* force WKaVP mismatch */
	rc = zpc_aes_ecb_encrypt(aes_ecb, buf + 16, buf + 16, msglen - 16);
	EXPECT_EQ(rc, 0);

	EXPECT_TRUE(memcmp(buf, ct, ctlen) == 0);

	/* Decrypt */
	memcpy(buf, ct, ctlen);

	memset(aes_ecb->param.protkey, 0, sizeof(aes_ecb->param.protkey));    /* force WKaVP mismatch */
	rc = zpc_aes_ecb_decrypt(aes_ecb, buf, buf, 16);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_ecb_decrypt(aes_ecb, buf + 16, buf + 16, msglen - 16);
	EXPECT_EQ(rc, 0);

	EXPECT_TRUE(memcmp(buf, msg, msglen) == 0);

	/* Decrypt */
	memcpy(buf, ct, ctlen);

	memset(aes_ecb->param.protkey, 0, sizeof(aes_ecb->param.protkey));    /* force WKaVP mismatch */
	rc = zpc_aes_ecb_decrypt(aes_ecb, buf, buf, 16);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_ecb_decrypt(aes_ecb, buf + 16, buf + 16, msglen - 16);
	EXPECT_EQ(rc, 0);

	EXPECT_TRUE(memcmp(buf, msg, msglen) == 0);

	zpc_aes_ecb_free(&aes_ecb);
	EXPECT_EQ(aes_ecb, nullptr);
	zpc_aes_key_free(&aes_key);
	EXPECT_EQ(aes_key, nullptr);

	free(key);
	free(msg);
	free(ct);
}

TEST(aes_ecb, reencipher)
{
	TESTLIB_ENV_AES_KEY_CHECK();

	size_t keylen, msglen, ctlen;
	unsigned char buf[4096];
	const char *mkvp, *apqns[257];
	struct zpc_aes_key *aes_key;
	struct zpc_aes_ecb *aes_ecb;
	unsigned int flags;
	int type, rc;

	const char *keystr = "605c4139c961b496ca5148f1bdb1bb1901f2101943a0ec10fcdc403d3b0c285a";
	const char *msgstr = "68c9885ba2be03181f65f1e04e83d6ba6880467550bcf099be26dc9d9c0af15ab02abac07c116ac862a41da90cfa604f";
	const char *ctstr = "a7603d29bbba4c77208bf2f3df9f5ec85204adce012299f2cce7b326ce78f5cf8040343dd291e8cf9f3645726368dc20";

	u8 *key = testlib_hexstr2buf(keystr, &keylen);
	ASSERT_NE(key, nullptr);
	u8 *msg = testlib_hexstr2buf(msgstr, &msglen);
	ASSERT_NE(msg, nullptr);
	u8 *ct = testlib_hexstr2buf(ctstr, &ctlen);
	ASSERT_NE(ct, nullptr);

	type = testlib_env_aes_key_type();
	flags = testlib_env_aes_key_flags();
	mkvp = testlib_env_aes_key_mkvp();
	(void)testlib_env_aes_key_apqns(apqns);

	rc = zpc_aes_key_alloc(&aes_key);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_ecb_alloc(&aes_ecb);
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

	rc = zpc_aes_ecb_set_key(aes_ecb, aes_key);
	EXPECT_EQ(rc, 0);

	memset(&aes_key->prot, 0, sizeof(aes_key->prot));    /* destroy cached protected key */
	memset(aes_ecb->param.protkey, 0, sizeof(aes_ecb->param.protkey));    /* force WKaVP mismatch */
	rc = zpc_aes_ecb_encrypt(aes_ecb, buf, buf, 16);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_ecb_encrypt(aes_ecb, buf + 16, buf + 16, msglen - 16);
	EXPECT_EQ(rc, 0);

	EXPECT_TRUE(memcmp(buf, ct, ctlen) == 0);

	/* Encrypt */
	memcpy(buf, msg, msglen);

	rc = zpc_aes_ecb_set_key(aes_ecb, aes_key);
	EXPECT_EQ(rc, 0);

	memset(&aes_key->prot, 0, sizeof(aes_key->prot));    /* destroy cached protected key */
	memset(aes_ecb->param.protkey, 0, sizeof(aes_ecb->param.protkey));    /* force WKaVP mismatch */
	rc = zpc_aes_ecb_encrypt(aes_ecb, buf, buf, 16);
	EXPECT_EQ(rc, 0);
	memset(&aes_key->prot, 0, sizeof(aes_key->prot));    /* destroy cached protected key */
	memset(aes_ecb->param.protkey, 0, sizeof(aes_ecb->param.protkey));    /* force WKaVP mismatch */
	rc = zpc_aes_ecb_encrypt(aes_ecb, buf + 16, buf + 16, msglen - 16);
	EXPECT_EQ(rc, 0);

	EXPECT_TRUE(memcmp(buf, ct, ctlen) == 0);

	/* Decrypt */
	memcpy(buf, ct, ctlen);

	memset(&aes_key->prot, 0, sizeof(aes_key->prot));    /* destroy cached protected key */
	memset(aes_ecb->param.protkey, 0, sizeof(aes_ecb->param.protkey));    /* force WKaVP mismatch */
	rc = zpc_aes_ecb_decrypt(aes_ecb, buf, buf, 16);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_ecb_decrypt(aes_ecb, buf + 16, buf + 16, msglen - 16);
	EXPECT_EQ(rc, 0);

	EXPECT_TRUE(memcmp(buf, msg, msglen) == 0);

	/* Decrypt */
	memcpy(buf, ct, ctlen);

	memset(&aes_key->prot, 0, sizeof(aes_key->prot));    /* destroy cached protected key */
	memset(aes_ecb->param.protkey, 0, sizeof(aes_ecb->param.protkey));    /* force WKaVP mismatch */
	rc = zpc_aes_ecb_decrypt(aes_ecb, buf, buf, 16);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_ecb_decrypt(aes_ecb, buf + 16, buf + 16, msglen - 16);
	EXPECT_EQ(rc, 0);

	EXPECT_TRUE(memcmp(buf, msg, msglen) == 0);

	zpc_aes_ecb_free(&aes_ecb);
	EXPECT_EQ(aes_ecb, nullptr);
	zpc_aes_key_free(&aes_key);
	EXPECT_EQ(aes_key, nullptr);

	free(key);
	free(msg);
	free(ct);
}

static void
__task(struct zpc_aes_key *aes_key)
{
	struct zpc_aes_ecb *aes_ecb;
	unsigned char buf[4096];
	size_t msglen, ctlen;
	int rc, i;

	const char *msgstr = "68c9885ba2be03181f65f1e04e83d6ba6880467550bcf099be26dc9d9c0af15ab02abac07c116ac862a41da90cfa604f";
	const char *ctstr = "a7603d29bbba4c77208bf2f3df9f5ec85204adce012299f2cce7b326ce78f5cf8040343dd291e8cf9f3645726368dc20";

	u8 *msg = testlib_hexstr2buf(msgstr, &msglen);
	ASSERT_NE(msg, nullptr);
	u8 *ct = testlib_hexstr2buf(ctstr, &ctlen);
	ASSERT_NE(ct, nullptr);

	rc = zpc_aes_ecb_alloc(&aes_ecb);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_ecb_set_key(aes_ecb, aes_key);
	EXPECT_EQ(rc, 0);

	for (i = 0; i < 1000; i++) {
		/* Encrypt */
		memcpy(buf, msg, msglen);

		memset(aes_ecb->param.protkey, 0, sizeof(aes_ecb->param.protkey));    /* force WKaVP mismatch */
		rc = zpc_aes_ecb_encrypt(aes_ecb, buf, buf, 16);
		EXPECT_EQ(rc, 0);
		rc = zpc_aes_ecb_encrypt(aes_ecb, buf + 16, buf + 16, msglen - 16);
		EXPECT_EQ(rc, 0);

		EXPECT_TRUE(memcmp(buf, ct, ctlen) == 0);

		/* Decrypt */
		memcpy(buf, ct, ctlen);

		memset(aes_ecb->param.protkey, 0, sizeof(aes_ecb->param.protkey));    /* force WKaVP mismatch */
		rc = zpc_aes_ecb_decrypt(aes_ecb, buf, buf, 16);
		EXPECT_EQ(rc, 0);
		rc = zpc_aes_ecb_decrypt(aes_ecb, buf + 16, buf + 16, msglen - 16);
		EXPECT_EQ(rc, 0);

		EXPECT_TRUE(memcmp(buf, msg, msglen) == 0);
	}

	zpc_aes_ecb_free(&aes_ecb);
	EXPECT_EQ(aes_ecb, nullptr);

	free(msg);
	free(ct);
}

TEST(aes_ecb, threads)
{
	TESTLIB_ENV_AES_KEY_CHECK();

	size_t keylen;
	const char *mkvp, *apqns[257];
	struct zpc_aes_key *aes_key;
	unsigned int flags;
	int type, rc, i;
	std::thread *t[500];

	const char *keystr = "605c4139c961b496ca5148f1bdb1bb1901f2101943a0ec10fcdc403d3b0c285a";

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
