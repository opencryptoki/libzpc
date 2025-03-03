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

#include "zpc/hmac.h"
#include "zpc/error.h"

#include "hmac_key_local.h"  /* de-opaquify struct zpc_hmac_key */
#include "hmac_local.h"  /* de-opaquify struct zpc_hmac */


const int hfunc2tagsize[] {
	28, 32, 48, 64,
};

const int hfunc2keysize[] {
	512, 512, 1024, 1024,
};

const int hfunc2blksize[] {
	64, 64, 128, 128,
};

/* Offset to protkey array in struct cpacf_kmac_hmac_param */
const int hfunc2protkeyoffset[] {
	40, 40, 80, 80,
};

const int hfunc2protkeysize[] {
	96, 96, 160, 160,
};

static void __run_json(const char *json, zpc_hmac_hashfunc_t hfunc);

TEST(hmac, alloc)
{
	struct zpc_hmac *hmac;
	int rc;

	TESTLIB_ENV_HMAC_KEY_CHECK();

	TESTLIB_HMAC_HW_CAPS_CHECK();

	rc = zpc_hmac_alloc(NULL);
	EXPECT_EQ(rc, ZPC_ERROR_ARG1NULL);

	hmac = NULL;
	rc = zpc_hmac_alloc(&hmac);
	EXPECT_EQ(rc, 0);
	zpc_hmac_free(&hmac);
	EXPECT_EQ(hmac, nullptr);

	hmac = (struct zpc_hmac *)&hmac;
	rc = zpc_hmac_alloc(&hmac);
	EXPECT_EQ(rc, 0);
	zpc_hmac_free(&hmac);
	EXPECT_EQ(hmac, nullptr);
}

TEST(hmac, free)
{
	struct zpc_hmac *hmac;
	int rc;

	TESTLIB_ENV_HMAC_KEY_CHECK();

	TESTLIB_HMAC_HW_CAPS_CHECK();

	zpc_hmac_free(NULL);

	hmac = NULL;
	zpc_hmac_free(&hmac);
	EXPECT_EQ(hmac, nullptr);

	rc = zpc_hmac_alloc(&hmac);
	EXPECT_EQ(rc, 0);
	zpc_hmac_free(&hmac);
	EXPECT_EQ(hmac, nullptr);
}

TEST(hmac, set_key)
{
	struct zpc_hmac_key *hmac_key1, *hmac_key2;
	struct zpc_hmac *hmac;
	u8 clearkey[32];
	int rc, type;
	zpc_hmac_hashfunc_t hfunc;

	TESTLIB_ENV_HMAC_KEY_CHECK();

	TESTLIB_HMAC_HW_CAPS_CHECK();

	type = testlib_env_hmac_key_type();
	hfunc = testlib_env_hmac_hashfunc();

	TESTLIB_HMAC_KERNEL_CAPS_CHECK();

	TESTLIB_HMAC_SW_CAPS_CHECK(type);

	rc = zpc_hmac_key_alloc(&hmac_key1);
	EXPECT_EQ(rc, 0);
	rc = zpc_hmac_key_alloc(&hmac_key2);
	EXPECT_EQ(rc, 0);
	rc = zpc_hmac_alloc(&hmac);
	EXPECT_EQ(rc, 0);

	rc = zpc_hmac_set_key(NULL, NULL);
	EXPECT_EQ(rc, ZPC_ERROR_ARG1NULL);
	rc = zpc_hmac_set_key(NULL, hmac_key1);
	EXPECT_EQ(rc, ZPC_ERROR_ARG1NULL);
	rc = zpc_hmac_set_key(hmac, NULL);
	EXPECT_EQ(rc, 0);

	rc = zpc_hmac_set_key(hmac, hmac_key1);
	EXPECT_EQ(rc, ZPC_ERROR_KEYNOTSET);

	/* key1 has type pvsecret, so set key from pvsecret is possible */
	rc = zpc_hmac_key_set_type(hmac_key1, type);
	EXPECT_EQ(rc, 0);
	rc = zpc_hmac_key_set_hash_function(hmac_key1, hfunc);
	EXPECT_EQ(rc, 0);
	rc = testlib_set_hmac_key_from_pvsecret(hmac_key1, hfunc2keysize[hfunc]);
	if (rc)
		goto ret;
	rc = zpc_hmac_set_key(hmac, hmac_key1);
	EXPECT_EQ(rc, 0);

	rc = zpc_hmac_set_key(hmac, NULL); /* Unset key. */
	EXPECT_EQ(rc, 0);

	/* key2 has no type, so set key from imported clearkey is possible */
	rc = zpc_hmac_key_set_hash_function(hmac_key2, hfunc);
	EXPECT_EQ(rc, 0);
	rc = zpc_hmac_key_import_clear(hmac_key2, clearkey, sizeof(clearkey));
	EXPECT_EQ(rc, 0);
	rc = zpc_hmac_set_key(hmac, hmac_key2);
	EXPECT_EQ(rc, 0);

ret:
	zpc_hmac_free(&hmac);
	EXPECT_EQ(hmac, nullptr);
	zpc_hmac_key_free(&hmac_key1);
	EXPECT_EQ(hmac_key1, nullptr);
	zpc_hmac_key_free(&hmac_key2);
	EXPECT_EQ(hmac_key2, nullptr);
}

TEST(hmac, sign)
{
	struct zpc_hmac_key *hmac_key1, *hmac_key2;
	struct zpc_hmac *hmac;
	u8  m[99], tag[64];
	int rc, type;
	zpc_hmac_hashfunc_t hfunc;

	TESTLIB_ENV_HMAC_KEY_CHECK();

	TESTLIB_HMAC_HW_CAPS_CHECK();

	type = testlib_env_hmac_key_type();
	hfunc = testlib_env_hmac_hashfunc();

	TESTLIB_HMAC_KERNEL_CAPS_CHECK();

	TESTLIB_HMAC_SW_CAPS_CHECK(type);

	rc = zpc_hmac_key_alloc(&hmac_key1);
	EXPECT_EQ(rc, 0);
	rc = zpc_hmac_key_alloc(&hmac_key2);
	EXPECT_EQ(rc, 0);
	rc = zpc_hmac_alloc(&hmac);
	EXPECT_EQ(rc, 0);

	/* Generate HMAC key1 via sysfs attributes (don't set a type here) */
	rc = zpc_hmac_key_set_hash_function(hmac_key1, hfunc);
	EXPECT_EQ(rc, 0);
	rc = zpc_hmac_key_generate(hmac_key1);
	EXPECT_EQ(rc, 0);
	rc = zpc_hmac_set_key(hmac, hmac_key1);
	EXPECT_EQ(rc, 0);
	rc = zpc_hmac_sign(hmac, tag, hfunc2tagsize[hfunc], m, 99);
	EXPECT_EQ(rc, 0);

	/* Create HMAC key2 from pvsecret */
	rc = zpc_hmac_key_set_type(hmac_key2, type);
	EXPECT_EQ(rc, 0);
	rc = zpc_hmac_key_set_hash_function(hmac_key2, hfunc);
	EXPECT_EQ(rc, 0);
	rc = testlib_set_hmac_key_from_pvsecret(hmac_key2, hfunc2keysize[hfunc]);
	if (rc)
		goto ret;
	rc = zpc_hmac_set_key(hmac, hmac_key2);
	EXPECT_EQ(rc, 0);
	rc = zpc_hmac_sign(hmac, tag, hfunc2tagsize[hfunc], m, 99);
	EXPECT_EQ(rc, 0);

ret:
	zpc_hmac_free(&hmac);
	EXPECT_EQ(hmac, nullptr);
	zpc_hmac_key_free(&hmac_key1);
	EXPECT_EQ(hmac_key1, nullptr);
	zpc_hmac_key_free(&hmac_key2);
	EXPECT_EQ(hmac_key2, nullptr);
}

TEST(hmac, verify)
{
	struct zpc_hmac_key *hmac_key1, *hmac_key2;
	struct zpc_hmac *hmac;
	u8 m[99], tag[64] = { 0, };
	int rc, type;
	zpc_hmac_hashfunc_t hfunc;

	TESTLIB_ENV_HMAC_KEY_CHECK();

	TESTLIB_HMAC_HW_CAPS_CHECK();

	type = testlib_env_hmac_key_type();
	hfunc = testlib_env_hmac_hashfunc();

	TESTLIB_HMAC_KERNEL_CAPS_CHECK();

	TESTLIB_HMAC_SW_CAPS_CHECK(type);

	rc = zpc_hmac_key_alloc(&hmac_key1);
	EXPECT_EQ(rc, 0);
	rc = zpc_hmac_key_alloc(&hmac_key2);
	EXPECT_EQ(rc, 0);
	rc = zpc_hmac_alloc(&hmac);
	EXPECT_EQ(rc, 0);

	/* Generate HMAC key1 via sysfs attributes (don't set a type here) */
	rc = zpc_hmac_key_set_hash_function(hmac_key1, hfunc);
	EXPECT_EQ(rc, 0);
	rc = zpc_hmac_key_generate(hmac_key1);
	EXPECT_EQ(rc, 0);
	rc = zpc_hmac_set_key(hmac, hmac_key1);
	EXPECT_EQ(rc, 0);
	rc = zpc_hmac_verify(hmac, tag, hfunc2tagsize[hfunc], m, 99);
	EXPECT_EQ(rc, ZPC_ERROR_TAGMISMATCH);

	/* Create HMAC key2 from pvsecret */
	rc = zpc_hmac_key_set_type(hmac_key2, type);
	EXPECT_EQ(rc, 0);
	rc = zpc_hmac_key_set_hash_function(hmac_key2, hfunc);
	EXPECT_EQ(rc, 0);
	rc = testlib_set_hmac_key_from_pvsecret(hmac_key2, hfunc2keysize[hfunc]);
	if (rc)
		goto ret;
	rc = zpc_hmac_set_key(hmac, hmac_key2);
	EXPECT_EQ(rc, 0);
	rc = zpc_hmac_verify(hmac, tag, hfunc2tagsize[hfunc], m, 99);
	EXPECT_EQ(rc, ZPC_ERROR_TAGMISMATCH);

ret:
	zpc_hmac_free(&hmac);
	EXPECT_EQ(hmac, nullptr);
	zpc_hmac_key_free(&hmac_key1);
	EXPECT_EQ(hmac_key1, nullptr);
	zpc_hmac_key_free(&hmac_key2);
	EXPECT_EQ(hmac_key2, nullptr);
}

TEST(hmac, pc)
{
	struct zpc_hmac_key *hmac_key1, *hmac_key2, *hmac_key3;
	struct zpc_hmac *hmac1, *hmac2;
	u8 m[99], tag[64];
	int rc, type;
	zpc_hmac_hashfunc_t hfunc;

	TESTLIB_ENV_HMAC_KEY_CHECK();

	TESTLIB_HMAC_HW_CAPS_CHECK();

	type = testlib_env_hmac_key_type();
	hfunc = testlib_env_hmac_hashfunc();

	TESTLIB_HMAC_KERNEL_CAPS_CHECK();

	TESTLIB_HMAC_SW_CAPS_CHECK(type);

	rc = zpc_hmac_key_alloc(&hmac_key1);
	EXPECT_EQ(rc, 0);
	rc = zpc_hmac_key_alloc(&hmac_key2);
	EXPECT_EQ(rc, 0);
	rc = zpc_hmac_key_alloc(&hmac_key3);
	EXPECT_EQ(rc, 0);
	rc = zpc_hmac_alloc(&hmac1);
	EXPECT_EQ(rc, 0);
	rc = zpc_hmac_alloc(&hmac2);
	EXPECT_EQ(rc, 0);

	/* Create key1 from pvsecret */
	rc = zpc_hmac_key_set_type(hmac_key1, type);
	EXPECT_EQ(rc, 0);
	rc = zpc_hmac_key_set_hash_function(hmac_key1, hfunc);
	EXPECT_EQ(rc, 0);
	rc = testlib_set_hmac_key_from_pvsecret(hmac_key1, hfunc2keysize[hfunc]);
	if (rc)
		goto ret;
	rc = zpc_hmac_set_key(hmac1, hmac_key1);
	EXPECT_EQ(rc, 0);

	/* Create key2 from same pvsecret */
	rc = zpc_hmac_key_set_type(hmac_key2, type);
	EXPECT_EQ(rc, 0);
	rc = zpc_hmac_key_set_hash_function(hmac_key2, hfunc);
	EXPECT_EQ(rc, 0);
	rc = testlib_set_hmac_key_from_pvsecret(hmac_key2, hfunc2keysize[hfunc]);
	if (rc)
		goto ret;
	rc = zpc_hmac_set_key(hmac2, hmac_key2);
	EXPECT_EQ(rc, 0);

	/* Sign with context 1, verify with context 2 and vice versa */
	rc = zpc_hmac_sign(hmac1, tag, hfunc2tagsize[hfunc], m, 99);
	EXPECT_EQ(rc, 0);
	rc = zpc_hmac_verify(hmac2, tag, hfunc2tagsize[hfunc], m, 99);
	EXPECT_EQ(rc, 0);
	rc = zpc_hmac_sign(hmac2, tag, hfunc2tagsize[hfunc], m, 99);
	EXPECT_EQ(rc, 0);
	rc = zpc_hmac_verify(hmac1, tag, hfunc2tagsize[hfunc], m, 99);
	EXPECT_EQ(rc, 0);

	/* Sign and then corrupt the tag */
	rc = zpc_hmac_sign(hmac2, tag, hfunc2tagsize[hfunc], m, 99);
	EXPECT_EQ(rc, 0);
	tag[0] ^= 1;
	rc = zpc_hmac_verify(hmac1, tag, hfunc2tagsize[hfunc], m, 99);
	EXPECT_EQ(rc, ZPC_ERROR_TAGMISMATCH);
	rc = zpc_hmac_sign(hmac1, tag, hfunc2tagsize[hfunc], m, 99);
	EXPECT_EQ(rc, 0);
	tag[0] ^= 1;
	rc = zpc_hmac_verify(hmac2, tag, hfunc2tagsize[hfunc], m, 99);
	EXPECT_EQ(rc, ZPC_ERROR_TAGMISMATCH);

	/* Create random protected key */
	rc = zpc_hmac_set_key(hmac1, NULL); /* Unset key. */
	EXPECT_EQ(rc, 0);
	rc = zpc_hmac_set_key(hmac2, NULL); /* Unset key. */
	EXPECT_EQ(rc, 0);

	rc = zpc_hmac_key_set_hash_function(hmac_key3, hfunc);
	EXPECT_EQ(rc, 0);
	rc = zpc_hmac_key_generate(hmac_key3);
	EXPECT_EQ(rc, 0);

	rc = zpc_hmac_set_key(hmac1, hmac_key3);
	EXPECT_EQ(rc, 0);
	rc = zpc_hmac_set_key(hmac2, hmac_key3);
	EXPECT_EQ(rc, 0);

	/* Sign with context 1, verify with context 2 and vice versa */
	rc = zpc_hmac_sign(hmac1, tag, hfunc2tagsize[hfunc], m, 99);
	EXPECT_EQ(rc, 0);
	rc = zpc_hmac_verify(hmac2, tag, hfunc2tagsize[hfunc], m, 99);
	EXPECT_EQ(rc, 0);
	rc = zpc_hmac_sign(hmac2, tag, hfunc2tagsize[hfunc], m, 99);
	EXPECT_EQ(rc, 0);
	rc = zpc_hmac_verify(hmac1, tag, hfunc2tagsize[hfunc], m, 99);
	EXPECT_EQ(rc, 0);

	/* Sign and then corrupt the tag */
	rc = zpc_hmac_sign(hmac2, tag, hfunc2tagsize[hfunc], m, 99);
	EXPECT_EQ(rc, 0);
	tag[0] ^= 1;
	rc = zpc_hmac_verify(hmac1, tag, hfunc2tagsize[hfunc], m, 99);
	EXPECT_EQ(rc, ZPC_ERROR_TAGMISMATCH);
	rc = zpc_hmac_sign(hmac1, tag, hfunc2tagsize[hfunc], m, 99);
	EXPECT_EQ(rc, 0);
	tag[0] ^= 1;
	rc = zpc_hmac_verify(hmac2, tag, hfunc2tagsize[hfunc], m, 99);
	EXPECT_EQ(rc, ZPC_ERROR_TAGMISMATCH);

ret:
	zpc_hmac_free(&hmac2);
	zpc_hmac_free(&hmac1);
	zpc_hmac_key_free(&hmac_key1);
	EXPECT_EQ(hmac_key1, nullptr);
	zpc_hmac_key_free(&hmac_key2);
	EXPECT_EQ(hmac_key2, nullptr);
	zpc_hmac_key_free(&hmac_key3);
	EXPECT_EQ(hmac_key3, nullptr);
}

TEST(hmac, stream_inplace_kat1)
{
	size_t keylen, msglen, taglen;
	unsigned char mac[64];
	struct zpc_hmac_key *hmac_key;
	struct zpc_hmac *hmac;
	int rc;

	const char *keystr =
		"82314540564ea3ce30591e97f68b2602de40fa29f773c2508327471b8348e8c4";
	const char *msgstr =
		"6a6d2f45cebf2757ae16ea33c68617671d77f8fdf80bed8fc5cdc5c8b7086bd2"
		"8e7eb3eecc7163491104e5309455e67f836579b82a1da3bf5991a8e2b2f189a4"
		"9e05700e46c409ed5de77780a5f389e3f13dad406c9d55675329c5c921f07034"
		"180937c0f6ef34a2308b6ff3e1a0e9dc1ea65f5632730e8744d1db2c40a6595b";
	const char *tagstr =
		"0900b3e6535d34f90e2c335775e86bf38ee7e3d26fb60cd9cdf639eb3496b94c";

	TESTLIB_ENV_HMAC_KEY_CHECK();

	TESTLIB_HMAC_HW_CAPS_CHECK();

	TESTLIB_HMAC_KERNEL_CAPS_CHECK();

	u8 *key = testlib_hexstr2buf(keystr, &keylen);
	ASSERT_NE(key, nullptr);
	u8 *msg = testlib_hexstr2buf(msgstr, &msglen);
	ASSERT_NE(msg, nullptr);
	u8 *tag = testlib_hexstr2buf(tagstr, &taglen);
	ASSERT_NE(tag, nullptr);

	rc = zpc_hmac_key_alloc(&hmac_key);
	EXPECT_EQ(rc, 0);
	rc = zpc_hmac_alloc(&hmac);
	EXPECT_EQ(rc, 0);

	/* This test uses a key with length equal to the blocksize of the hash function */
	rc = zpc_hmac_key_set_hash_function(hmac_key, ZPC_HMAC_HASHFUNC_SHA_256);
	EXPECT_EQ(rc, 0);
	rc = zpc_hmac_key_import_clear(hmac_key, key, keylen);
	EXPECT_EQ(rc, 0);
	rc = zpc_hmac_set_key(hmac, hmac_key);
	EXPECT_EQ(rc, 0);

	/* Sign in multiple steps */
	rc = zpc_hmac_sign(hmac, NULL, 0, msg, 64);
	EXPECT_EQ(rc, 0);
	rc = zpc_hmac_sign(hmac, NULL, 0, msg + 64, 64);
	EXPECT_EQ(rc, 0);
	rc = zpc_hmac_sign(hmac, mac, taglen, msg + 64 + 64, msglen - 64 - 64);
	EXPECT_EQ(rc, 0);
	EXPECT_TRUE(memcmp(mac, tag, taglen) == 0);

	/* Sign in 1 step */
	rc = zpc_hmac_sign(hmac, mac, taglen, msg, msglen);
	EXPECT_EQ(rc, 0);
	EXPECT_TRUE(memcmp(mac, tag, taglen) == 0);

	/* Verify in multiple steps */
	rc = zpc_hmac_verify(hmac, NULL, 0, msg, 64);
	EXPECT_EQ(rc, 0);
	rc = zpc_hmac_verify(hmac, NULL, 0, NULL, 0);
	EXPECT_EQ(rc, 0);
	rc = zpc_hmac_verify(hmac, NULL, 0, NULL, 0);
	EXPECT_EQ(rc, 0);
	rc = zpc_hmac_verify(hmac, tag, taglen, msg + 64, msglen - 64);
	EXPECT_EQ(rc, 0);

	/* Verify in 1 step */
	rc = zpc_hmac_verify(hmac, tag, taglen, msg, msglen);
	EXPECT_EQ(rc, 0);

	zpc_hmac_free(&hmac);
	EXPECT_EQ(hmac, nullptr);
	zpc_hmac_key_free(&hmac_key);
	EXPECT_EQ(hmac_key, nullptr);

	free(key);
	free(msg);
	free(tag);
}

TEST(hmac, stream_inplace_kat2)
{
	size_t keylen, msglen, taglen;
	unsigned char mac[64];
	struct zpc_hmac_key *hmac_key;
	struct zpc_hmac *hmac;
	int rc;

	const char *keystr =
		"b36d3d47a4585b401fc64c98eff56243d4da78863063d814e88f370b92576406d4"
		"47fcf3d129a1ede57ddc56ea3a0a1f100105a95e83138cdf45ecf2a5992acf90";
	const char *msgstr =
		"15c75a64b04d097af2371af380079eb8";
	const char *tagstr =
		"4ecb2daa5fb08dbd836e92a51e200bb230f54ac2c9778f5226b3abc9";

	TESTLIB_ENV_HMAC_KEY_CHECK();

	TESTLIB_HMAC_HW_CAPS_CHECK();

	TESTLIB_HMAC_KERNEL_CAPS_CHECK();

	u8 *key = testlib_hexstr2buf(keystr, &keylen);
	ASSERT_NE(key, nullptr);
	u8 *msg = testlib_hexstr2buf(msgstr, &msglen);
	ASSERT_NE(msg, nullptr);
	u8 *tag = testlib_hexstr2buf(tagstr, &taglen);
	ASSERT_NE(tag, nullptr);

	rc = zpc_hmac_key_alloc(&hmac_key);
	EXPECT_EQ(rc, 0);
	rc = zpc_hmac_alloc(&hmac);
	EXPECT_EQ(rc, 0);

	/* This test uses a key longer than the blocksize of the hash function */
	rc = zpc_hmac_key_set_hash_function(hmac_key, ZPC_HMAC_HASHFUNC_SHA_224);
	EXPECT_EQ(rc, 0);
	rc = zpc_hmac_key_import_clear(hmac_key, key, keylen);
	EXPECT_EQ(rc, 0);
	rc = zpc_hmac_set_key(hmac, hmac_key);
	EXPECT_EQ(rc, 0);

	/* Sign */
	rc = zpc_hmac_sign(hmac, mac, taglen, msg, msglen);
	EXPECT_EQ(rc, 0);
	EXPECT_TRUE(memcmp(mac, tag, taglen) == 0);

	/* Verify */
	rc = zpc_hmac_verify(hmac, tag, taglen, msg, msglen);
	EXPECT_EQ(rc, 0);

	zpc_hmac_free(&hmac);
	EXPECT_EQ(hmac, nullptr);
	zpc_hmac_key_free(&hmac_key);
	EXPECT_EQ(hmac_key, nullptr);

	free(key);
	free(msg);
	free(tag);
}

/*
 * This test assumes that the tester manually added the clear HMAC key
 * to the pvsecret list file, for example:
 *
 * 7 HMAC-SHA-256-KEY:
 *  0xb620b6d76f899 ...   <- secret ID
 *  0xa783830e0bd6f3ae ...   <- clear HMAC key
 * 8 HMAC-SHA-512-KEY:
 *  ...
 *
 * The test creates one HMAC key from given pvsecret ID and a second HMAC
 * key from the given clear key value to compare results.
 */
TEST(hmac, pvsecret_kat)
{
	struct zpc_hmac_key *hmac_key1, *hmac_key2;
	struct zpc_hmac *ctx1, *ctx2;
	u8 m[99], mac1[64], mac2[64];
	int type, rc;
	zpc_hmac_hashfunc_t hfunc;

	TESTLIB_ENV_HMAC_KEY_CHECK();

	TESTLIB_HMAC_HW_CAPS_CHECK();

	hfunc = testlib_env_hmac_hashfunc();
	type = testlib_env_hmac_key_type();

	if (type != ZPC_HMAC_KEY_TYPE_PVSECRET) {
		GTEST_SKIP_("Skipping pvsecret_kat test. Only applicable for PVSECRET type keys.");
	}

	TESTLIB_HMAC_KERNEL_CAPS_CHECK();

	TESTLIB_HMAC_SW_CAPS_CHECK(type);

	rc = zpc_hmac_key_alloc(&hmac_key1);
	EXPECT_EQ(rc, 0);
	rc = zpc_hmac_key_alloc(&hmac_key2);
	EXPECT_EQ(rc, 0);
	rc = zpc_hmac_alloc(&ctx1);
	EXPECT_EQ(rc, 0);
	rc = zpc_hmac_alloc(&ctx2);
	EXPECT_EQ(rc, 0);

	/* Create a first HMAC key from pvsecret */
	rc = zpc_hmac_key_set_type(hmac_key1, type);
	EXPECT_EQ(rc, 0);
	rc = zpc_hmac_key_set_hash_function(hmac_key1, hfunc);
	EXPECT_EQ(rc, 0);
	rc = testlib_set_hmac_key_from_pvsecret(hmac_key1, hfunc2keysize[hfunc]);
	if (rc)
		goto ret;
	rc = zpc_hmac_set_key(ctx1, hmac_key1);
	EXPECT_EQ(rc, 0);

	/*
	 * Create a second HMAC key from clear key value in list file.
	 * Don't set the type here to make clear import possible
	 */
	rc = zpc_hmac_key_set_hash_function(hmac_key2, hfunc);
	EXPECT_EQ(rc, 0);
	rc = testlib_set_hmac_key_from_file(hmac_key2, type, hfunc2keysize[hfunc]);
	if (rc)
		goto ret;
	rc = zpc_hmac_set_key(ctx2, hmac_key2);
	EXPECT_EQ(rc, 0);

	/* Now calculate MACs and compare results */
	rc = zpc_hmac_sign(ctx1, mac1, hfunc2tagsize[hfunc], m, sizeof(m));
	EXPECT_EQ(rc, 0);
	rc = zpc_hmac_sign(ctx2, mac2, hfunc2tagsize[hfunc], m, sizeof(m));
	EXPECT_EQ(rc, 0);
	EXPECT_TRUE(memcmp(mac1, mac2, hfunc2tagsize[hfunc]) == 0);

	/* Now sign with first key and verify with 2nd key */
	rc = zpc_hmac_sign(ctx1, mac1, hfunc2tagsize[hfunc], m, sizeof(m));
	EXPECT_EQ(rc, 0);
	rc = zpc_hmac_verify(ctx2, mac1, hfunc2tagsize[hfunc], m, sizeof(m));
	EXPECT_EQ(rc, 0);

ret:
	zpc_hmac_free(&ctx1);
	EXPECT_EQ(ctx1, nullptr);
	zpc_hmac_free(&ctx2);
	EXPECT_EQ(ctx2, nullptr);
	zpc_hmac_key_free(&hmac_key1);
	EXPECT_EQ(hmac_key1, nullptr);
	zpc_hmac_key_free(&hmac_key2);
	EXPECT_EQ(hmac_key2, nullptr);
}

TEST(hmac, wycheproof_kat)
{
	TESTLIB_ENV_HMAC_KEY_CHECK();

	TESTLIB_HMAC_HW_CAPS_CHECK();

	TESTLIB_HMAC_KERNEL_CAPS_CHECK();

	__run_json("wycheproof/src/wycheproof/testvectors/hmac_sha224_test.json", ZPC_HMAC_HASHFUNC_SHA_224);
	__run_json("wycheproof/src/wycheproof/testvectors/hmac_sha256_test.json", ZPC_HMAC_HASHFUNC_SHA_256);
	__run_json("wycheproof/src/wycheproof/testvectors/hmac_sha384_test.json", ZPC_HMAC_HASHFUNC_SHA_384);
	__run_json("wycheproof/src/wycheproof/testvectors/hmac_sha512_test.json", ZPC_HMAC_HASHFUNC_SHA_512);
}

static void __run_json(const char *json, zpc_hmac_hashfunc_t hfunc)
{
	const char *tv = json, *str;
	struct zpc_hmac_key *hmac_key;
	struct zpc_hmac *hmac;
	u8 *key = NULL;
	u8 *pt = NULL;
	u8 *tag = NULL, *tag_out = NULL;
	int rc, tagsize = 0, keysize = 0;
	int valid = 0;
	size_t ptlen, taglen, i, j;
	json_object *jkey, *jtag, *jmsg, *jresult, *jtmp, *jtestgroups, *jfile, *jkeysize, *jtagsize, *jtests;
	json_bool b;

	rc = zpc_hmac_key_alloc(&hmac_key);
	EXPECT_EQ(rc, 0);
	rc = zpc_hmac_alloc(&hmac);
	EXPECT_EQ(rc, 0);

	/*
	 * Don't set the type (which is currently always pvsecret) here to make
	 * clear import possible.
	 */
	rc = zpc_hmac_key_set_hash_function(hmac_key, hfunc);
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

			rc = zpc_hmac_key_import_clear(hmac_key, key, keysize / 8);
			EXPECT_EQ(rc, 0);
			rc = zpc_hmac_set_key(hmac, hmac_key);
			EXPECT_EQ(rc, 0);

			rc = zpc_hmac_sign(hmac, tag_out, tagsize / 8, pt, ptlen);
			EXPECT_EQ(rc, 0);
			if (valid) {
				EXPECT_TRUE(memcmp(tag_out, tag, tagsize / 8) == 0);
			}
	
			rc = zpc_hmac_verify(hmac, tag, tagsize / 8, pt, ptlen);
			EXPECT_EQ(rc, valid ? 0 : ZPC_ERROR_TAGMISMATCH);

			/* Unset key. */
			rc = zpc_hmac_set_key(hmac, NULL);
			EXPECT_EQ(rc, 0);

			free(key); key = NULL;
			free(pt); pt = NULL;
			free(tag); tag = NULL;
			free(tag_out); tag_out = NULL;
		}
	}

	zpc_hmac_free(&hmac);
	EXPECT_EQ(hmac, nullptr);
	zpc_hmac_key_free(&hmac_key);
	EXPECT_EQ(hmac_key, nullptr);
}

TEST(hmac, rederive_protected_key1)
{
	struct zpc_hmac_key *hmac_key1;
	struct zpc_hmac *hmac1, *hmac2, *hmac3;
	u8 m[234], tag[64];
	int rc, mlen = sizeof(m);
	zpc_hmac_hashfunc_t hfunc;

	TESTLIB_ENV_HMAC_KEY_CHECK();

	TESTLIB_HMAC_HW_CAPS_CHECK();

	hfunc = testlib_env_hmac_hashfunc();

	TESTLIB_HMAC_KERNEL_CAPS_CHECK();

	rc = zpc_hmac_key_alloc(&hmac_key1);
	EXPECT_EQ(rc, 0);
	rc = zpc_hmac_alloc(&hmac1);
	EXPECT_EQ(rc, 0);
	rc = zpc_hmac_alloc(&hmac2);
	EXPECT_EQ(rc, 0);
	rc = zpc_hmac_alloc(&hmac3);
	EXPECT_EQ(rc, 0);

	rc = zpc_hmac_set_key(hmac1, NULL); /* Unset key. */
	EXPECT_EQ(rc, 0);
	rc = zpc_hmac_set_key(hmac2, NULL); /* Unset key. */
	EXPECT_EQ(rc, 0);
	rc = zpc_hmac_set_key(hmac3, NULL); /* Unset key. */
	EXPECT_EQ(rc, 0);

	/* Random protected keys cannot be re-derived. */

	rc = zpc_hmac_key_set_hash_function(hmac_key1, hfunc);
	EXPECT_EQ(rc, 0);

	rc = zpc_hmac_key_generate(hmac_key1);
	EXPECT_EQ(rc, 0);

	rc = zpc_hmac_set_key(hmac1, hmac_key1);
	EXPECT_EQ(rc, 0);
	rc = zpc_hmac_set_key(hmac2, hmac_key1);
	EXPECT_EQ(rc, 0);

	rc = zpc_hmac_sign(hmac2, NULL, 0, m, hfunc2blksize[hfunc]);
	EXPECT_EQ(rc, 0);
	memset((char *)&hmac2->param_kmac + hfunc2protkeyoffset[hfunc], 0, hfunc2protkeysize[hfunc]);
	rc = zpc_hmac_sign(hmac2, tag, hfunc2tagsize[hfunc], m + hfunc2blksize[hfunc], mlen - hfunc2blksize[hfunc]);
	EXPECT_EQ(rc, ZPC_ERROR_PROTKEYONLY);

	rc = zpc_hmac_set_key(hmac3, hmac_key1);
	EXPECT_EQ(rc, 0);

	rc = zpc_hmac_verify(hmac3, NULL, 0, m, hfunc2blksize[hfunc]);
	memset((char *)&hmac3->param_kmac + hfunc2protkeyoffset[hfunc], 0, hfunc2protkeysize[hfunc]);
	rc = zpc_hmac_verify(hmac3, tag, hfunc2tagsize[hfunc], m + hfunc2blksize[hfunc], mlen - hfunc2blksize[hfunc]);
	EXPECT_EQ(rc, ZPC_ERROR_PROTKEYONLY);

	zpc_hmac_free(&hmac3);
	zpc_hmac_free(&hmac2);
	zpc_hmac_free(&hmac1);
	zpc_hmac_key_free(&hmac_key1);
	EXPECT_EQ(hmac3, nullptr);
	EXPECT_EQ(hmac2, nullptr);
	EXPECT_EQ(hmac1, nullptr);
	EXPECT_EQ(hmac_key1, nullptr);
}

TEST(hmac, rederive_protected_key2)
{
	struct zpc_hmac_key *hmac_key;
	struct zpc_hmac *hmac;
	u8 m[234], mac[64];
	int rc, type, mlen = sizeof(m);
	zpc_hmac_hashfunc_t hfunc;

	TESTLIB_ENV_HMAC_KEY_CHECK();

	TESTLIB_HMAC_HW_CAPS_CHECK();

	type = testlib_env_hmac_key_type();
	hfunc = testlib_env_hmac_hashfunc();

	TESTLIB_HMAC_KERNEL_CAPS_CHECK();

	TESTLIB_HMAC_SW_CAPS_CHECK(type);

	rc = zpc_hmac_key_alloc(&hmac_key);
	EXPECT_EQ(rc, 0);
	rc = zpc_hmac_alloc(&hmac);
	EXPECT_EQ(rc, 0);

	rc = zpc_hmac_key_set_type(hmac_key, type);
	EXPECT_EQ(rc, 0);
	rc = zpc_hmac_key_set_hash_function(hmac_key, hfunc);
	EXPECT_EQ(rc, 0);

	/* Only pvsecret-type HMAC keys can be rederived from their ID */
	rc = testlib_set_hmac_key_from_pvsecret(hmac_key, hfunc2keysize[hfunc]);
	if (rc)
		goto ret;

	rc = zpc_hmac_set_key(hmac, hmac_key);
	EXPECT_EQ(rc, 0);

	/* Sign */
	rc = zpc_hmac_sign(hmac, NULL, 0, m, hfunc2blksize[hfunc]);
	EXPECT_EQ(rc, 0);
	memset((char *)&hmac->param_kmac + hfunc2protkeyoffset[hfunc], 0, hfunc2protkeysize[hfunc]);
	rc = zpc_hmac_sign(hmac, mac, hfunc2tagsize[hfunc], m + hfunc2blksize[hfunc], mlen - hfunc2blksize[hfunc]);
	EXPECT_EQ(rc, 0);

	/* Verify */
	rc = zpc_hmac_verify(hmac, NULL, 0, m, hfunc2blksize[hfunc]);
	EXPECT_EQ(rc, 0);
	memset((char *)&hmac->param_kmac + hfunc2protkeyoffset[hfunc], 0, hfunc2protkeysize[hfunc]);
	rc = zpc_hmac_verify(hmac, mac, hfunc2tagsize[hfunc], m + hfunc2blksize[hfunc], mlen - hfunc2blksize[hfunc]);
	EXPECT_EQ(rc, 0);

ret:
	zpc_hmac_free(&hmac);
	EXPECT_EQ(hmac, nullptr);
	zpc_hmac_key_free(&hmac_key);
	EXPECT_EQ(hmac_key, nullptr);
}

static void
__task(struct zpc_hmac_key *hmac_key)
{
	struct zpc_hmac *hmac;
	u8 m[345], mac[64];
	int mlen = sizeof(m);
	int rc, i;

	rc = zpc_hmac_alloc(&hmac);
	EXPECT_EQ(rc, 0);
	rc = zpc_hmac_set_key(hmac, hmac_key);
	EXPECT_EQ(rc, 0);

	for (i = 0; i < 1000; i++) {
		/* Sign */
		rc = zpc_hmac_sign(hmac, NULL, 0, m, hfunc2blksize[hmac_key->hfunc]);
		EXPECT_EQ(rc, 0);
		memset((char *)&hmac->param_kmac + hfunc2protkeyoffset[hmac_key->hfunc], 0, hfunc2protkeysize[hmac_key->hfunc]);
		rc = zpc_hmac_sign(hmac, mac, hfunc2tagsize[hmac_key->hfunc], m + hfunc2blksize[hmac_key->hfunc], mlen - hfunc2blksize[hmac_key->hfunc]);
		EXPECT_EQ(rc, 0);

		/* Verify */
		rc = zpc_hmac_verify(hmac, NULL, 0, m, hfunc2blksize[hmac_key->hfunc]);
		EXPECT_EQ(rc, 0);
		memset((char *)&hmac->param_kmac + hfunc2protkeyoffset[hmac_key->hfunc], 0, hfunc2protkeysize[hmac_key->hfunc]);
		rc = zpc_hmac_verify(hmac, mac, hfunc2tagsize[hmac_key->hfunc], m + hfunc2blksize[hmac_key->hfunc], mlen - hfunc2blksize[hmac_key->hfunc]);
		EXPECT_EQ(rc, 0);
	}

	zpc_hmac_free(&hmac);
	EXPECT_EQ(hmac, nullptr);
}

TEST(hmac, threads)
{
	struct zpc_hmac_key *hmac_key;
	zpc_hmac_hashfunc_t hfunc;
	int type, rc, i;
	std::thread *t[500];

	TESTLIB_ENV_HMAC_KEY_CHECK();

	TESTLIB_HMAC_HW_CAPS_CHECK();

	type = testlib_env_hmac_key_type();
	hfunc = testlib_env_hmac_hashfunc();

	TESTLIB_HMAC_KERNEL_CAPS_CHECK();

	TESTLIB_HMAC_SW_CAPS_CHECK(type);

	rc = zpc_hmac_key_alloc(&hmac_key);
	EXPECT_EQ(rc, 0);

	rc = zpc_hmac_key_set_type(hmac_key, type);
	EXPECT_EQ(rc, 0);
	rc = zpc_hmac_key_set_hash_function(hmac_key, hfunc);
	EXPECT_EQ(rc, 0);

	rc = testlib_set_hmac_key_from_pvsecret(hmac_key, hfunc2keysize[hfunc]);
	if (rc)
		goto ret;

	for (i = 0; i < 500; i++) {
		t[i] = new std::thread(__task, hmac_key);
	}

	/*
	 * Do something with key object while threads are working with it.
	 * pvsecret-type HMAC keys can be rederived from their IDs. But their
	 * IDs cannot be restored, aka "reenciphered", if corrupted. Therefore
	 * don't corrupt any IDs here.
	 */
	for (i = 0; i < 500; i++) {
		memset(&hmac_key->prot, 0, sizeof(hmac_key->prot)); /* destroy cached protected key */
		usleep(1);
	}

	for (i = 0; i < 500; i++) {
		t[i]->join();
		delete t[i];
	}

ret:
	zpc_hmac_key_free(&hmac_key);
	EXPECT_EQ(hmac_key, nullptr);
}
