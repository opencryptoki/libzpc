/*
 * Copyright IBM Corp. 2022
 *
 * libzpc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "testlib.h"

#include "gtest/gtest.h"
#include "zpc/ecc_key.h"
#include "zpc/error.h"

extern const struct EC_TEST_VECTOR ec_tv[];

TEST(ec_key, alloc)
{
	struct zpc_ec_key *ec_key;
	int rc;

	TESTLIB_ENV_EC_KEY_CHECK();

	rc = zpc_ec_key_alloc(NULL);
	EXPECT_EQ(rc, ZPC_ERROR_ARG1NULL);

	ec_key = NULL;
	rc = zpc_ec_key_alloc(&ec_key);
	EXPECT_EQ(rc, 0);
	zpc_ec_key_free(&ec_key);
	EXPECT_EQ(ec_key, nullptr);

	ec_key = (struct zpc_ec_key *)&ec_key;
	rc = zpc_ec_key_alloc(&ec_key);
	EXPECT_EQ(rc, 0);
	zpc_ec_key_free(&ec_key);
	EXPECT_EQ(ec_key, nullptr);
}

TEST(ec_key, free)
{
	struct zpc_ec_key *ec_key;
	int rc;

	TESTLIB_ENV_EC_KEY_CHECK();

	zpc_ec_key_free(NULL);

	ec_key = NULL;
	zpc_ec_key_free(&ec_key);
	EXPECT_EQ(ec_key, nullptr);

	rc = zpc_ec_key_alloc(&ec_key);
	EXPECT_EQ(rc, 0);
	zpc_ec_key_free(&ec_key);
	EXPECT_EQ(ec_key, nullptr);
}

TEST(ec_key, set_curve)
{
	struct zpc_ec_key *ec_key;
	int rc;

	TESTLIB_ENV_EC_KEY_CHECK();

	rc = zpc_ec_key_alloc(&ec_key);
	EXPECT_EQ(rc, 0);

	rc = zpc_ec_key_set_curve(NULL, ZPC_EC_CURVE_P256);
	EXPECT_EQ(rc, ZPC_ERROR_ARG1NULL);
	rc = zpc_ec_key_set_curve(NULL, ZPC_EC_CURVE_P384);
	EXPECT_EQ(rc, ZPC_ERROR_ARG1NULL);
	rc = zpc_ec_key_set_curve(NULL, ZPC_EC_CURVE_P521);
	EXPECT_EQ(rc, ZPC_ERROR_ARG1NULL);
	rc = zpc_ec_key_set_curve(NULL, ZPC_EC_CURVE_ED25519);
	EXPECT_EQ(rc, ZPC_ERROR_ARG1NULL);
	rc = zpc_ec_key_set_curve(NULL, ZPC_EC_CURVE_ED448);
	EXPECT_EQ(rc, ZPC_ERROR_ARG1NULL);

	rc = zpc_ec_key_set_curve(ec_key, ZPC_EC_CURVE_P256);
	EXPECT_EQ(rc, 0);
	rc = zpc_ec_key_set_curve(ec_key, ZPC_EC_CURVE_P384);
	EXPECT_EQ(rc, 0);
	rc = zpc_ec_key_set_curve(ec_key, ZPC_EC_CURVE_P521);
	EXPECT_EQ(rc, 0);
	rc = zpc_ec_key_set_curve(ec_key, ZPC_EC_CURVE_ED25519);
	EXPECT_EQ(rc, 0);
	rc = zpc_ec_key_set_curve(ec_key, ZPC_EC_CURVE_ED448);
	EXPECT_EQ(rc, 0);

	rc = zpc_ec_key_set_curve(ec_key, ZPC_EC_CURVE_INVALID);
	EXPECT_EQ(rc, ZPC_ERROR_EC_INVALID_CURVE);

	zpc_ec_key_free(&ec_key);
	EXPECT_EQ(ec_key, nullptr);
}

TEST(ec_key, set_type_cca)
{
	struct zpc_ec_key *ec_key;
	int rc;

	TESTLIB_ENV_EC_KEY_CHECK();

	TESTLIB_EC_SW_CAPS_CHECK(ZPC_EC_KEY_TYPE_CCA);

	rc = zpc_ec_key_alloc(&ec_key);
	EXPECT_EQ(rc, 0);

	rc = zpc_ec_key_set_type(NULL, -1);
	EXPECT_EQ(rc, ZPC_ERROR_ARG1NULL);
	rc = zpc_ec_key_set_type(NULL, 0);
	EXPECT_EQ(rc, ZPC_ERROR_ARG1NULL);
	rc = zpc_ec_key_set_type(NULL, ZPC_EC_KEY_TYPE_CCA);
	EXPECT_EQ(rc, ZPC_ERROR_ARG1NULL);
	rc = zpc_ec_key_set_type(NULL, 4);
	EXPECT_EQ(rc, ZPC_ERROR_ARG1NULL);

	rc = zpc_ec_key_set_type(ec_key, -1);
	EXPECT_EQ(rc, ZPC_ERROR_KEYTYPE);
	rc = zpc_ec_key_set_type(ec_key, 0);
	EXPECT_EQ(rc, ZPC_ERROR_KEYTYPE);

	rc = zpc_ec_key_set_type(ec_key, ZPC_EC_KEY_TYPE_CCA);
	EXPECT_EQ(rc, 0);

	zpc_ec_key_free(&ec_key);
	EXPECT_EQ(ec_key, nullptr);
}

TEST(ec_key, set_type_ep11)
{
	struct zpc_ec_key *ec_key;
	int rc;

	TESTLIB_ENV_EC_KEY_CHECK();

	TESTLIB_EC_SW_CAPS_CHECK(ZPC_EC_KEY_TYPE_EP11);

	rc = zpc_ec_key_alloc(&ec_key);
	EXPECT_EQ(rc, 0);

	rc = zpc_ec_key_set_type(NULL, -1);
	EXPECT_EQ(rc, ZPC_ERROR_ARG1NULL);
	rc = zpc_ec_key_set_type(NULL, 0);
	EXPECT_EQ(rc, ZPC_ERROR_ARG1NULL);
	rc = zpc_ec_key_set_type(NULL, ZPC_EC_KEY_TYPE_EP11);
	EXPECT_EQ(rc, ZPC_ERROR_ARG1NULL);
	rc = zpc_ec_key_set_type(NULL, 4);
	EXPECT_EQ(rc, ZPC_ERROR_ARG1NULL);

	rc = zpc_ec_key_set_type(ec_key, -1);
	EXPECT_EQ(rc, ZPC_ERROR_KEYTYPE);
	rc = zpc_ec_key_set_type(ec_key, 0);
	EXPECT_EQ(rc, ZPC_ERROR_KEYTYPE);
	rc = zpc_ec_key_set_type(ec_key, ZPC_EC_KEY_TYPE_EP11 + 1);
	EXPECT_EQ(rc, ZPC_ERROR_KEYTYPE);

	rc = zpc_ec_key_set_type(ec_key, ZPC_EC_KEY_TYPE_EP11);
	EXPECT_EQ(rc, 0);

	zpc_ec_key_free(&ec_key);
	EXPECT_EQ(ec_key, nullptr);
}

TEST(ec_key, set_flags)
{
	struct zpc_ec_key *ec_key;
	int rc;

	TESTLIB_ENV_EC_KEY_CHECK();

	rc = zpc_ec_key_alloc(&ec_key);
	EXPECT_EQ(rc, 0);

	rc = zpc_ec_key_set_flags(NULL, 0);
	EXPECT_EQ(rc, ZPC_ERROR_ARG1NULL);
	rc = zpc_ec_key_set_flags(ec_key, -1);
	EXPECT_EQ(rc, 0);

	zpc_ec_key_free(&ec_key);
	EXPECT_EQ(ec_key, nullptr);
}

TEST(ec_key, set_mkvp)
{
	struct zpc_ec_key *ec_key;
	const char *mkvp;
	unsigned int flags;
	int rc, type;

	TESTLIB_ENV_EC_KEY_CHECK();

	type = testlib_env_ec_key_type();
	flags = testlib_env_ec_key_flags();
	mkvp = testlib_env_ec_key_mkvp();

	TESTLIB_EC_SW_CAPS_CHECK(type);

	rc = zpc_ec_key_alloc(&ec_key);
	EXPECT_EQ(rc, 0);

	rc = zpc_ec_key_set_mkvp(NULL, NULL);
	EXPECT_EQ(rc, ZPC_ERROR_ARG1NULL);
	rc = zpc_ec_key_set_mkvp(NULL, mkvp);
	EXPECT_EQ(rc, ZPC_ERROR_ARG1NULL);

	rc = zpc_ec_key_set_mkvp(ec_key, NULL);
	EXPECT_EQ(rc, 0);

	rc = zpc_ec_key_set_flags(ec_key, flags);
	EXPECT_EQ(rc, 0);
	rc = zpc_ec_key_set_mkvp(ec_key, mkvp);
	if (mkvp)
		EXPECT_EQ(rc, ZPC_ERROR_KEYTYPENOTSET);
	else
		EXPECT_EQ(rc, 0);
	rc = zpc_ec_key_set_type(ec_key, type);
	EXPECT_EQ(rc, 0);
	rc = zpc_ec_key_set_mkvp(ec_key, mkvp);
	EXPECT_EQ(rc, 0);

	zpc_ec_key_free(&ec_key);
	EXPECT_EQ(ec_key, nullptr);
}

TEST(ec_key, set_apqns)
{
	struct zpc_ec_key *ec_key;
	const char *apqns[] = {"01.0037", "\n01.0037\t ", NULL}; /* apqn example */
	int rc;

	TESTLIB_ENV_EC_KEY_CHECK();

	rc = zpc_ec_key_alloc(&ec_key);
	EXPECT_EQ(rc, 0);

	rc = zpc_ec_key_set_apqns(NULL, NULL);
	EXPECT_EQ(rc, ZPC_ERROR_ARG1NULL);
	rc = zpc_ec_key_set_apqns(NULL, apqns);
	EXPECT_EQ(rc, ZPC_ERROR_ARG1NULL);

	rc = zpc_ec_key_set_apqns(ec_key, NULL);
	EXPECT_EQ(rc, 0);
	rc = zpc_ec_key_set_apqns(ec_key, apqns);
	EXPECT_TRUE(rc == 0 || rc == ZPC_ERROR_WKVPMISMATCH ||
				rc == ZPC_ERROR_APQNS_INVALID_VERSION );

	zpc_ec_key_free(&ec_key);
	EXPECT_EQ(ec_key, nullptr);
}

TEST(ec_key, import_clear)
{
	struct zpc_ec_key *ec_key;
	unsigned int pubkeylen, privkeylen;
	const char *apqns[257];
	unsigned int flags;
	int rc, type;
	zpc_ec_curve_t curve;
	const char *mkvp;

	TESTLIB_ENV_EC_KEY_CHECK();

	curve = testlib_env_ec_key_curve();
	type = testlib_env_ec_key_type();
	flags = testlib_env_ec_key_flags();
	mkvp = testlib_env_ec_key_mkvp();
	(void)testlib_env_ec_key_apqns(apqns);

	TESTLIB_EC_SW_CAPS_CHECK(type);

	TESTLIB_EC_KERNEL_CAPS_CHECK(type, mkvp,apqns);

	const u8 *pubkey = ec_tv[curve].pubkey;
	const u8 *privkey = ec_tv[curve].privkey;
	pubkeylen = ec_tv[curve].pubkey_len;
	privkeylen = ec_tv[curve].privkey_len;

	rc = zpc_ec_key_alloc(&ec_key);
	EXPECT_EQ(rc, 0);

	rc = zpc_ec_key_import_clear(NULL, NULL, 0, NULL, 0);
	EXPECT_EQ(rc, ZPC_ERROR_ARG1NULL);
	rc = zpc_ec_key_import_clear(NULL, pubkey, pubkeylen, privkey, privkeylen);
	EXPECT_EQ(rc, ZPC_ERROR_ARG1NULL);

	rc = zpc_ec_key_import_clear(ec_key, NULL, 0, NULL, 0);
	EXPECT_EQ(rc, ZPC_ERROR_EC_NO_KEY_PARTS);
	rc = zpc_ec_key_import_clear(ec_key, pubkey, pubkeylen, privkey, privkeylen);
	EXPECT_EQ(rc, ZPC_ERROR_APQNSNOTSET);

	if (mkvp == NULL) {
		rc = zpc_ec_key_set_apqns(ec_key, apqns);
		EXPECT_EQ(rc, 0);
		rc = zpc_ec_key_import_clear(ec_key, pubkey, pubkeylen, privkey, privkeylen);
		EXPECT_EQ(rc, ZPC_ERROR_EC_CURVE_NOTSET);
	}

	rc = zpc_ec_key_set_curve(ec_key, curve);
	EXPECT_EQ(rc, 0);
	rc = zpc_ec_key_set_flags(ec_key, flags);
	EXPECT_EQ(rc, 0);

	if (mkvp == NULL) {
		rc = zpc_ec_key_import_clear(ec_key, pubkey, pubkeylen, privkey, privkeylen);
		EXPECT_EQ(rc, ZPC_ERROR_KEYTYPENOTSET);
	}

	rc = zpc_ec_key_set_type(ec_key, type);
	EXPECT_EQ(rc, 0);
	if (mkvp != NULL) {
		rc = zpc_ec_key_set_mkvp(ec_key, mkvp);
		EXPECT_EQ(rc, 0);
	}

	rc = zpc_ec_key_import_clear(ec_key, pubkey, 5, privkey, privkeylen);
	EXPECT_EQ(rc, ZPC_ERROR_EC_PUBKEY_LENGTH);

	rc = zpc_ec_key_import_clear(ec_key, pubkey, pubkeylen, privkey, 5);
	EXPECT_EQ(rc, ZPC_ERROR_EC_PRIVKEY_LENGTH);

	rc = zpc_ec_key_import_clear(ec_key, pubkey, pubkeylen, privkey, privkeylen);
	EXPECT_EQ(rc, 0);

	zpc_ec_key_free(&ec_key);
	EXPECT_EQ(ec_key, nullptr);
}

TEST(ec_key, generate)
{
	struct zpc_ec_key *ec_key;
	unsigned int flags;
	const char *apqns[257];
	int rc, type;
	zpc_ec_curve_t curve;
	const char *mkvp;

	TESTLIB_ENV_EC_KEY_CHECK();

	curve = testlib_env_ec_key_curve();
	type = testlib_env_ec_key_type();
	flags= testlib_env_ec_key_flags();
	mkvp = testlib_env_ec_key_mkvp();
	(void)testlib_env_ec_key_apqns(apqns);

	TESTLIB_EC_SW_CAPS_CHECK(type);

	TESTLIB_EC_KERNEL_CAPS_CHECK(type, mkvp, apqns);

	rc = zpc_ec_key_alloc(&ec_key);
	EXPECT_EQ(rc, 0);

	rc = zpc_ec_key_generate(NULL);
	EXPECT_EQ(rc, ZPC_ERROR_ARG1NULL);

	rc = zpc_ec_key_generate(ec_key);
	EXPECT_EQ(rc, ZPC_ERROR_EC_CURVE_NOTSET);

	if (mkvp == NULL) {
		rc = zpc_ec_key_set_apqns(ec_key, apqns);
		EXPECT_EQ(rc, 0);

		rc = zpc_ec_key_generate(ec_key);
		EXPECT_EQ(rc, ZPC_ERROR_EC_CURVE_NOTSET);
	}

	rc = zpc_ec_key_set_curve(ec_key, curve);
	EXPECT_EQ(rc, 0);

	if (mkvp == NULL) {
		rc = zpc_ec_key_generate(ec_key);
		EXPECT_EQ(rc, ZPC_ERROR_KEYTYPENOTSET);
	}

	rc = zpc_ec_key_set_type(ec_key, type);
	EXPECT_EQ(rc, 0);
	if (mkvp != NULL) {
		rc = zpc_ec_key_set_mkvp(ec_key, mkvp);
		EXPECT_EQ(rc, 0);
	}
	rc = zpc_ec_key_set_flags(ec_key, flags);
	EXPECT_EQ(rc, 0);
	rc = zpc_ec_key_generate(ec_key);
	EXPECT_EQ(rc, 0);

	zpc_ec_key_free(&ec_key);
	EXPECT_EQ(ec_key, nullptr);
}

TEST(ec_key, reencipher)
{
	struct zpc_ec_key *ec_key;
	unsigned int flags;
	const char *apqns[257];
	int rc, type;
	zpc_ec_curve_t curve;
	const char *mkvp;

	TESTLIB_ENV_EC_KEY_CHECK();

	curve = testlib_env_ec_key_curve();
	type = testlib_env_ec_key_type();
	flags= testlib_env_ec_key_flags();
	mkvp = testlib_env_ec_key_mkvp();
	(void)testlib_env_ec_key_apqns(apqns);

	TESTLIB_EC_SW_CAPS_CHECK(type);

	TESTLIB_EC_KERNEL_CAPS_CHECK(type, mkvp, apqns);

	TESTLIB_EC_NEW_MK_CHECK(type, mkvp, apqns);

	rc = zpc_ec_key_alloc(&ec_key);
	EXPECT_EQ(rc, 0);

	rc = zpc_ec_key_set_flags(ec_key, flags);
	EXPECT_EQ(rc, 0);

	rc = zpc_ec_key_set_curve(ec_key, curve);
	EXPECT_EQ(rc, 0);

	rc = zpc_ec_key_set_type(ec_key, type);
	EXPECT_EQ(rc, 0);

	if (mkvp != NULL) {
		rc = zpc_ec_key_set_mkvp(ec_key, mkvp);
		EXPECT_EQ(rc, 0);
	} else {
		rc = zpc_ec_key_set_apqns(ec_key, apqns);
		EXPECT_EQ(rc, 0);
	}

	rc = zpc_ec_key_generate(ec_key);
	EXPECT_EQ(rc, 0);

	rc = zpc_ec_key_reencipher(ec_key, ZPC_EC_KEY_REENCIPHER_CURRENT_TO_NEW);
	EXPECT_EQ(rc, 0);

	zpc_ec_key_free(&ec_key);
	EXPECT_EQ(ec_key, nullptr);
}

TEST(ec_key, export)
{
	struct zpc_ec_key *ec_key, *ec_key2;
	u8 buf[2000], buf2[2000];
	unsigned int buflen, buflen2, flags;
	const char *apqns[257];
	int rc, type;
	zpc_ec_curve_t curve;
	const char *mkvp;

	TESTLIB_ENV_EC_KEY_CHECK();

	curve = testlib_env_ec_key_curve();
	type = testlib_env_ec_key_type();
	flags= testlib_env_ec_key_flags();
	mkvp = testlib_env_ec_key_mkvp();
	(void)testlib_env_ec_key_apqns(apqns);

	TESTLIB_EC_SW_CAPS_CHECK(type);

	TESTLIB_EC_KERNEL_CAPS_CHECK(type, mkvp, apqns);

	rc = zpc_ec_key_export(NULL, NULL, NULL);
	EXPECT_EQ(rc, ZPC_ERROR_ARG1NULL);

	rc = zpc_ec_key_alloc(&ec_key);
	EXPECT_EQ(rc, 0);
	rc = zpc_ec_key_alloc(&ec_key2);
	EXPECT_EQ(rc, 0);

	rc = zpc_ec_key_export(ec_key, NULL, NULL);
	EXPECT_EQ(rc, ZPC_ERROR_ARG3NULL);

	rc = zpc_ec_key_export(ec_key, NULL, &buflen);
	EXPECT_EQ(rc, ZPC_ERROR_EC_NO_KEY_PARTS);

	rc = zpc_ec_key_set_type(ec_key, type);
	EXPECT_EQ(rc, 0);
	if (mkvp != NULL) {
		rc = zpc_ec_key_set_mkvp(ec_key, mkvp);
		EXPECT_EQ(rc, 0);
	} else {
		rc = zpc_ec_key_set_apqns(ec_key, apqns);
		EXPECT_EQ(rc, 0);
	}
	rc = zpc_ec_key_set_flags(ec_key, flags);
	EXPECT_EQ(rc, 0);
	rc = zpc_ec_key_set_curve(ec_key, curve);
	EXPECT_EQ(rc, 0);
	rc = zpc_ec_key_generate(ec_key);
	EXPECT_EQ(rc, 0);

	buflen = 0;
	rc = zpc_ec_key_export(ec_key, buf, &buflen);
	EXPECT_EQ(rc, ZPC_ERROR_SMALLOUTBUF);

	rc = zpc_ec_key_export(ec_key, NULL, &buflen);
	EXPECT_EQ(rc, 0);
	EXPECT_GT(buflen, 0UL);

	rc = zpc_ec_key_export(ec_key, buf, &buflen);
	EXPECT_EQ(rc, 0);

	/* Import this secure key token into a 2nd key */
	rc = zpc_ec_key_set_type(ec_key2, type);
	EXPECT_EQ(rc, 0);
	rc = zpc_ec_key_set_flags(ec_key2, flags);
	EXPECT_EQ(rc, 0);
	rc = zpc_ec_key_set_curve(ec_key2, curve);
	EXPECT_EQ(rc, 0);
	rc = zpc_ec_key_import(ec_key2, buf, buflen);
	EXPECT_EQ(rc, 0);

	/* And export it again */
	buflen2 = sizeof(buf2);
	rc = zpc_ec_key_export(ec_key2, buf2, &buflen2);
	EXPECT_EQ(rc, 0);
	EXPECT_EQ(buflen, buflen2);
	EXPECT_TRUE(memcmp(buf2, buf, buflen) == 0);

	zpc_ec_key_free(&ec_key);
	EXPECT_EQ(ec_key, nullptr);
	zpc_ec_key_free(&ec_key2);
	EXPECT_EQ(ec_key2, nullptr);
}

TEST(ec_key, export_public)
{
	struct zpc_ec_key *ec_key;
	u8 buf[132];
	unsigned int buflen, flags;
	const char *apqns[257];
	int rc, type;
	zpc_ec_curve_t curve;
	const char *mkvp;

	TESTLIB_ENV_EC_KEY_CHECK();

	curve = testlib_env_ec_key_curve();
	type = testlib_env_ec_key_type();
	flags= testlib_env_ec_key_flags();
	mkvp = testlib_env_ec_key_mkvp();
	(void)testlib_env_ec_key_apqns(apqns);

	TESTLIB_EC_SW_CAPS_CHECK(type);

	TESTLIB_EC_KERNEL_CAPS_CHECK(type, mkvp, apqns);

	rc = zpc_ec_key_export_public(NULL, NULL, NULL);
	EXPECT_EQ(rc, ZPC_ERROR_ARG1NULL);

	rc = zpc_ec_key_alloc(&ec_key);
	EXPECT_EQ(rc, 0);

	rc = zpc_ec_key_export_public(ec_key, NULL, NULL);
	EXPECT_EQ(rc, ZPC_ERROR_ARG3NULL);

	rc = zpc_ec_key_export_public(ec_key, NULL, &buflen);
	EXPECT_EQ(rc, ZPC_ERROR_EC_PUBKEY_NOTSET);

	rc = zpc_ec_key_set_type(ec_key, type);
	EXPECT_EQ(rc, 0);
	if (mkvp != NULL) {
		rc = zpc_ec_key_set_mkvp(ec_key, mkvp);
		EXPECT_EQ(rc, 0);
	} else {
		rc = zpc_ec_key_set_apqns(ec_key, apqns);
		EXPECT_EQ(rc, 0);
	}
	rc = zpc_ec_key_set_flags(ec_key, flags);
	EXPECT_EQ(rc, 0);
	rc = zpc_ec_key_set_curve(ec_key, curve);
	EXPECT_EQ(rc, 0);
	rc = zpc_ec_key_generate(ec_key);
	EXPECT_EQ(rc, 0);

	buflen = 0;
	rc = zpc_ec_key_export_public(ec_key, buf, &buflen);
	EXPECT_EQ(rc, ZPC_ERROR_SMALLOUTBUF);

	rc = zpc_ec_key_export_public(ec_key, NULL, &buflen);
	EXPECT_EQ(rc, 0);
	EXPECT_GT(buflen, 0UL);

	rc = zpc_ec_key_export_public(ec_key, buf, &buflen);
	EXPECT_EQ(rc, 0);

	zpc_ec_key_free(&ec_key);
	EXPECT_EQ(ec_key, nullptr);
}

TEST(ec_key, import)
{
	struct zpc_ec_key *ec_key, *ec_key2;
	u8 buf[10000], buf2[10000];
	unsigned int buflen = sizeof(buf);
	unsigned int buf2len = sizeof(buf2);
	unsigned int flags;
	const char *apqns[257];
	const char *mkvp;
	int rc, type;
	zpc_ec_curve_t curve;

	TESTLIB_ENV_EC_KEY_CHECK();

	curve = testlib_env_ec_key_curve();
	type = testlib_env_ec_key_type();
	flags= testlib_env_ec_key_flags();
	mkvp = testlib_env_ec_key_mkvp();
	(void)testlib_env_ec_key_apqns(apqns);

	TESTLIB_EC_SW_CAPS_CHECK(type);

	TESTLIB_EC_KERNEL_CAPS_CHECK(type, mkvp, apqns);

	rc = zpc_ec_key_alloc(&ec_key);
	EXPECT_EQ(rc, 0);
	rc = zpc_ec_key_alloc(&ec_key2);
	EXPECT_EQ(rc, 0);

	rc = zpc_ec_key_import(NULL, NULL, 0);
	EXPECT_EQ(rc, ZPC_ERROR_ARG1NULL);

	rc = zpc_ec_key_import(ec_key, NULL, 0);
	EXPECT_EQ(rc, ZPC_ERROR_ARG2NULL);

	rc = zpc_ec_key_import(ec_key, buf, 63);
	EXPECT_EQ(rc, ZPC_ERROR_ARG3RANGE);
	rc = zpc_ec_key_import(ec_key, buf, 3000);
	EXPECT_EQ(rc, ZPC_ERROR_ARG3RANGE);

	rc = zpc_ec_key_set_curve(ec_key, curve);
	EXPECT_EQ(rc, 0);
	rc = zpc_ec_key_set_curve(ec_key2, curve);
	EXPECT_EQ(rc, 0);

	rc = zpc_ec_key_import(ec_key, buf, 226);
	EXPECT_EQ(rc, ZPC_ERROR_KEYTYPENOTSET);

	rc = zpc_ec_key_set_type(ec_key, type);
	EXPECT_EQ(rc, 0);
	rc = zpc_ec_key_set_type(ec_key2, type);
	EXPECT_EQ(rc, 0);

	if (mkvp != NULL) {
		rc = zpc_ec_key_set_mkvp(ec_key, mkvp);
		EXPECT_EQ(rc, 0);
		rc = zpc_ec_key_set_mkvp(ec_key2, mkvp);
		EXPECT_EQ(rc, 0);
	} else {
		rc = zpc_ec_key_set_apqns(ec_key, apqns);
		EXPECT_EQ(rc, 0);
		rc = zpc_ec_key_set_apqns(ec_key2, apqns);
		EXPECT_EQ(rc, 0);
	}

	rc = zpc_ec_key_import(ec_key, buf, 333);
	EXPECT_TRUE(rc == ZPC_ERROR_EC_NO_CCA_SECUREKEY_TOKEN ||
				rc == ZPC_ERROR_EC_NO_EP11_SECUREKEY_TOKEN);

	rc = zpc_ec_key_set_flags(ec_key, flags);
	EXPECT_EQ(rc, 0);
	rc = zpc_ec_key_generate(ec_key);
	EXPECT_EQ(rc, 0);

	rc = zpc_ec_key_export(ec_key, buf, &buflen);
	EXPECT_EQ(rc, 0);

	rc = zpc_ec_key_import(ec_key2, buf, buflen);
	EXPECT_EQ(rc, 0);

	rc = zpc_ec_key_export(ec_key2, buf2, &buf2len);
	EXPECT_EQ(rc, 0);
	EXPECT_EQ(buf2len, buflen);
	EXPECT_TRUE(memcmp(buf2, buf, buflen) == 0);

	zpc_ec_key_free(&ec_key);
	EXPECT_EQ(ec_key, nullptr);
	zpc_ec_key_free(&ec_key2);
	EXPECT_EQ(ec_key2, nullptr);
}

TEST(ec_key, spki_test)
{
	struct zpc_ec_key *ec_key, *ec_key2;
	unsigned int pubkeylen, privkeylen, blob_len, pubkey_offset;
	u8 buf[3000] = {0}, buf2[3000] = {0}, buf3[132] = {0}, buf4[3000] = {0};
	unsigned int buflen = sizeof(buf);
	unsigned int buf2len = sizeof(buf2);
	unsigned int buf3len = sizeof(buf3);
	unsigned int buf4len = sizeof(buf4);
	unsigned int flags;
	const char *apqns[257];
	const char *mkvp;
	int rc, type;
	zpc_ec_curve_t curve;

	/* These numbers are derived from the pxxx_maced_spki_t structs in ep11.h,
	 * applications should have their own way of handling SPKIs. */
	unsigned int curve2pubkey_offset[] = { 27, 24, 26, 21, 21 };

	struct ep11kblob_header {
		u8  type;	/* always 0x00 */
		u8  hver;	/* header version,  currently needs to be 0x00 */
		u16 len;	/* total length in bytes (including this header) */
		u8  version;	/* PKEY_TYPE_EP11_AES or PKEY_TYPE_EP11_ECC */
		u8  res0;	/* unused */
		u16 bitlen;	/* clear key bit len, 0 for unknown */
		u8  res1[8];	/* unused */
	};

	TESTLIB_ENV_EC_KEY_CHECK();

	curve = testlib_env_ec_key_curve();
	type = testlib_env_ec_key_type();
	flags= testlib_env_ec_key_flags();
	mkvp = testlib_env_ec_key_mkvp();
	(void)testlib_env_ec_key_apqns(apqns);

	if (type != ZPC_EC_KEY_TYPE_EP11)
		GTEST_SKIP_("Skipping spki_test. Only supported for EP11 type keys.");

	TESTLIB_EC_SW_CAPS_CHECK(type);

	TESTLIB_EC_KERNEL_CAPS_CHECK(type, mkvp, apqns);

	const u8 *pubkey = ec_tv[curve].pubkey;
	const u8 *privkey = ec_tv[curve].privkey;
	pubkeylen = ec_tv[curve].pubkey_len;
	privkeylen = ec_tv[curve].privkey_len;

	rc = zpc_ec_key_alloc(&ec_key);
	EXPECT_EQ(rc, 0);
	rc = zpc_ec_key_alloc(&ec_key2);
	EXPECT_EQ(rc, 0);

	rc = zpc_ec_key_set_curve(ec_key, curve);
	EXPECT_EQ(rc, 0);
	rc = zpc_ec_key_set_curve(ec_key2, curve);
	EXPECT_EQ(rc, 0);

	rc = zpc_ec_key_set_type(ec_key, type);
	EXPECT_EQ(rc, 0);
	rc = zpc_ec_key_set_type(ec_key2, type);
	EXPECT_EQ(rc, 0);

	if (mkvp != NULL) {
		rc = zpc_ec_key_set_mkvp(ec_key, mkvp);
		EXPECT_EQ(rc, 0);
		rc = zpc_ec_key_set_mkvp(ec_key2, mkvp);
		EXPECT_EQ(rc, 0);
	} else {
		rc = zpc_ec_key_set_apqns(ec_key, apqns);
		EXPECT_EQ(rc, 0);
		rc = zpc_ec_key_set_apqns(ec_key2, apqns);
		EXPECT_EQ(rc, 0);
	}

	rc = zpc_ec_key_set_flags(ec_key, flags);
	EXPECT_EQ(rc, 0);
	rc = zpc_ec_key_set_flags(ec_key2, flags);
	EXPECT_EQ(rc, 0);

	/* Test (1): Import private key only */
	rc = zpc_ec_key_import_clear(ec_key, NULL, 0, privkey, privkeylen);
	EXPECT_EQ(rc, 0);

	/* Export key, there is no public key spki available. The buflen must
	 * be equal to the length given inside the secure key blob. */
	rc = zpc_ec_key_export(ec_key, buf, &buflen);
	EXPECT_EQ(rc, 0);
	EXPECT_EQ(buflen, ((struct ep11kblob_header *)buf)->len);

	/* Test (2): Add public key, now an spki is created internally */
	rc = zpc_ec_key_import_clear(ec_key, pubkey, pubkeylen, NULL, 0);
	EXPECT_EQ(rc, 0);

	/* Export key: buf2len must now be greater than buflen, because of the
	 * appended spki. */
	rc = zpc_ec_key_export(ec_key, buf2, &buf2len);
	EXPECT_EQ(rc, 0);
	EXPECT_GT(buf2len, buflen);

	/* Public key inside the spki must be identical to original pubkey */
	blob_len = ((struct ep11kblob_header *)buf2)->len;
	pubkey_offset = curve2pubkey_offset[curve];
	EXPECT_TRUE(memcmp(pubkey, buf2 + blob_len + pubkey_offset, pubkeylen) == 0);

	/* Test (3): Now import [blob||spki] into a second key */
	rc = zpc_ec_key_import(ec_key2, buf2, buf2len);
	EXPECT_EQ(rc, 0);

	/* Export public key only: must be identical to original public key */
	rc = zpc_ec_key_export_public(ec_key2, buf3, &buf3len);
	EXPECT_EQ(rc, 0);
	EXPECT_EQ(buf3len, pubkeylen);
	EXPECT_TRUE(memcmp(buf3, pubkey, buf3len) == 0);

	/* Export secure key: must be [blob||spki] as previously imported */
	rc = zpc_ec_key_export(ec_key2, buf4, &buf4len);
	EXPECT_EQ(rc, 0);
	EXPECT_EQ(buf4len, buf2len);
	EXPECT_TRUE(memcmp(buf4, buf2, buf4len) == 0);

	/* Test (4): Generate a new key pair */
	rc = zpc_ec_key_generate(ec_key);
	EXPECT_EQ(rc, 0);

	/* Export public key */
	rc = zpc_ec_key_export_public(ec_key2, buf3, &buf3len);
	EXPECT_EQ(rc, 0);

	/* Export [blob||spki] */
	buflen = sizeof(buf);
	rc = zpc_ec_key_export(ec_key2, buf, &buflen);
	EXPECT_EQ(rc, 0);

	/* Public key must be identical to public key inside the spki */
	blob_len = ((struct ep11kblob_header *)buf)->len;
	pubkey_offset = curve2pubkey_offset[curve];
	EXPECT_TRUE(memcmp(buf3, buf + blob_len + pubkey_offset, buf3len) == 0);

	zpc_ec_key_free(&ec_key);
	EXPECT_EQ(ec_key, nullptr);
	zpc_ec_key_free(&ec_key2);
	EXPECT_EQ(ec_key2, nullptr);
}
