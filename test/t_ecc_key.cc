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
