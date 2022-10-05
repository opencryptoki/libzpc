/*
 *
 * libzpc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "testlib.h"

#include "gtest/gtest.h"
#include "zpc/error.h"

#include "ecc_key_local.h"  /* de-opaquify struct zpc_ecc_key */
#include "ecdsa_ctx_local.h"  /* de-opaquify struct zpc_ecc_ctx */

#include "zpc/ecdsa_ctx.h"

#include <json-c/json.h>
#include <stdio.h>
#include <thread>
#include <unistd.h>

extern const struct EC_TEST_VECTOR ec_tv[];


void force_WKaVP_mismatch(struct zpc_ecdsa_ctx *ctx)
{
	if (ctx == NULL || ctx->ec_key ==  NULL)
		return;

	switch (ctx->ec_key->curve) {
	case ZPC_EC_CURVE_P256:
		memset(ctx->p256_sign_param.prot, 0, sizeof(ctx->p256_sign_param.prot));
		memset(ctx->p256_sign_param.wkvp, 0, sizeof(ctx->p256_sign_param.wkvp));
		break;
	case ZPC_EC_CURVE_P384:
		memset(ctx->p384_sign_param.prot, 0, sizeof(ctx->p384_sign_param.prot));
		memset(ctx->p384_sign_param.wkvp, 0, sizeof(ctx->p384_sign_param.wkvp));
		break;
	case ZPC_EC_CURVE_P521:
		memset(ctx->p521_sign_param.prot, 0, sizeof(ctx->p521_sign_param.prot));
		memset(ctx->p521_sign_param.wkvp, 0, sizeof(ctx->p521_sign_param.wkvp));
		break;
	case ZPC_EC_CURVE_ED25519:
		memset(ctx->ed25519_sign_param.prot, 0, sizeof(ctx->ed25519_sign_param.prot));
		memset(ctx->ed25519_sign_param.wkvp, 0, sizeof(ctx->ed25519_sign_param.wkvp));
		break;
	case ZPC_EC_CURVE_ED448:
		memset(ctx->ed448_sign_param.prot, 0, sizeof(ctx->ed448_sign_param.prot));
		memset(ctx->ed448_sign_param.wkvp, 0, sizeof(ctx->ed448_sign_param.wkvp));
		break;
	default:
		break;
	}
}

static void __run_json(const char *json);

TEST(ecdsa_ctx, alloc)
{
	struct zpc_ecdsa_ctx *ec_ctx;
	int rc;

	TESTLIB_ENV_EC_KEY_CHECK();

	TESTLIB_EC_HW_CAPS_CHECK();

	rc = zpc_ecdsa_ctx_alloc(NULL);
	EXPECT_EQ(rc, ZPC_ERROR_ARG1NULL);

	ec_ctx = NULL;
	rc = zpc_ecdsa_ctx_alloc(&ec_ctx);
	EXPECT_EQ(rc, 0);
	zpc_ecdsa_ctx_free(&ec_ctx);
	EXPECT_EQ(ec_ctx, nullptr);

	ec_ctx = (struct zpc_ecdsa_ctx *)&ec_ctx;
	rc = zpc_ecdsa_ctx_alloc(&ec_ctx);
	EXPECT_EQ(rc, 0);
	zpc_ecdsa_ctx_free(&ec_ctx);
	EXPECT_EQ(ec_ctx, nullptr);
}

TEST(ecdsa_ctx, free)
{
	struct zpc_ecdsa_ctx *ec_ctx;
	int rc;

	TESTLIB_ENV_EC_KEY_CHECK();

	TESTLIB_EC_HW_CAPS_CHECK();

	zpc_ecdsa_ctx_free(NULL);

	ec_ctx = NULL;
	zpc_ecdsa_ctx_free(&ec_ctx);
	EXPECT_EQ(ec_ctx, nullptr);

	rc = zpc_ecdsa_ctx_alloc(&ec_ctx);
	EXPECT_EQ(rc, 0);
	zpc_ecdsa_ctx_free(&ec_ctx);
	EXPECT_EQ(ec_ctx, nullptr);
}

TEST(ecdsa_ctx, set_key)
{
	struct zpc_ec_key *ec_key;
	struct zpc_ecdsa_ctx *ec_ctx;
	unsigned int pubkeylen, privkeylen, flags = 0;
	const char *mkvp, *apqns[257];
	int rc, type;
	zpc_ec_curve_t curve;

	TESTLIB_ENV_EC_KEY_CHECK();

	TESTLIB_EC_HW_CAPS_CHECK();

	curve = testlib_env_ec_key_curve();
	type = testlib_env_ec_key_type();
	flags = testlib_env_ec_key_flags();
	mkvp = testlib_env_ec_key_mkvp();
	(void)testlib_env_ec_key_apqns(apqns);

	TESTLIB_EC_SW_CAPS_CHECK(type);

	TESTLIB_EC_KERNEL_CAPS_CHECK(type, mkvp, apqns);

	const u8 *pubkey = ec_tv[curve].pubkey;
	const u8 *privkey = ec_tv[curve].privkey;
	pubkeylen = ec_tv[curve].pubkey_len;
	privkeylen = ec_tv[curve].privkey_len;

	rc = zpc_ec_key_alloc(&ec_key);
	EXPECT_EQ(rc, 0);
	rc = zpc_ecdsa_ctx_alloc(&ec_ctx);
	EXPECT_EQ(rc, 0);

	rc = zpc_ecdsa_ctx_set_key(ec_ctx, ec_key);
	EXPECT_EQ(rc, ZPC_ERROR_EC_NO_KEY_PARTS);

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
	rc = zpc_ec_key_set_flags(ec_key, flags);
	EXPECT_EQ(rc, 0);

	rc = zpc_ec_key_import_clear(ec_key, pubkey, pubkeylen, privkey, privkeylen);
	EXPECT_EQ(rc, 0);

	rc = zpc_ecdsa_ctx_set_key(NULL, NULL);
	EXPECT_EQ(rc, ZPC_ERROR_ARG1NULL);
	rc = zpc_ecdsa_ctx_set_key(NULL, ec_key);
	EXPECT_EQ(rc, ZPC_ERROR_ARG1NULL);

	rc = zpc_ecdsa_ctx_set_key(ec_ctx, NULL);
	EXPECT_EQ(rc, 0);
	rc = zpc_ecdsa_ctx_set_key(ec_ctx, ec_key);
	EXPECT_EQ(rc, 0);

	zpc_ecdsa_ctx_free(&ec_ctx);
	EXPECT_EQ(ec_ctx, nullptr);
	zpc_ec_key_free(&ec_key);
	EXPECT_EQ(ec_key, nullptr);
}

TEST(ecdsa_ctx, sign)
{
	struct zpc_ec_key *ec_key;
	struct zpc_ecdsa_ctx *ec_ctx;
	const char *mkvp, *apqns[257];
	u8 msg[1000], signature[200];
	unsigned int msg_len, sig_len, flags;
	int rc, type;
	zpc_ec_curve_t curve;
	const unsigned int test_msglen_from_curve[] = { 32, 48, 64, 500, 1000 };
	const unsigned int expected_siglen_from_curve[] = { 64, 96, 132, 64, 114 };

	TESTLIB_ENV_EC_KEY_CHECK();

	TESTLIB_EC_HW_CAPS_CHECK();

	curve = testlib_env_ec_key_curve();
	type = testlib_env_ec_key_type();
	flags = testlib_env_ec_key_flags();
	mkvp = testlib_env_ec_key_mkvp();
	(void)testlib_env_ec_key_apqns(apqns);

	TESTLIB_EC_SW_CAPS_CHECK(type);

	TESTLIB_EC_KERNEL_CAPS_CHECK(type, mkvp, apqns);

	rc = zpc_ec_key_alloc(&ec_key);
	EXPECT_EQ(rc, 0);
	rc = zpc_ecdsa_ctx_alloc(&ec_ctx);
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
	rc = zpc_ec_key_set_curve(ec_key, curve);
	EXPECT_EQ(rc, 0);
	rc = zpc_ec_key_set_flags(ec_key, flags);
	EXPECT_EQ(rc, 0);
	rc = zpc_ec_key_generate(ec_key);
	EXPECT_EQ(rc, 0);

	rc = zpc_ecdsa_ctx_set_key(ec_ctx, ec_key);
	EXPECT_EQ(rc, 0);

	sig_len = sizeof(signature);
	msg_len = test_msglen_from_curve[curve];

	/* Check 'length_only': returned sig_len must match with expected len */
	rc = zpc_ecdsa_sign(ec_ctx, msg, msg_len, NULL, &sig_len);
	EXPECT_EQ(rc, 0);
	EXPECT_EQ(sig_len, expected_siglen_from_curve[curve]);

	/* Now perform the sign */
	rc = zpc_ecdsa_sign(ec_ctx, msg, msg_len, signature, &sig_len);
	EXPECT_EQ(rc, 0);

	zpc_ecdsa_ctx_free(&ec_ctx);
	EXPECT_EQ(ec_ctx, nullptr);
	zpc_ec_key_free(&ec_key);
	EXPECT_EQ(ec_key, nullptr);
}

TEST(ecdsa_ctx, verify)
{
	struct zpc_ec_key *ec_key, *ec_key2, *ec_key3;
	struct zpc_ecdsa_ctx *ec_ctx;
	const char *mkvp, *apqns[257];
	u8 signature[200];
	u8 buf[200];
	unsigned int signature_len, hash_len, sig_len, buflen;
	unsigned int pubkeylen, flags;
	int rc, type;
	zpc_ec_curve_t curve;

	TESTLIB_ENV_EC_KEY_CHECK();

	TESTLIB_EC_HW_CAPS_CHECK();

	curve = testlib_env_ec_key_curve();
	type = testlib_env_ec_key_type();
	flags = testlib_env_ec_key_flags();
	mkvp = testlib_env_ec_key_mkvp();
	(void)testlib_env_ec_key_apqns(apqns);

	TESTLIB_EC_SW_CAPS_CHECK(type);

	TESTLIB_EC_KERNEL_CAPS_CHECK(type, mkvp, apqns);

	const u8 *pubkey = ec_tv[curve].pubkey;
	const u8 *hash = ec_tv[curve].msg;
	const u8 *sig = ec_tv[curve].sig;
	pubkeylen = ec_tv[curve].pubkey_len;
	hash_len = ec_tv[curve].msg_len;
	sig_len = ec_tv[curve].sig_len;

	rc = zpc_ec_key_alloc(&ec_key);
	EXPECT_EQ(rc, 0);
	rc = zpc_ec_key_alloc(&ec_key2);
	EXPECT_EQ(rc, 0);
	rc = zpc_ec_key_alloc(&ec_key3);
	EXPECT_EQ(rc, 0);
	rc = zpc_ecdsa_ctx_alloc(&ec_ctx);
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
	rc = zpc_ec_key_set_curve(ec_key, curve);
	EXPECT_EQ(rc, 0);
	rc = zpc_ec_key_set_flags(ec_key, flags);
	EXPECT_EQ(rc, 0);

	rc = zpc_ec_key_generate(ec_key);
	EXPECT_EQ(rc, 0);
	rc = zpc_ecdsa_ctx_set_key(ec_ctx, ec_key);
	EXPECT_EQ(rc, 0);

	/* Create local signature with given NIST key */
	signature_len = sizeof(signature);
	rc = zpc_ecdsa_sign(ec_ctx, hash, hash_len, signature, &signature_len);
	EXPECT_EQ(rc, 0);
	EXPECT_EQ(signature_len, sig_len);

	/* Export public key ... */
	buflen = sizeof(buf);
	rc = zpc_ec_key_export_public(ec_key, buf, &buflen);
	EXPECT_EQ(rc, 0);
	EXPECT_GT(buflen, 0UL);

	/* Create a 2nd key with only the public key set */
	rc = zpc_ec_key_set_type(ec_key2, type);
	EXPECT_EQ(rc, 0);
	if (mkvp != NULL) {
		rc = zpc_ec_key_set_mkvp(ec_key2, mkvp);
		EXPECT_EQ(rc, 0);
	} else {
		rc = zpc_ec_key_set_apqns(ec_key2, apqns);
		EXPECT_EQ(rc, 0);
	}
	rc = zpc_ec_key_set_curve(ec_key2, curve);
	EXPECT_EQ(rc, 0);
	rc = zpc_ec_key_set_flags(ec_key2, flags);
	EXPECT_EQ(rc, 0);
	rc = zpc_ec_key_import_clear(ec_key2, buf, buflen, NULL, 0);
	EXPECT_EQ(rc, 0);

	/* Overwrite old key in ctx with new public-only key */
	rc = zpc_ecdsa_ctx_set_key(ec_ctx, ec_key2);
	EXPECT_EQ(rc, 0);

	/* Now verify locally created signature with the public-only key */
	rc = zpc_ecdsa_verify(ec_ctx, hash, hash_len, signature, signature_len);
	EXPECT_EQ(rc, 0);

	/* Import public key from NIST test into a new key3 */
	rc = zpc_ec_key_set_type(ec_key3, type);
	EXPECT_EQ(rc, 0);
	if (mkvp != NULL) {
		rc = zpc_ec_key_set_mkvp(ec_key3, mkvp);
		EXPECT_EQ(rc, 0);
	} else {
		rc = zpc_ec_key_set_apqns(ec_key3, apqns);
		EXPECT_EQ(rc, 0);
	}
	rc = zpc_ec_key_set_curve(ec_key3, curve);
	EXPECT_EQ(rc, 0);
	rc = zpc_ec_key_set_flags(ec_key3, flags);
	EXPECT_EQ(rc, 0);
	rc = zpc_ec_key_import_clear(ec_key3, pubkey, pubkeylen, NULL, 0);
	EXPECT_EQ(rc, 0);
	rc = zpc_ecdsa_ctx_set_key(ec_ctx, ec_key3);
	EXPECT_EQ(rc, 0);

	/* And verify NIST signature with the NIST public-only key */
	rc = zpc_ecdsa_verify(ec_ctx, hash, hash_len, sig, sig_len);
	EXPECT_EQ(rc, 0);

	zpc_ecdsa_ctx_free(&ec_ctx);
	EXPECT_EQ(ec_ctx, nullptr);
	zpc_ec_key_free(&ec_key);
	EXPECT_EQ(ec_key, nullptr);
	zpc_ec_key_free(&ec_key2);
	EXPECT_EQ(ec_key2, nullptr);
	zpc_ec_key_free(&ec_key3);
	EXPECT_EQ(ec_key3, nullptr);
}

TEST(ecdsa_ctx, sv)
{
	struct zpc_ec_key *ec_key1, *ec_key2;
	struct zpc_ecdsa_ctx *ec_ctx1, *ec_ctx2;
	u8 sigbuf[200];
	unsigned int hash_len, sig_len, pubkeylen, privkeylen;
	const char *mkvp, *apqns[257];
	unsigned int flags;
	int rc, type;
	zpc_ec_curve_t curve;

	TESTLIB_ENV_EC_KEY_CHECK();

	TESTLIB_EC_HW_CAPS_CHECK();

	curve = testlib_env_ec_key_curve();
	type = testlib_env_ec_key_type();
	flags = testlib_env_ec_key_flags();
	mkvp = testlib_env_ec_key_mkvp();
	(void)testlib_env_ec_key_apqns(apqns);

	TESTLIB_EC_SW_CAPS_CHECK(type);

	TESTLIB_EC_KERNEL_CAPS_CHECK(type, mkvp, apqns);

	const u8 *pubkey = ec_tv[curve].pubkey;
	const u8 *privkey = ec_tv[curve].privkey;
	const u8 *hash = ec_tv[curve].msg;
	const u8 *sig = ec_tv[curve].sig;
	pubkeylen = ec_tv[curve].pubkey_len;
	privkeylen = ec_tv[curve].privkey_len;
	hash_len = ec_tv[curve].msg_len;
	sig_len = ec_tv[curve].sig_len;

	rc = zpc_ec_key_alloc(&ec_key1);
	EXPECT_EQ(rc, 0);
	rc = zpc_ec_key_alloc(&ec_key2);
	EXPECT_EQ(rc, 0);
	rc = zpc_ecdsa_ctx_alloc(&ec_ctx1);
	EXPECT_EQ(rc, 0);
	rc = zpc_ecdsa_ctx_alloc(&ec_ctx2);
	EXPECT_EQ(rc, 0);

	/* Import NIST test key into ec_key1 */
	rc = zpc_ec_key_set_curve(ec_key1, curve);
	EXPECT_EQ(rc, 0);
	rc = zpc_ec_key_set_type(ec_key1, type);
	EXPECT_EQ(rc, 0);
	if (mkvp != NULL) {
		rc = zpc_ec_key_set_mkvp(ec_key1, mkvp);
		EXPECT_EQ(rc, 0);
	} else {
		rc = zpc_ec_key_set_apqns(ec_key1, apqns);
		EXPECT_EQ(rc, 0);
	}
	rc = zpc_ec_key_set_flags(ec_key1, flags);
	EXPECT_EQ(rc, 0);
	rc = zpc_ec_key_import_clear(ec_key1, pubkey, pubkeylen, privkey, privkeylen);
	EXPECT_EQ(rc, 0);
	rc = zpc_ecdsa_ctx_set_key(ec_ctx1, ec_key1);
	EXPECT_EQ(rc, 0);

	/* Import NIST test key into ec_key2 */
	rc = zpc_ec_key_set_curve(ec_key2, curve);
	EXPECT_EQ(rc, 0);
	rc = zpc_ec_key_set_type(ec_key2, type);
	EXPECT_EQ(rc, 0);
	if (mkvp != NULL) {
		rc = zpc_ec_key_set_mkvp(ec_key2, mkvp);
		EXPECT_EQ(rc, 0);
	} else {
		rc = zpc_ec_key_set_apqns(ec_key2, apqns);
		EXPECT_EQ(rc, 0);
	}
	rc = zpc_ec_key_set_flags(ec_key2, flags);
	EXPECT_EQ(rc, 0);
	rc = zpc_ec_key_import_clear(ec_key2, pubkey, pubkeylen, privkey, privkeylen);
	EXPECT_EQ(rc, 0);
	rc = zpc_ecdsa_ctx_set_key(ec_ctx2, ec_key2);
	EXPECT_EQ(rc, 0);

	/* Sign with first key */
	rc = zpc_ecdsa_sign(ec_ctx1, hash, hash_len, sigbuf, &sig_len);
	EXPECT_EQ(rc, 0);
	/* Verify created signature with 1st key */
	rc = zpc_ecdsa_verify(ec_ctx1, hash, hash_len, sigbuf, sig_len);
	EXPECT_EQ(rc, 0);
	/* Verify created signature with 2nd key */
	rc = zpc_ecdsa_verify(ec_ctx2, hash, hash_len, sigbuf, sig_len);
	EXPECT_EQ(rc, 0);
	/* Verify known signature from test vector with 1st key */
	rc = zpc_ecdsa_verify(ec_ctx1, hash, hash_len, sig, sig_len);
	EXPECT_EQ(rc, 0);
	/* Verify known signature from test vector with 2nd key */
	rc = zpc_ecdsa_verify(ec_ctx2, hash, hash_len, sig, sig_len);
	EXPECT_EQ(rc, 0);

	/* Create a random key. Note that random EC protected keys are not possible,
	 * because, unlike AES, we always have to create a secure key first via
	 * the host libs. So we cannot unset apqns as done in the aes tests. */
	rc = zpc_ecdsa_ctx_set_key(ec_ctx1, NULL);   /* Unset key. */
	EXPECT_EQ(rc, 0);
	rc = zpc_ecdsa_ctx_set_key(ec_ctx2, NULL);   /* Unset key. */
	EXPECT_EQ(rc, 0);
	rc = zpc_ec_key_set_curve(ec_key1, curve);
	EXPECT_EQ(rc, 0);
	rc = zpc_ec_key_generate(ec_key1);
	EXPECT_EQ(rc, 0);
	rc = zpc_ecdsa_ctx_set_key(ec_ctx1, ec_key1);
	EXPECT_EQ(rc, 0);
	rc = zpc_ecdsa_ctx_set_key(ec_ctx2, ec_key1);
	EXPECT_EQ(rc, 0);

	/* Perform sign/verify: ctx1 -> ctx2 */
	rc = zpc_ecdsa_sign(ec_ctx1, hash, hash_len, sigbuf, &sig_len);
	EXPECT_EQ(rc, 0);
	rc = zpc_ecdsa_verify(ec_ctx2, hash, hash_len, sigbuf, sig_len);
	EXPECT_EQ(rc, 0);

	/* Perform sign/verify: ctx2 -> ctx1 */
	rc = zpc_ecdsa_sign(ec_ctx2, hash, hash_len, sigbuf, &sig_len);
	EXPECT_EQ(rc, 0);
	rc = zpc_ecdsa_verify(ec_ctx1, hash, hash_len, sigbuf, sig_len);
	EXPECT_EQ(rc, 0);

	zpc_ec_key_free(&ec_key1);
	EXPECT_EQ(ec_key1, nullptr);
	zpc_ec_key_free(&ec_key2);
	EXPECT_EQ(ec_key2, nullptr);
	zpc_ecdsa_ctx_free(&ec_ctx1);
	EXPECT_EQ(ec_ctx1, nullptr);
	zpc_ecdsa_ctx_free(&ec_ctx2);
	EXPECT_EQ(ec_ctx2, nullptr);
}

TEST(ecdsa_ctx, wycheproof_kat)
{
	TESTLIB_ENV_EC_KEY_CHECK();

	__run_json("wycheproof/src/wycheproof/testvectors/ecdsa_webcrypto_test.json");
	__run_json("wycheproof/src/wycheproof/testvectors/eddsa_test.json");
	__run_json("wycheproof/src/wycheproof/testvectors/ed448_test.json");
}

TEST(ecdsa_ctx, nist_kat)
{
	TESTLIB_ENV_EC_KEY_CHECK();

	__run_json("nist_ecdsa.json");
	__run_json("nist_eddsa.json");
}

static zpc_ec_curve_t __str2curve(const char *str)
{
	if (strcmp(str, "P-256") == 0 || strcmp(str, "secp256r1") == 0)
		return ZPC_EC_CURVE_P256;
	else if (strcmp(str, "P-384") == 0 || strcmp(str, "secp384r1") == 0)
		return ZPC_EC_CURVE_P384;
	else if (strcmp(str, "P-521") == 0 || strcmp(str, "secp521r1") == 0)
		return ZPC_EC_CURVE_P521;
	else if (strcmp(str, "ed25519") == 0 || strcmp(str, "edwards25519") == 0)
		return ZPC_EC_CURVE_ED25519;
	else if (strcmp(str, "ed448") == 0 || strcmp(str, "edwards448") == 0)
		return ZPC_EC_CURVE_ED448;
	else
		return ZPC_EC_CURVE_INVALID;
}

static void __get_ec_params_from_json(json_object *jtmp, zpc_ec_curve_t curve,
				u8 *priv, unsigned int *privlen, u8 *pub, unsigned int *publen,
				u8 *msg, unsigned int *msglen, u8 *sig, unsigned int *siglen)
{
	json_object *jd, *jx, *jy, *jmsg, *jsig_r, *jsig_s;
	json_bool b;
	u8 *d = NULL, *x = NULL, *y = NULL, *r = NULL, *s = NULL, *m = NULL;
	const char *str;
	size_t mlen;
	const unsigned int curve2privlen[] = { 32, 48, 66 };
	const unsigned int curve2publen[] = { 64, 96, 132 };
	const unsigned int curve2siglen[] = { 64, 96, 132 };

	b = json_object_object_get_ex(jtmp, "msg", &jmsg);
	ASSERT_TRUE(b);
	b = json_object_object_get_ex(jtmp, "d", &jd);
	ASSERT_TRUE(b);
	b = json_object_object_get_ex(jtmp, "x", &jx);
	ASSERT_TRUE(b);
	b = json_object_object_get_ex(jtmp, "y", &jy);
	ASSERT_TRUE(b);
	b = json_object_object_get_ex(jtmp, "sig_r", &jsig_r);
	ASSERT_TRUE(b);
	b = json_object_object_get_ex(jtmp, "sig_s", &jsig_s);
	ASSERT_TRUE(b);

	str = json_object_get_string(jmsg);
	ASSERT_NE(str, nullptr);
	m = testlib_hexstr2buf(str, &mlen);
	ASSERT_NE(m, nullptr);

	str = json_object_get_string(jd);
	ASSERT_NE(str, nullptr);
	d = testlib_hexstr2fixedbuf(str, curve2privlen[curve]);
	ASSERT_NE(d, nullptr);

	str = json_object_get_string(jx);
	ASSERT_NE(str, nullptr);
	x = testlib_hexstr2fixedbuf(str, curve2publen[curve] / 2);
	ASSERT_NE(x, nullptr);

	str = json_object_get_string(jy);
	ASSERT_NE(str, nullptr);
	y = testlib_hexstr2fixedbuf(str, curve2publen[curve] / 2);
	ASSERT_NE(y, nullptr);

	str = json_object_get_string(jsig_r);
	ASSERT_NE(str, nullptr);
	r = testlib_hexstr2fixedbuf(str, curve2siglen[curve] / 2);
	ASSERT_NE(r, nullptr);

	str = json_object_get_string(jsig_s);
	ASSERT_NE(str, nullptr);
	s = testlib_hexstr2fixedbuf(str, curve2siglen[curve] / 2);
	ASSERT_NE(s, nullptr);

	memcpy(priv, d, curve2privlen[curve]);
	memcpy(pub, x, curve2publen[curve] / 2);
	memcpy(pub + curve2publen[curve] / 2, y, curve2publen[curve] / 2);
	memcpy(sig, r, curve2siglen[curve] / 2);
	memcpy(sig + curve2siglen[curve] / 2, s, curve2siglen[curve] / 2);
	memcpy(msg, m, mlen);

	*privlen = curve2privlen[curve];
	*publen = curve2publen[curve];
	*siglen = curve2siglen[curve];
	*msglen = mlen;

	free(d);
	free(m);
	free(x);
	free(y);
	free(r);
	free(s);
}

static void __get_ed_params_from_json(json_object *jtmp,
		u8 *priv, unsigned int *privlen, u8 *pub, unsigned int *publen,
		u8 *msg, unsigned int *msglen, u8 *sig, unsigned int *siglen)
{
	json_object *jd, *jq, *jm, *js;
	json_bool b;
	u8 *d = NULL, *q = NULL, *s = NULL, *m = NULL;
	const char *str;
	size_t mlen = 0, dlen = 0, qlen = 0, slen = 0;

	b = json_object_object_get_ex(jtmp, "msg", &jm);
	ASSERT_TRUE(b);
	b = json_object_object_get_ex(jtmp, "priv", &jd);
	ASSERT_TRUE(b);
	b = json_object_object_get_ex(jtmp, "pub", &jq);
	ASSERT_TRUE(b);
	b = json_object_object_get_ex(jtmp, "sig", &js);
	ASSERT_TRUE(b);

	str = json_object_get_string(jm);
	ASSERT_NE(str, nullptr);
	m = testlib_hexstr2buf(str, &mlen);
	/* m may be null, because ED curves can sign an empty msg */

	str = json_object_get_string(jd);
	ASSERT_NE(str, nullptr);
	d = testlib_hexstr2buf(str, &dlen);
	ASSERT_NE(d, nullptr);

	str = json_object_get_string(jq);
	ASSERT_NE(str, nullptr);
	q = testlib_hexstr2buf(str, &qlen);
	ASSERT_NE(q, nullptr);

	str = json_object_get_string(js);
	ASSERT_NE(str, nullptr);
	s = testlib_hexstr2buf(str, &slen);
	ASSERT_NE(s, nullptr);

	memcpy(priv, d, dlen);
	memcpy(pub, q, qlen);
	memcpy(sig, s, slen);
	if (mlen > 0)
		memcpy(msg, m, mlen);

	*privlen = dlen;
	*publen = qlen;
	*siglen = slen;
	*msglen = mlen;

	free(d);
	free(m);
	free(q);
	free(s);
}

static void __get_curve_from_json(json_object *jcurve, zpc_ec_curve_t *curve)
{
	const char *curve_str;

	curve_str = json_object_get_string(jcurve);
	ASSERT_NE(curve_str, nullptr);
	*curve = __str2curve(curve_str);
}

static void __get_result_from_json(json_object *jresult, int *valid)
{
	const char *str;

	*valid = 0;

	str = json_object_get_string(jresult);
	ASSERT_NE(str, nullptr);
	if (strcmp(str, "valid") == 0 || strcmp(str, "acceptable") == 0)
		*valid = 1;
}

/**
 * Get key material from json 'key' entry
 */
static void __get_key_from_json(json_object *jkey, zpc_ec_curve_t curve,
							unsigned char *pubbuf, unsigned int *publen,
							unsigned char *privbuf, unsigned int *privlen)
{
	json_object *jwx, *jwy, *jsk, *jpk;
	json_bool b;
	const char *str;
	u8 *d = NULL, *x = NULL, *y = NULL;
	const unsigned int curve2publen[] = { 64, 96, 132, 32, 57 };
	const unsigned int curve2privlen[] = { 32, 48, 66, 32, 57 };

	*publen = 0;
	*privlen = 0;

	b = json_object_object_get_ex(jkey, "wx", &jwx);
	b = json_object_object_get_ex(jkey, "wy", &jwy);
	if (b) {
		/* Here we are for ecdsa_webcrypto_test.json. This json file only
		 * contains verify tests, i.e. only public keys. */
		str = json_object_get_string(jwx);
		ASSERT_NE(str, nullptr);
		if (strlen(str) > curve2publen[curve] / 2 && str[0] == '0' && str[1] == '0') {
			str+=2;
		}
		x = testlib_hexstr2fixedbuf(str, curve2publen[curve] / 2);
		ASSERT_NE(x, nullptr);
		str = json_object_get_string(jwy);
		ASSERT_NE(str, nullptr);
		if (strlen(str) > curve2publen[curve] / 2 && str[0] == '0' && str[1] == '0') {
			str+=2;
		}
		y = testlib_hexstr2fixedbuf(str, curve2publen[curve] / 2);
		ASSERT_NE(y, nullptr);
		memcpy(pubbuf, x, curve2publen[curve] / 2);
		memcpy(pubbuf + curve2publen[curve] / 2, y, curve2publen[curve] / 2);
		*publen = curve2publen[curve];
		goto done;
	}

	b = json_object_object_get_ex(jkey, "pk", &jpk);
	b = json_object_object_get_ex(jkey, "sk", &jsk);
	if (b) {
		/* Here we are for eddsa_test.json and ed448_test.json. These two
		 * json files contain public and private keys. */
		str = json_object_get_string(jpk);
		ASSERT_NE(str, nullptr);
		y = testlib_hexstr2fixedbuf(str, curve2publen[curve]);
		ASSERT_NE(y, nullptr);
		str = json_object_get_string(jsk);
		ASSERT_NE(str, nullptr);
		d = testlib_hexstr2fixedbuf(str, curve2privlen[curve]);
		ASSERT_NE(d, nullptr);
		memcpy(pubbuf, y, curve2publen[curve]);
		memcpy(privbuf, d, curve2privlen[curve]);
		*publen = curve2publen[curve];
		*privlen = curve2privlen[curve];
	}

done:
	free(d);
	free(x);
	free(y);
}

static void __get_bytes_from_json(json_object *jobj, unsigned char *buf,
							unsigned int *len)
{
	const char *str;
	u8 *bytes = NULL;
	size_t num_bytes;

	*len = 0;

	str = json_object_get_string(jobj);
	ASSERT_NE(str, nullptr);

	bytes = testlib_hexstr2buf(str, &num_bytes);
	/* bytes may be NULL */
	if (num_bytes > 0) {
		memcpy(buf, bytes, num_bytes);
		*len = num_bytes;
	}

	free(bytes);
}

static void __run_sign_verify_test(zpc_ecdsa_ctx *ec_ctx,
						unsigned char *msgbuf, unsigned int msglen,
						unsigned char *sigbuf1, unsigned int *siglen1,
						unsigned int privlen)
{
	int rc;

	if (privlen > 0) {
		rc = zpc_ecdsa_sign(ec_ctx, msgbuf, msglen, sigbuf1, siglen1);
		EXPECT_EQ(rc, 0);

		rc = zpc_ecdsa_verify(ec_ctx, msgbuf, msglen, sigbuf1, *siglen1);
		EXPECT_EQ(rc, 0);
	}
}

static void __run_verify_kat_test(zpc_ecdsa_ctx *ec_ctx, zpc_ec_curve_t curve,
						unsigned char *msgbuf, unsigned int msglen,
						unsigned char *sigbuf2, unsigned int siglen2,
						int expected_valid)
{
	int rc;
	/*
	 * Note that for p521 CPACF expects 521 bits, padded on the leftmost
	 * significant bits with 7 zeros to form 528 bits or 66 bytes (octets).
	 * But all considered test vectors for p521 have input hashs/msgs up to
	 * 64 bytes, so let's use 64 bytes for the tests here.
	 */
	const unsigned int curve2msglen[] = { 32, 48, 64 };

	switch (curve) {
	case ZPC_EC_CURVE_P256:
	case ZPC_EC_CURVE_P384:
	case ZPC_EC_CURVE_P521:
		rc = zpc_ecdsa_verify(ec_ctx, msgbuf, msglen, sigbuf2, siglen2);
		if (msglen == curve2msglen[curve]) {
			/* For EC curves CPACF has fixed expected hash lengths via the CPACF
			 * parm block layout. So the actual hash length does not go into
			 * CPACF and we can verify a test signature only if the test vector
			 * msg length is equal to the expected CPACF hash buffer size. */
			if (expected_valid)
				EXPECT_EQ(rc, 0);
			else
				EXPECT_EQ(rc, ZPC_ERROR_EC_SIGNATURE_INVALID);
		}
		break;
	case ZPC_EC_CURVE_ED25519:
	case ZPC_EC_CURVE_ED448:
		/* For ED curves the hash/msg length is an input parm to the
		 * KDSA instruction, so we can verify any msglen */
		rc = zpc_ecdsa_verify(ec_ctx, msgbuf, msglen, sigbuf2, siglen2);
		if (expected_valid)
			EXPECT_EQ(rc, 0);
		else
			EXPECT_TRUE(rc != 0);
		break;
	default:
		break;
	}
}

static void __run_nist_tests(json_object *jtestgroups, struct zpc_ec_key *ec_key)
{
	size_t i, j;
	zpc_ec_curve_t curve;
	struct zpc_ecdsa_ctx *ec_ctx;
	json_object *jtmp, *jtests, *jcurve;
	json_bool b;
	int rc;

	rc = zpc_ecdsa_ctx_alloc(&ec_ctx);
	EXPECT_EQ(rc, 0);

	for (i = 0; i < (size_t)json_object_array_length(jtestgroups); i++) {

		jtmp = json_object_array_get_idx(jtestgroups, i);
		ASSERT_NE(jtmp, nullptr);

		b = json_object_object_get_ex(jtmp, "tests", &jtests);
		ASSERT_TRUE(b);

		for (j = 0; j < (size_t)json_object_array_length(jtests); j++) {

			u8 pubbuf[200] = { 0 }, privbuf[100] = { 0 };
			u8 sigbuf1[200] = { 0 }, sigbuf2[200] = { 0 }, msgbuf[4096] = { 0 };
			unsigned int siglen1 = sizeof(sigbuf1), siglen2 = sizeof(sigbuf2);
			unsigned int privlen, publen, msglen;

			jtmp = json_object_array_get_idx(jtests, j);
			ASSERT_NE(jtmp, nullptr);

			b = json_object_object_get_ex(jtmp, "curve", &jcurve);
			ASSERT_TRUE(b);

			__get_curve_from_json(jcurve, &curve);
			if (curve == ZPC_EC_CURVE_INVALID)
				continue;

			rc = zpc_ec_key_set_curve(ec_key, curve);
			EXPECT_EQ(rc, 0);

			switch (curve) {
			case ZPC_EC_CURVE_P256:
			case ZPC_EC_CURVE_P384:
			case ZPC_EC_CURVE_P521:
				__get_ec_params_from_json(jtmp, curve, privbuf, &privlen,
						pubbuf, &publen, msgbuf, &msglen, sigbuf2, &siglen1);
				break;
			case ZPC_EC_CURVE_ED25519:
			case ZPC_EC_CURVE_ED448:
				__get_ed_params_from_json(jtmp, privbuf, &privlen,
						pubbuf, &publen, msgbuf, &msglen, sigbuf2, &siglen1);
				break;
			default:
				continue;
			}
			siglen2 = siglen1;

			/* Import clear key from test vector */
			rc = zpc_ec_key_import_clear(ec_key, pubbuf, publen, privbuf, privlen);
			EXPECT_EQ(rc, 0);
			rc = zpc_ecdsa_ctx_set_key(ec_ctx, ec_key);
			EXPECT_EQ(rc, 0);

			/* Perform tests */
			__run_sign_verify_test(ec_ctx, msgbuf, msglen, sigbuf1, &siglen1, privlen);
			__run_verify_kat_test(ec_ctx, curve, msgbuf, msglen, sigbuf2, siglen2, 1);

			/* Unset key. */
			rc = zpc_ecdsa_ctx_set_key(ec_ctx, NULL);
			EXPECT_EQ(rc, 0);
		}
	}

	zpc_ecdsa_ctx_free(&ec_ctx);
	EXPECT_EQ(ec_ctx, nullptr);
}

static void __run_wycheproof_tests(json_object *jtestgroups, struct zpc_ec_key *ec_key)
{
	json_object *jkey, *jcurve, *jtests, *jtmp, *jmsg, *jsig, *jresult;
	json_bool b;
	size_t i, j;
	struct zpc_ecdsa_ctx *ec_ctx;
	zpc_ec_curve_t curve;
	int valid, rc;

	rc = zpc_ecdsa_ctx_alloc(&ec_ctx);
	EXPECT_EQ(rc, 0);

	for (i = 0; i < (size_t)json_object_array_length(jtestgroups); i++) {

		u8 sigbuf1[200] = { 0 }, sigbuf2[200] = { 0 }, msgbuf[4096] = { 0 };
		u8 pubbuf[200] = { 0 }, privbuf[100] = { 0 };
		unsigned int siglen1 = sizeof(sigbuf1), siglen2 = sizeof(sigbuf2);
		unsigned int privlen, publen, msglen;

		jtmp = json_object_array_get_idx(jtestgroups, i);
		ASSERT_NE(jtmp, nullptr);

		/* Get 'key' entry with key material */
		b = json_object_object_get_ex(jtmp, "key", &jkey);
		ASSERT_TRUE(b);

		/* Get curve from json 'key' entry */
		b = json_object_object_get_ex(jkey, "curve", &jcurve);
		ASSERT_TRUE(b);
		__get_curve_from_json(jcurve, &curve);
		if (curve == ZPC_EC_CURVE_INVALID)
			continue;
		rc = zpc_ec_key_set_curve(ec_key, curve);
		EXPECT_EQ(rc, 0);

		/* Get clear key from json 'key' entry */
		__get_key_from_json(jkey, curve, (unsigned char *)&pubbuf, &publen,
						(unsigned char *)&privbuf, &privlen);
		rc = zpc_ec_key_import_clear(ec_key, pubbuf, publen, privbuf, privlen);
		EXPECT_EQ(rc, 0);
		rc = zpc_ecdsa_ctx_set_key(ec_ctx, ec_key);
		EXPECT_EQ(rc, 0);

		/* Perform tests for this key */
		b = json_object_object_get_ex(jtmp, "tests", &jtests);
		ASSERT_TRUE(b);

		for (j = 0; j < (size_t)json_object_array_length(jtests); j++) {

			jtmp = json_object_array_get_idx(jtests, j);
			ASSERT_NE(jtmp, nullptr);

			/* Get msg and signature */
			b = json_object_object_get_ex(jtmp, "msg", &jmsg);
			ASSERT_TRUE(b);
			b = json_object_object_get_ex(jtmp, "sig", &jsig);
			ASSERT_TRUE(b);
			b = json_object_object_get_ex(jtmp, "result", &jresult);
			ASSERT_TRUE(b);

			/* Get test params */
			__get_bytes_from_json(jmsg, (unsigned char *)&msgbuf, &msglen);
			__get_bytes_from_json(jsig, (unsigned char *)&sigbuf2, &siglen2);
			__get_result_from_json(jresult, &valid);

			/* Perform tests */
			__run_sign_verify_test(ec_ctx, msgbuf, msglen, sigbuf1, &siglen1, privlen);
			__run_verify_kat_test(ec_ctx, curve, msgbuf, msglen, sigbuf2, siglen2, valid);
		}

		rc = zpc_ecdsa_ctx_set_key(ec_ctx, NULL);
		EXPECT_EQ(rc, 0);
	}

	zpc_ecdsa_ctx_free(&ec_ctx);
	EXPECT_EQ(ec_ctx, nullptr);
}

static void __run_json(const char *json)
{
	const char *tv = json;
	const char *mkvp, *apqns[257];
	struct zpc_ec_key *ec_key;
	unsigned int flags;
	int rc, type;
	json_object *jtestgroups, *jfile;
	json_bool b;

	type = testlib_env_ec_key_type();
	flags = testlib_env_ec_key_flags();
	mkvp = testlib_env_ec_key_mkvp();
	(void)testlib_env_ec_key_apqns(apqns);

	TESTLIB_EC_SW_CAPS_CHECK(type);

	TESTLIB_EC_KERNEL_CAPS_CHECK(type, mkvp, apqns);

	rc = zpc_ec_key_alloc(&ec_key);
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
	rc = zpc_ec_key_set_flags(ec_key, flags);
	EXPECT_EQ(rc, 0);

	jfile = json_object_from_file(tv);
	ASSERT_NE(jfile, nullptr);

	b = json_object_object_get_ex(jfile, "testGroups", &jtestgroups);
	ASSERT_TRUE(b);

	if (strstr(json, "nist"))
		__run_nist_tests(jtestgroups, ec_key);
	else
		__run_wycheproof_tests(jtestgroups, ec_key);

	zpc_ec_key_free(&ec_key);
	EXPECT_EQ(ec_key, nullptr);
}

TEST(ecdsa_ctx, rederive_protected_key)
{
	unsigned int pubkeylen, privkeylen, msg_len, sig_len;
	zpc_ec_curve_t curve;
	unsigned char buf[4096];
	const char *mkvp, *apqns[257];
	struct zpc_ec_key *ec_key;
	struct zpc_ecdsa_ctx *ec_ctx;
	unsigned int flags;
	int type, rc;

	TESTLIB_ENV_EC_KEY_CHECK();

	TESTLIB_EC_HW_CAPS_CHECK();

	curve = testlib_env_ec_key_curve();
	type = testlib_env_ec_key_type();
	flags = testlib_env_ec_key_flags();
	mkvp = testlib_env_ec_key_mkvp();
	(void)testlib_env_ec_key_apqns(apqns);

	TESTLIB_EC_SW_CAPS_CHECK(type);

	TESTLIB_EC_KERNEL_CAPS_CHECK(type, mkvp, apqns);

	const u8 *pubkey = ec_tv[curve].pubkey;
	const u8 *privkey = ec_tv[curve].privkey;
	const u8 *msg = ec_tv[curve].msg;
	const u8 *sig = ec_tv[curve].sig;
	pubkeylen = ec_tv[curve].pubkey_len;
	privkeylen = ec_tv[curve].privkey_len;
	msg_len = ec_tv[curve].msg_len;
	sig_len = ec_tv[curve].sig_len;

	rc = zpc_ec_key_alloc(&ec_key);
	EXPECT_EQ(rc, 0);
	rc = zpc_ecdsa_ctx_alloc(&ec_ctx);
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
	rc = zpc_ec_key_set_flags(ec_key, flags);
	EXPECT_EQ(rc, 0);

	rc = zpc_ec_key_set_curve(ec_key, curve);
	EXPECT_EQ(rc, 0);

	/* Import test key: creates the secure and protected key internally */
	rc = zpc_ec_key_import_clear(ec_key, pubkey, pubkeylen, privkey, privkeylen);
	EXPECT_EQ(rc, 0);
	rc = zpc_ecdsa_ctx_set_key(ec_ctx, ec_key);
	EXPECT_EQ(rc, 0);

	/* Invalidate protected key */
	force_WKaVP_mismatch(ec_ctx);

	/* Sign: invalid protkey is re-created from secure key */
	rc = zpc_ecdsa_sign(ec_ctx, msg, msg_len, buf, &sig_len);
	EXPECT_EQ(rc, 0);

	/* Verify locally created signature */
	memcpy(buf, sig, sig_len);
	rc = zpc_ecdsa_verify(ec_ctx, msg, msg_len, buf, sig_len);
	EXPECT_EQ(rc, 0);

	/* Verify known signature from NIST vector */
	rc = zpc_ecdsa_verify(ec_ctx, msg, msg_len, sig, sig_len);
	EXPECT_EQ(rc, 0);

	zpc_ecdsa_ctx_free(&ec_ctx);
	EXPECT_EQ(ec_ctx, nullptr);
	zpc_ec_key_free(&ec_key);
	EXPECT_EQ(ec_key, nullptr);
}

TEST(ecdsa_ctx, reencipher)
{
	unsigned int pubkeylen, privkeylen, msg_len, sig_len;
	unsigned char buf[4096];
	const char *mkvp, *apqns[257];
	struct zpc_ec_key *ec_key;
	struct zpc_ecdsa_ctx *ec_ctx;
	unsigned int flags;
	int type, rc;
	zpc_ec_curve_t curve;

	TESTLIB_ENV_EC_KEY_CHECK();

	TESTLIB_EC_HW_CAPS_CHECK();

	curve = testlib_env_ec_key_curve();
	type = testlib_env_ec_key_type();
	flags = testlib_env_ec_key_flags();
	mkvp = testlib_env_ec_key_mkvp();
	(void)testlib_env_ec_key_apqns(apqns);

	TESTLIB_EC_SW_CAPS_CHECK(type);

	TESTLIB_EC_KERNEL_CAPS_CHECK(type, mkvp, apqns);

	TESTLIB_EC_NEW_MK_CHECK(type, mkvp, apqns);

	const u8 *pubkey = ec_tv[curve].pubkey;
	const u8 *privkey = ec_tv[curve].privkey;
	const u8 *msg = ec_tv[curve].msg;
	const u8 *sig = ec_tv[curve].sig;
	pubkeylen = ec_tv[curve].pubkey_len;
	privkeylen = ec_tv[curve].privkey_len;
	msg_len = ec_tv[curve].msg_len;
	sig_len = ec_tv[curve].sig_len;

	rc = zpc_ec_key_alloc(&ec_key);
	EXPECT_EQ(rc, 0);
	rc = zpc_ecdsa_ctx_alloc(&ec_ctx);
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
	rc = zpc_ec_key_set_flags(ec_key, flags);
	EXPECT_EQ(rc, 0);

	rc = zpc_ec_key_set_curve(ec_key, curve);
	EXPECT_EQ(rc, 0);

	rc = zpc_ec_key_import_clear(ec_key, pubkey, pubkeylen, privkey, privkeylen);
	EXPECT_EQ(rc, 0);

	rc = zpc_ec_key_reencipher(ec_key, ZPC_EC_KEY_REENCIPHER_CURRENT_TO_NEW);
	EXPECT_EQ(rc, 0);

	memset(&ec_key->cur, 0, sizeof(ec_key->cur)); /* destroy current secure key */

	rc = zpc_ecdsa_ctx_set_key(ec_ctx, ec_key);
	EXPECT_EQ(rc, 0);
	memset(&ec_key->prot, 0, sizeof(ec_key->prot)); /* destroy cached protected key */

	force_WKaVP_mismatch(ec_ctx); /* enforce WKaVP mismaych in ctx */

	/* Sign: internally re-creates the secure key from new MK and re-creates
	 * the protkey from created secure key. */
	rc = zpc_ecdsa_sign(ec_ctx, msg, msg_len, buf, &sig_len);
	EXPECT_EQ(rc, 0);

	/* Verify locally created signature */
	rc = zpc_ecdsa_verify(ec_ctx, msg, msg_len, buf, sig_len);
	EXPECT_EQ(rc, 0);

	/* Verify known signature from NIST vector */
	rc = zpc_ecdsa_verify(ec_ctx, msg, msg_len, sig, sig_len);
	EXPECT_EQ(rc, 0);

	zpc_ecdsa_ctx_free(&ec_ctx);
	EXPECT_EQ(ec_ctx, nullptr);
	zpc_ec_key_free(&ec_key);
	EXPECT_EQ(ec_key, nullptr);
}

TEST(ecdsa_ctx, use_existing)
{
	unsigned int pubkeylen, privkeylen, msg_len, sig_len, signature_len;
	unsigned char buf[4096], signature[132];
	unsigned int buflen;
	const char *mkvp, *apqns[257];
	struct zpc_ec_key *ec_key, *ec_key2;
	struct zpc_ecdsa_ctx *ec_ctx;
	unsigned int flags;
	int type, rc;
	zpc_ec_curve_t curve;

	TESTLIB_ENV_EC_KEY_CHECK();

	TESTLIB_EC_HW_CAPS_CHECK();

	curve = testlib_env_ec_key_curve();
	type = testlib_env_ec_key_type();
	flags = testlib_env_ec_key_flags();
	mkvp = testlib_env_ec_key_mkvp();
	(void)testlib_env_ec_key_apqns(apqns);

	TESTLIB_EC_SW_CAPS_CHECK(type);

	TESTLIB_EC_KERNEL_CAPS_CHECK(type, mkvp, apqns);

	TESTLIB_EC_NEW_MK_CHECK(type, mkvp, apqns);

	const u8 *pubkey = ec_tv[curve].pubkey;
	const u8 *privkey = ec_tv[curve].privkey;
	const u8 *msg = ec_tv[curve].msg;
	pubkeylen = ec_tv[curve].pubkey_len;
	privkeylen = ec_tv[curve].privkey_len;
	msg_len = ec_tv[curve].msg_len;
	sig_len = ec_tv[curve].sig_len;

	rc = zpc_ec_key_alloc(&ec_key);
	EXPECT_EQ(rc, 0);
	rc = zpc_ec_key_alloc(&ec_key2);
	EXPECT_EQ(rc, 0);
	rc = zpc_ecdsa_ctx_alloc(&ec_ctx);
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

	rc = zpc_ec_key_set_flags(ec_key, flags);
	EXPECT_EQ(rc, 0);

	rc = zpc_ec_key_set_curve(ec_key, curve);
	EXPECT_EQ(rc, 0);

	rc = zpc_ec_key_import_clear(ec_key, pubkey, pubkeylen, privkey, privkeylen);
	EXPECT_EQ(rc, 0);

	buflen = sizeof(buf);
	rc = zpc_ec_key_export(ec_key, buf, &buflen);
	EXPECT_EQ(rc, 0);

	/* At this point we have a valid secure key in buf. Now let's assume that
	 * host libs are not available. The existing secure key/public key pair is
	 * still usable even without host libs. */

	rc = zpc_ec_key_set_type(ec_key2, type);
	EXPECT_EQ(rc, 0);
	if (mkvp != NULL) {
		rc = zpc_ec_key_set_mkvp(ec_key2, mkvp);
		EXPECT_EQ(rc, 0);
	} else {
		rc = zpc_ec_key_set_apqns(ec_key2, apqns);
		EXPECT_EQ(rc, 0);
	}

	rc = zpc_ec_key_set_flags(ec_key2, flags);
	EXPECT_EQ(rc, 0);

	rc = zpc_ec_key_set_curve(ec_key2, curve);
	EXPECT_EQ(rc, 0);

	/* Import existing secure key ... */
	rc = zpc_ec_key_import(ec_key2, buf, buflen);
	EXPECT_EQ(rc, 0);

	/* Add public key to key object (leaves imported secure key untouched) */
	rc = zpc_ec_key_import_clear(ec_key2, pubkey, pubkeylen, NULL, 0);
	EXPECT_EQ(rc, 0);

	/* At this point the already existing secure key and the corresponding
	 * public key are imported into ec_key2. */

	rc = zpc_ecdsa_ctx_set_key(ec_ctx, ec_key2);
	EXPECT_EQ(rc, 0);

	/* Now use ec_key2 for sign/verify */
	signature_len = sizeof(signature);
	rc = zpc_ecdsa_sign(ec_ctx, msg, msg_len, signature, &signature_len);
	EXPECT_EQ(rc, 0);
	EXPECT_EQ(sig_len, signature_len);

	rc = zpc_ecdsa_verify(ec_ctx, msg, msg_len, signature, signature_len);
	EXPECT_EQ(rc, 0);

	zpc_ecdsa_ctx_free(&ec_ctx);
	EXPECT_EQ(ec_ctx, nullptr);
	zpc_ec_key_free(&ec_key);
	EXPECT_EQ(ec_key, nullptr);
	zpc_ec_key_free(&ec_key2);
	EXPECT_EQ(ec_key2, nullptr);
}

static void __task(struct zpc_ec_key *ec_key)
{
	struct zpc_ecdsa_ctx *ec_ctx;
	unsigned char sigbuf[200];
	unsigned int msglen, siglen;
	int rc, i;

	const u8 *msg = ec_tv[ec_key->curve].msg;
	const u8 *sig = ec_tv[ec_key->curve].sig;
	msglen = ec_tv[ec_key->curve].msg_len;
	siglen = ec_tv[ec_key->curve].sig_len;

	rc = zpc_ecdsa_ctx_alloc(&ec_ctx);
	EXPECT_EQ(rc, 0);

	rc = zpc_ecdsa_ctx_set_key(ec_ctx, ec_key);
	EXPECT_EQ(rc, 0);

	for (i = 0; i < 1000; i++) {
		/* Sign */
		force_WKaVP_mismatch(ec_ctx);
		rc = zpc_ecdsa_sign(ec_ctx, msg, msglen, sigbuf, &siglen);
		EXPECT_EQ(rc, 0);

		/* All curves: Verify against created signature and known signature
		 * from NIST test vector. We cannot specify the random-value for prime
		 * curves, so we never get to the NIST result by signing here. */
		rc = zpc_ecdsa_verify(ec_ctx, msg, msglen, sigbuf, siglen);
		EXPECT_EQ(rc, 0);
		rc = zpc_ecdsa_verify(ec_ctx, msg, msglen, sig, siglen);
		EXPECT_EQ(rc, 0);

		/* Edwards curves do not use a random value when signing, so we can
		 * check if the locally created signature matches the known
		 * signature. */
		if (ec_key->curve == ZPC_EC_CURVE_ED25519 ||
			ec_key->curve == ZPC_EC_CURVE_ED448) {
			EXPECT_TRUE(memcmp(sigbuf, sig, siglen) == 0);
		}
	}

	zpc_ecdsa_ctx_free(&ec_ctx);
	EXPECT_EQ(ec_ctx, nullptr);
}

TEST(ecdsa_ctx, threads)
{
	unsigned int pubkeylen, privkeylen;
	const char *mkvp, *apqns[257];
	struct zpc_ec_key *ec_key;
	unsigned int flags;
	int type, rc, i;
	std::thread *t[500];
	zpc_ec_curve_t curve;

	TESTLIB_ENV_EC_KEY_CHECK();

	TESTLIB_EC_HW_CAPS_CHECK();

	curve = testlib_env_ec_key_curve();
	type = testlib_env_ec_key_type();
	flags = testlib_env_ec_key_flags();
	mkvp = testlib_env_ec_key_mkvp();
	(void)testlib_env_ec_key_apqns(apqns);

	TESTLIB_EC_SW_CAPS_CHECK(type);

	TESTLIB_EC_KERNEL_CAPS_CHECK(type, mkvp, apqns);

	TESTLIB_EC_NEW_MK_CHECK(type, mkvp, apqns);

	const u8 *pubkey = ec_tv[curve].pubkey;
	const u8 *privkey = ec_tv[curve].privkey;
	pubkeylen = ec_tv[curve].pubkey_len;
	privkeylen = ec_tv[curve].privkey_len;

	rc = zpc_ec_key_alloc(&ec_key);
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
	rc = zpc_ec_key_set_flags(ec_key, flags);
	EXPECT_EQ(rc, 0);

	rc = zpc_ec_key_set_curve(ec_key, curve);
	EXPECT_EQ(rc, 0);

	rc = zpc_ec_key_import_clear(ec_key, pubkey, pubkeylen, privkey, privkeylen);
	EXPECT_EQ(rc, 0);

	for (i = 0; i < 500; i++) {
		t[i] = new std::thread(__task, ec_key);
	}

	/* Do something with key object while threads are working with it. */
	rc = zpc_ec_key_reencipher(ec_key, ZPC_EC_KEY_REENCIPHER_CURRENT_TO_NEW);
	EXPECT_EQ(rc, 0);
	memset(&ec_key->cur, 0, sizeof(ec_key->cur)); /* destroy current secure key */

	for (i = 0; i < 500; i++) {
		memset(&ec_key->prot, 0, sizeof(ec_key->prot)); /* destroy cached protected key */
		usleep(1);
	}

	for (i = 0; i < 500; i++) {
		t[i]->join();
		delete t[i];
	}

	zpc_ec_key_free(&ec_key);
	EXPECT_EQ(ec_key, nullptr);
}
