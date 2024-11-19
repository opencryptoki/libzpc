/*
 * Copyright IBM Corp. 2021
 *
 * libzpc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "gtest/gtest.h"
#include "testlib.h"

#include "zpc/aes_key.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

TEST(testlib, env_aes_key_mkvp)
{
	const char *oldenv = NULL, *mkvp;
	int rc;

	/* Save environment. */
	oldenv = getenv("ZPC_TEST_AES_KEY_MKVP");

	rc = setenv("ZPC_TEST_AES_KEY_MKVP", "abcde", 1);
	ASSERT_EQ(rc, 0);

	mkvp = testlib_env_aes_key_mkvp();
	EXPECT_TRUE(strcmp(mkvp, "abcde") == 0);

	rc = unsetenv("ZPC_TEST_AES_KEY_MKVP");
	ASSERT_EQ(rc, 0);

	mkvp = testlib_env_aes_key_mkvp();
	EXPECT_EQ(mkvp, nullptr);

	if (oldenv != NULL) {
		/* Restore environment. */
		rc = setenv("ZPC_TEST_AES_KEY_MKVP", oldenv, 1);
		ASSERT_EQ(rc, 0);
	}
}

TEST(testlib, env_aes_key_apqns)
{
	const char *oldenv = NULL;
	const char *apqns[257];
	int rc;

	/* Save environment. */
	oldenv = getenv("ZPC_TEST_AES_KEY_APQNS");

	rc = setenv("ZPC_TEST_AES_KEY_APQNS", "abcde fg\nhi\tj,k \n\t, l", 1);
	ASSERT_EQ(rc, 0);

	rc = testlib_env_aes_key_apqns(apqns);
	EXPECT_TRUE(strcmp(apqns[0], "abcde") == 0);
	EXPECT_TRUE(strcmp(apqns[1], "fg") == 0);
	EXPECT_TRUE(strcmp(apqns[2], "hi") == 0);
	EXPECT_TRUE(strcmp(apqns[3], "j") == 0);
	EXPECT_TRUE(strcmp(apqns[4], "k") == 0);
	EXPECT_TRUE(strcmp(apqns[5], "l") == 0);
	EXPECT_EQ(apqns[6], nullptr);

	rc = unsetenv("ZPC_TEST_AES_KEY_APQNS");
	ASSERT_EQ(rc, 0);

	rc = testlib_env_aes_key_apqns(apqns);
	EXPECT_EQ(rc, -1);

	if (oldenv != NULL) {
		/* Restore environment. */
		rc = setenv("ZPC_TEST_AES_KEY_APQNS", oldenv, 1);
		ASSERT_EQ(rc, 0);
	}
}

TEST(testlib, env_aes_key_size)
{
	const char *oldenv = NULL;
	int rc, size;
	size_t i;
	struct {
		const char *sizestr;
		const int sizeint;
	} kat[] = {
		{
			"",
			-1
		},
		{
			"abcde",
			-1
		},
		{
			"-2147483649", /* -max(4 byte int) - 2 = -2^31 - 1 */
			-1
		},
		{
			"2147483648", /* max(4 byte int) + 1 = 2^31 */
			-1
		},
		{
			"-1",
			-1
		},
		{
			"-0xa",
			-10
		},
		{
			"-0XFf",
			-255
		},
		{
			"-011",
			-9
		},
		{
			"256",
			256
		},
		{
			"0xB",
			11
		},
		{
			"0XfF",
			255
		},
		{
			"012",
			10
		}
	};

	/* Save environment. */
	oldenv = getenv("ZPC_TEST_AES_KEY_SIZE");

	for (i = 0; i < NMEMB(kat); i++)  {
		rc = setenv("ZPC_TEST_AES_KEY_SIZE", kat[i].sizestr, 1);
		ASSERT_EQ(rc, 0);

		size = testlib_env_aes_key_size();
		EXPECT_EQ(size, kat[i].sizeint);

		rc = unsetenv("ZPC_TEST_AES_KEY_SIZE");
		ASSERT_EQ(rc, 0);

	}

	if (oldenv != NULL) {
		/* Restore environment. */
		rc = setenv("ZPC_TEST_AES_KEY_SIZE", oldenv, 1);
		ASSERT_EQ(rc, 0);
	}
}

TEST(testlib, env_aes_key_type)
{
	const char *oldenv = NULL;
	int rc, type;

	/* Save environment. */
	oldenv = getenv("ZPC_TEST_AES_KEY_TYPE");

	rc = setenv("ZPC_TEST_AES_KEY_TYPE", "abcde", 1);
	ASSERT_EQ(rc, 0);
	type = testlib_env_aes_key_type();
	EXPECT_EQ(type, -1);
	rc = unsetenv("ZPC_TEST_AES_KEY_TYPE");
	ASSERT_EQ(rc, 0);

	rc = setenv("ZPC_TEST_AES_KEY_TYPE", "ZPC_AES_KEY_TYPE_CCA_DATA", 1);
	ASSERT_EQ(rc, 0);
	type = testlib_env_aes_key_type();
	EXPECT_EQ(type, ZPC_AES_KEY_TYPE_CCA_DATA);
	rc = unsetenv("ZPC_TEST_AES_KEY_TYPE");
	ASSERT_EQ(rc, 0);

	rc = setenv("ZPC_TEST_AES_KEY_TYPE", "ZPC_AES_KEY_TYPE_CCA_CIPHER", 1);
	ASSERT_EQ(rc, 0);
	type = testlib_env_aes_key_type();
	EXPECT_EQ(type, ZPC_AES_KEY_TYPE_CCA_CIPHER);
	rc = unsetenv("ZPC_TEST_AES_KEY_TYPE");
	ASSERT_EQ(rc, 0);

	rc = setenv("ZPC_TEST_AES_KEY_TYPE", "ZPC_AES_KEY_TYPE_EP11", 1);
	ASSERT_EQ(rc, 0);
	type = testlib_env_aes_key_type();
	EXPECT_EQ(type, ZPC_AES_KEY_TYPE_EP11);
	rc = unsetenv("ZPC_TEST_AES_KEY_TYPE");
	ASSERT_EQ(rc, 0);

	rc = setenv("ZPC_TEST_AES_KEY_TYPE", "ZPC_AES_KEY_TYPE_PVSECRET", 1);
	ASSERT_EQ(rc, 0);
	type = testlib_env_aes_key_type();
	EXPECT_EQ(type, ZPC_AES_KEY_TYPE_PVSECRET);
	rc = unsetenv("ZPC_TEST_AES_KEY_TYPE");
	ASSERT_EQ(rc, 0);

	if (oldenv != NULL) {
		/* Restore environment. */
		rc = setenv("ZPC_TEST_AES_KEY_TYPE", oldenv, 1);
		ASSERT_EQ(rc, 0);
	}
}

TEST(testlib, env_aes_key_flags)
{
	const char *oldenv = NULL;
	int rc;
	unsigned int flags;
	size_t i;
	struct {
		const char *flagsstr;
		const unsigned int flagsint;
	} kat[] = {
		{
			"",
			0
		},
		{
			"abcde",
			0
		},
		{
			"-4294967297", /* max(4 byte uint) - 1 = -2^32 - 1 */
			0
		},
		{
			"4294967296", /* max(4 byte int) + 1 = 2^32 */
			0
		},
		{
			"-1",
			0
		},
		{
			"-0xa",
			0
		},
		{
			"-0XFf",
			0
		},
		{
			"-011",
			0
		},
		{
			"256",
			256
		},
		{
			"0xB",
			11
		},
		{
			"0XfF",
			255
		},
		{
			"012",
			10
		}
	};

	/* Save environment. */
	oldenv = getenv("ZPC_TEST_AES_KEY_FLAGS");

	for (i = 0; i < NMEMB(kat); i++)  {
		rc = setenv("ZPC_TEST_AES_KEY_FLAGS", kat[i].flagsstr, 1);
		ASSERT_EQ(rc, 0);

		flags = testlib_env_aes_key_flags();
		EXPECT_EQ(flags, kat[i].flagsint);

		rc = unsetenv("ZPC_TEST_AES_KEY_FLAGS");
		ASSERT_EQ(rc, 0);

	}

	if (oldenv != NULL) {
		/* Restore environment. */
		rc = setenv("ZPC_TEST_AES_KEY_FLAGS", oldenv, 1);
		ASSERT_EQ(rc, 0);
	}
}

TEST(testlib, env_ec_key_type)
{
	const char *oldenv = NULL;
	int rc, type;

	/* Save environment. */
	oldenv = getenv("ZPC_TEST_EC_KEY_TYPE");

	rc = setenv("ZPC_TEST_EC_KEY_TYPE", "abcde", 1);
	ASSERT_EQ(rc, 0);
	type = testlib_env_ec_key_type();
	EXPECT_EQ(type, -1);
	rc = unsetenv("ZPC_TEST_EC_KEY_TYPE");
	ASSERT_EQ(rc, 0);

	rc = setenv("ZPC_TEST_EC_KEY_TYPE", "ZPC_EC_KEY_TYPE_CCA", 1);
	ASSERT_EQ(rc, 0);
	type = testlib_env_ec_key_type();
	EXPECT_EQ(type, ZPC_EC_KEY_TYPE_CCA);
	rc = unsetenv("ZPC_TEST_EC_KEY_TYPE");
	ASSERT_EQ(rc, 0);

	rc = setenv("ZPC_TEST_EC_KEY_TYPE", "ZPC_EC_KEY_TYPE_EP11", 1);
	ASSERT_EQ(rc, 0);
	type = testlib_env_ec_key_type();
	EXPECT_EQ(type, ZPC_EC_KEY_TYPE_EP11);
	rc = unsetenv("ZPC_TEST_EC_KEY_TYPE");
	ASSERT_EQ(rc, 0);

	rc = setenv("ZPC_TEST_EC_KEY_TYPE", "ZPC_EC_KEY_TYPE_PVSECRET", 1);
	ASSERT_EQ(rc, 0);
	type = testlib_env_ec_key_type();
	EXPECT_EQ(type, ZPC_EC_KEY_TYPE_PVSECRET);
	rc = unsetenv("ZPC_TEST_EC_KEY_TYPE");
	ASSERT_EQ(rc, 0);

	if (oldenv != NULL) {
		/* Restore environment. */
		rc = setenv("ZPC_TEST_EC_KEY_TYPE", oldenv, 1);
		ASSERT_EQ(rc, 0);
	}
}

TEST(testlib, env_ec_key_curve)
{
	const char *oldenv = NULL;
	int rc, curve;
	size_t i;
	struct {
		const char *curvestr;
		const int curveint;
	} kat[] = {
		{ "", -2 }, { "blahblah", -1 }, { "p256", 0 }, { "p384", 1 },
		{ "p521", 2 }, { "ed25519", 3 }, { "ed448", 4 }, { "P256", 0 },
		{ "ED25519", 3 }
	};

	/* Save environment. */
	oldenv = getenv("ZPC_TEST_EC_KEY_CURVE");

	for (i = 0; i < NMEMB(kat); i++)  {
		rc = setenv("ZPC_TEST_EC_KEY_CURVE", kat[i].curvestr, 1);
		ASSERT_EQ(rc, 0);

		curve = testlib_env_ec_key_curve();
		EXPECT_EQ(curve, kat[i].curveint);

		rc = unsetenv("ZPC_TEST_EC_KEY_CURVE");
		ASSERT_EQ(rc, 0);

	}

	if (oldenv != NULL) {
		/* Restore environment. */
		rc = setenv("ZPC_TEST_EC_KEY_CURVE", oldenv, 1);
		ASSERT_EQ(rc, 0);
	}
}

TEST(testlib, hexstr2buf)
{
	const u8 buf1[] = {0xde, 0xad, 0xbe, 0xef};
	const u8 buf2[] = {0x01, 0x23, 0x45, 0x67, 0x89,
					   0xaA, 0xbB, 0xcC, 0xdD, 0xeE, 0xfF};
	u8 *buf;
	size_t buflen;

	buf = testlib_hexstr2buf(NULL, &buflen);
	EXPECT_EQ(buflen, (size_t)0);
	EXPECT_EQ(buf, nullptr);

	buf = testlib_hexstr2buf("", &buflen);
	EXPECT_EQ(buflen, (size_t)0);
	EXPECT_EQ(buf, nullptr);
	free(buf);

	buf = testlib_hexstr2buf("0x", &buflen);
	EXPECT_EQ(buflen, (size_t)0);
	EXPECT_EQ(buf, nullptr);
	free(buf);

	buf = testlib_hexstr2buf("0x 1", &buflen);
	EXPECT_EQ(buflen, (size_t)0);
	EXPECT_EQ(buf, nullptr);
	free(buf);

	buf = testlib_hexstr2buf("0xa", &buflen);
	EXPECT_EQ(buflen, (size_t)0);
	EXPECT_EQ(buf, nullptr);
	free(buf);

	buf = testlib_hexstr2buf("A", &buflen);
	EXPECT_EQ(buflen, (size_t)0);
	EXPECT_EQ(buf, nullptr);
	free(buf);
	buf = testlib_hexstr2buf("9a", &buflen);
	EXPECT_EQ(buflen, (size_t)1);
	ASSERT_NE(buf, nullptr);
	EXPECT_EQ(buf[0], 0x9a);
	free(buf);

	buf = testlib_hexstr2buf("0xBc", &buflen);
	EXPECT_EQ(buflen, (size_t)1);
	ASSERT_NE(buf, nullptr);
	EXPECT_EQ(buf[0], 0xBc);
	free(buf);

	buf = testlib_hexstr2buf("crypto", NULL);
	EXPECT_EQ(buflen, (size_t)1);
	EXPECT_EQ(buf, nullptr);
	free(buf);

	buf = testlib_hexstr2buf("deadbeef", &buflen);
	ASSERT_NE(buf, nullptr);
	EXPECT_EQ(buflen, (size_t)4);
	EXPECT_TRUE(memcmp(buf, buf1, buflen) == 0);
	free(buf);

	buf = testlib_hexstr2buf("0x0123456789aAbBcCdDeEfF", &buflen);
	ASSERT_NE(buf, nullptr);
	EXPECT_EQ(buflen, (size_t)11);
	EXPECT_TRUE(memcmp(buf, buf2, buflen) == 0);
	free(buf);

	buf = testlib_hexstr2buf("0123456789aAbBcCdDeEfF", &buflen);
	ASSERT_NE(buf, nullptr);
	EXPECT_EQ(buflen, (size_t)11);
	EXPECT_TRUE(memcmp(buf, buf2, buflen) == 0);
	free(buf);
}

TEST(testlib, buf2hexstr)
{
	const u8 buf1[] = {0xde, 0xad, 0xbe, 0xef};
	const u8 buf2[] = {0x01, 0x23, 0x45, 0x67, 0x89,
					   0xaA, 0xbB, 0xcC, 0xdD, 0xeE, 0xfF};
	char *hexstr;

	hexstr = testlib_buf2hexstr(NULL, 0);
	EXPECT_EQ(hexstr, nullptr);
	free(hexstr);

	hexstr = testlib_buf2hexstr(NULL, 1);
	EXPECT_EQ(hexstr, nullptr);
	free(hexstr);

	hexstr = testlib_buf2hexstr(buf1, 0);
	EXPECT_EQ(hexstr, nullptr);
	free(hexstr);

	hexstr = testlib_buf2hexstr(buf1, SIZE_MAX / 2);
	EXPECT_EQ(hexstr, nullptr);
	free(hexstr);

	hexstr = testlib_buf2hexstr(buf1, sizeof(buf1));
	ASSERT_NE(hexstr, nullptr);
	EXPECT_TRUE(strcmp(hexstr, "deadbeef") == 0);
	free(hexstr);

	hexstr = testlib_buf2hexstr(buf2, sizeof(buf2));
	ASSERT_NE(hexstr, nullptr);
	EXPECT_TRUE(strcmp(hexstr, "0123456789aabbccddeeff") == 0);
	free(hexstr);
}
