/*
 * Copyright IBM Corp. 2021
 *
 * libzpc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "gtest/gtest.h"
#include "testlib.h"

#include "zpc/aes_key.h"
#include "zpc/ecc_key.h"

#include <stdio.h>

/*
 * Check for invalid test environment variable values.
 * Unset environment variables are ignored. The corresponding tests are
 * skipped later.
 */

/*
 * Check environment variables for test cases
 * that use zpc_aes_key objects.
 */
TEST(environment, test_aes_key)
{
	int size;

	size = testlib_env_aes_key_size();
	switch(size) {
	case -1:   /* fall-through */
	case 128:   /* fall-through */
	case 192:   /* fall-through */
	case 256:   /* fall-through */
		break;
	default:
		ASSERT_TRUE(size == 128 || size == 192 || size == 256);
		break;
	}
}

/*
 * Check environment variables for test cases
 * that use zpc_ec_key objects.
 */
TEST(environment, test_ec_key)
{
	int curve;

	curve = testlib_env_ec_key_curve();
	switch(curve) {
	case ZPC_EC_CURVE_NOT_SET: /* fall-through */
	case ZPC_EC_CURVE_P256:    /* fall-through */
	case ZPC_EC_CURVE_P384:    /* fall-through */
	case ZPC_EC_CURVE_P521:    /* fall-through */
	case ZPC_EC_CURVE_ED25519: /* fall-through */
	case ZPC_EC_CURVE_ED448:   /* fall-through */
		break;
	default:
		ASSERT_TRUE(curve >= ZPC_EC_CURVE_P256 && curve <= ZPC_EC_CURVE_ED448);
		break;
	}
}
