/*
 * Copyright IBM Corp. 2021
 *
 * libzpc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "gtest/gtest.h"
#include "testlib.h"

#include "zpc/aes_key.h"

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
