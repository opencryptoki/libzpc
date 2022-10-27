/*
 * Copyright IBM Corp. 2021
 *
 * libzpc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "gtest/gtest.h"
#include "zpc/error.h"

#include <stdlib.h>
#include <string.h>

TEST(error, string)
{
	const char *errstr;

	errstr = zpc_error_string(0);
	EXPECT_TRUE(strcmp(errstr, "success") == 0);

	errstr = zpc_error_string(-1);
	EXPECT_TRUE(strcmp(errstr, "undefined error code") == 0);

	errstr = zpc_error_string(71);
	EXPECT_TRUE(strcmp(errstr, "LAST") == 0);
}
