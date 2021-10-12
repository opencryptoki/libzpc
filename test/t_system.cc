/*
 * Copyright IBM Corp. 2021
 *
 * libzpc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "gtest/gtest.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

TEST(system, platform)
{
	const union {
		long _;
		char little;
	} is_endian = { 1 };

	EXPECT_TRUE(sizeof(char) == 1);
	EXPECT_TRUE(sizeof(short) == 2);
	EXPECT_TRUE(sizeof(int) == 4);
	EXPECT_TRUE(sizeof(size_t) == 8);
	EXPECT_TRUE(sizeof(long) == 8);
	EXPECT_TRUE(sizeof(long long) == 8);

	EXPECT_FALSE(is_endian.little);
}

TEST(system, dev_pkey)
{
	int pkeyfd;

	EXPECT_GE(pkeyfd = open("/dev/pkey", O_RDWR), 0);

	if (pkeyfd >= 0) {
		close(pkeyfd);
		pkeyfd = -1;
	}
}
