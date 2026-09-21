/*
 * Copyright IBM Corp. 2021
 *
 * libzpc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "misc.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

static int ishexdigit(const char);
static unsigned char hexdigit2byte(char);
static char byte2hexdigit(unsigned char);

int
local_rng(u8 *output, size_t bytes)
{
	int ranfd;
	int rlen;
	unsigned int totallen = 0;

	ranfd = open("/dev/prandom", O_RDONLY);
	if (ranfd < 0)
		ranfd = open("/dev/urandom", O_RDONLY);
	if (ranfd >= 0) {
		do {
			rlen = read(ranfd, output + totallen, bytes - totallen);
			totallen += rlen;
		} while (totallen < bytes);
		close(ranfd);
		return 0;
	}

	return -1;
}

int
hexstr2buf(u8 * buf, size_t *buflen, const char *hex)
{
	size_t i;

	assert(buf != NULL);
	assert(buflen != NULL);
	assert(*buflen != 0);
	assert(hex != NULL);

	/* Skip possible leading '0x'. */
	if (strlen(hex) >= 2 && hex[0] == '0' && hex[1] == 'x')
		hex += 2;
	if (strlen(hex) == 0 || strlen(hex) % 2 != 0
	    || strlen(hex) / 2 > *buflen)
		return -1;

	memset(buf, 0, *buflen);

	for (i = 0; i + 1 < strlen(hex); i += 2) {
		if (!ishexdigit(hex[i]) || !ishexdigit(hex[i + 1]))
			return -1;      /* Parse error. */

		buf[i / 2] = hexdigit2byte(hex[i]) << 4;
		buf[i / 2] += hexdigit2byte(hex[i + 1]);
	}

	*buflen = strlen(hex) / 2;
	return 0;
}

void
buf2hexstr(char *hex, size_t hexlen, const unsigned char *buf, size_t buflen)
{
	size_t i;

	assert(hex != NULL);
	assert(buf != NULL);
	assert(buflen > 0);
	assert(hexlen >= 2 * buflen);

	memset(hex, 0, hexlen);

	for (i = 0; i < buflen; i++) {
		hex[2 * i] = byte2hexdigit(buf[i] >> 4);
		hex[2 * i + 1] = byte2hexdigit(buf[i] & 0xf);
	}
	hex[2 * i] = '\0';
}

static int
ishexdigit(const char d)
{
	return ((d >= '0' && d <= '9')
	    || (d >= 'A' && d <= 'F') || (d >= 'a' && d <= 'f'));
}

static unsigned char
hexdigit2byte(char d)
{
	const char noff = '0' - 0;
	const char uoff = 'A' - 10;
	const char loff = 'a' - 10;

	return (d >= 'a' ? d - loff : (d >= 'A' ? d - uoff : d - noff));
}

static char
byte2hexdigit(unsigned char b)
{
	const char noff = '0' - 0;
	const char loff = 'a' - 10;

	assert((b & 0xf0) == 0);

	return (b >= 10 ? b + loff : b + noff);
}
