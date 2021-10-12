/*
 * Copyright IBM Corp. 2021
 *
 * libzpc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "testlib.h"

#include "zpc/aes_key.h"

#include <assert.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#define ENV_AES_KEY_MKVP	"ZPC_TEST_AES_KEY_MKVP"
#define ENV_AES_KEY_APQNS	"ZPC_TEST_AES_KEY_APQNS"
#define ENV_AES_KEY_SIZE	"ZPC_TEST_AES_KEY_SIZE"
#define ENV_AES_KEY_TYPE	"ZPC_TEST_AES_KEY_TYPE"
#define ENV_AES_KEY_FLAGS	"ZPC_TEST_AES_KEY_FLAGS"

static int ishexdigit(const char);
static unsigned char hexdigit2byte(char);
static char byte2hexdigit(unsigned char);

const char *
testlib_env_aes_key_mkvp(void)
{
	char *env;

	env = getenv(ENV_AES_KEY_MKVP);
	return env;
}

int
testlib_env_aes_key_apqns(const char *apqns[257])
{
	char *env, *tok;
	int i;

	env = getenv(ENV_AES_KEY_APQNS);
	if (env == NULL)
		return -1;

	i = 0;
	tok = strtok(env, " \t\n,");
	while (tok && i < 256) {
		apqns[i] = tok;

		tok = strtok(NULL, " \t\n,");
		i++;
	}
	apqns[i] = NULL;
	return 0;
}

int
testlib_env_aes_key_size(void)
{
	int size = -1;	/* Invalid key-size. */
    long sizelong = LONG_MIN;
	char *env = NULL, *endptr = NULL;

	env = getenv(ENV_AES_KEY_SIZE);
	if (env == NULL || env[0] == '\0')
		goto ret;

    sizelong = strtol(env, &endptr, 0);
    if (*endptr != '\0' || sizelong < INT_MIN || sizelong > INT_MAX)
            goto ret;

    size = (int)sizelong;
ret:
    return size;
}

int
testlib_env_aes_key_type(void)
{
    int type = -1;	/* Invalid key-type. */
	char *env = NULL;

	env = getenv(ENV_AES_KEY_TYPE);
	if (env == NULL)
		goto ret;

	if (strcmp(env, "ZPC_AES_KEY_TYPE_CCA_DATA") == 0)
		type = ZPC_AES_KEY_TYPE_CCA_DATA;
	else if (strcmp(env, "ZPC_AES_KEY_TYPE_CCA_CIPHER") == 0)
		type = ZPC_AES_KEY_TYPE_CCA_CIPHER;
	else if (strcmp(env, "ZPC_AES_KEY_TYPE_EP11") == 0)
		type = ZPC_AES_KEY_TYPE_EP11;

ret:
    return type;
}

unsigned int testlib_env_aes_key_flags(void)
{
    int flags = 0;	/* Default flags. */
    long flagslong = LONG_MIN;
	char *env = NULL, *endptr = NULL;

	env = getenv(ENV_AES_KEY_FLAGS);
	if (env == NULL || env[0] == '\0')
		goto ret;

    flagslong = strtol(env, &endptr, 0);
    if (*endptr != '\0' || flagslong < 0 || flagslong > UINT_MAX)
        goto ret;

    flags = (unsigned int)flagslong;
ret:
    return flags;
}

unsigned char *
testlib_hexstr2buf(const char *hexstr, size_t *buflen)
{
	unsigned char *buf = NULL;
	const char *ptr;
	size_t len, i;
	int err = 1;

	if (buflen != NULL)
		*buflen = 0;

	ptr = hexstr;
	if (ptr == NULL)
		goto ret;

	/* Skip possible leading '0x'. */
	if (strlen(ptr) > 2 && ptr[0] == '0' && ptr[1] == 'x')
		ptr += 2;

	len = strlen(ptr);
	if (len % 2 != 0 || len == 0)
		goto ret;

	buf = (unsigned char *)calloc(1, len / 2);
	if (buf == NULL)
		goto ret;

	for (i = 0; i + 1 < len; i += 2) {
		if (!ishexdigit(ptr[i]) || !ishexdigit(ptr[i + 1]))
			goto ret;

		buf[i / 2] = hexdigit2byte(ptr[i]) << 4;
		buf[i / 2] += hexdigit2byte(ptr[i + 1]);

		if (buflen != NULL)
			(*buflen)++;
	}

	err = 0;
ret:
	if (err) {
		free(buf);
		buf = NULL;
	}
	return buf;
}

char *
testlib_buf2hexstr(const unsigned char *buf, size_t buflen)
{
	char *hexstr = NULL;
	int err = 1;
	size_t i;

	if (buf == NULL || buflen == 0)
		goto ret;

	if (buflen * 2 + 1 < buflen)
		goto ret;

	hexstr = (char *)calloc(1, buflen * 2 + 1);
	if (hexstr == NULL)
		goto ret;

	for (i = 0; i < buflen; i++) {
		hexstr[2 * i] = byte2hexdigit(buf[i] >> 4);
		hexstr[2 * i + 1] = byte2hexdigit(buf[i] & 0xf);
	}
	hexstr[2 * i] = '\0';

	err = 0;
ret:
	if (err) {
		free(hexstr);
		buf = 0;
	}
	return hexstr;
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
