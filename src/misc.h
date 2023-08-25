/*
 * Copyright IBM Corp. 2021
 *
 * libzpc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef MISC_H
# define MISC_H

# include <stddef.h>

# define UNUSED(x)	(void)(x)
# define NMEMB(x)	(sizeof(x) / sizeof(x[0]))

# define __packed __attribute__((packed))

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;

/* Maximum binary MKVP byte-length. */
# define MAX_MKVPLEN            32

void memzero_secure(void *, size_t);
int memcmp_consttime(const void *, const void *, size_t);
int hexstr2buf(u8 *, size_t *, const char *);
void buf2hexstr(char *, size_t, const unsigned char *, size_t);
int local_rng(u8 *output, size_t bytes);

#endif
