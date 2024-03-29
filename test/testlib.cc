/*
 * Copyright IBM Corp. 2021
 *
 * libzpc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "testlib.h"

#include "zpc/aes_key.h"
#include "zpc/ecc_key.h"

#include <assert.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#define ENV_AES_KEY_MKVP	"ZPC_TEST_AES_KEY_MKVP"
#define ENV_AES_KEY_APQNS	"ZPC_TEST_AES_KEY_APQNS"
#define ENV_AES_KEY_SIZE	"ZPC_TEST_AES_KEY_SIZE"
#define ENV_AES_KEY_TYPE	"ZPC_TEST_AES_KEY_TYPE"
#define ENV_AES_KEY_FLAGS	"ZPC_TEST_AES_KEY_FLAGS"

#define ENV_EC_KEY_MKVP		"ZPC_TEST_EC_KEY_MKVP"
#define ENV_EC_KEY_APQNS	"ZPC_TEST_EC_KEY_APQNS"
#define ENV_EC_KEY_CURVE	"ZPC_TEST_EC_KEY_CURVE"
#define ENV_EC_KEY_TYPE		"ZPC_TEST_EC_KEY_TYPE"
#define ENV_EC_KEY_FLAGS	"ZPC_TEST_EC_KEY_FLAGS"

static int ishexdigit(const char);
static unsigned char hexdigit2byte(char);
static char byte2hexdigit(unsigned char);


/*
 * Note: array index is curve's type.
 * From NIST test vectors.
 */
const struct EC_TEST_VECTOR ec_tv[5] = {
	{
		.curve = ZPC_EC_CURVE_P256,
		.privkey = {
			0x51, 0x9b, 0x42, 0x3d, 0x71, 0x5f, 0x8b, 0x58,
			0x1f, 0x4f, 0xa8, 0xee, 0x59, 0xf4, 0x77, 0x1a,
			0x5b, 0x44, 0xc8, 0x13, 0x0b, 0x4e, 0x3e, 0xac,
			0xca, 0x54, 0xa5, 0x6d, 0xda, 0x72, 0xb4, 0x64 },
		.privkey_len = 32,
		.pubkey = {
			0x1c, 0xcb, 0xe9, 0x1c, 0x07, 0x5f, 0xc7, 0xf4,
			0xf0, 0x33, 0xbf, 0xa2, 0x48, 0xdb, 0x8f, 0xcc,
			0xd3, 0x56, 0x5d, 0xe9, 0x4b, 0xbf, 0xb1, 0x2f,
			0x3c, 0x59, 0xff, 0x46, 0xc2, 0x71, 0xbf, 0x83,
			0xce, 0x40, 0x14, 0xc6, 0x88, 0x11, 0xf9, 0xa2,
			0x1a, 0x1f, 0xdb, 0x2c, 0x0e, 0x61, 0x13, 0xe0,
			0x6d, 0xb7, 0xca, 0x93, 0xb7, 0x40, 0x4e, 0x78,
			0xdc, 0x7c, 0xcd, 0x5c, 0xa8, 0x9a, 0x4c, 0xa9 },
		.pubkey_len = 64,
		.msg = {
			0x44, 0xac, 0xf6, 0xb7, 0xe3, 0x6c, 0x13, 0x42,
			0xc2, 0xc5, 0x89, 0x72, 0x04, 0xfe, 0x09, 0x50,
			0x4e, 0x1e, 0x2e, 0xfb, 0x1a, 0x90, 0x03, 0x77,
			0xdb, 0xc4, 0xe7, 0xa6, 0xa1, 0x33, 0xec, 0x56 },
		.msg_len = 32,
		.sig = {
			0xf3, 0xac, 0x80, 0x61, 0xb5, 0x14, 0x79, 0x5b,
			0x88, 0x43, 0xe3, 0xd6, 0x62, 0x95, 0x27, 0xed,
			0x2a, 0xfd, 0x6b, 0x1f, 0x6a, 0x55, 0x5a, 0x7a,
			0xca, 0xbb, 0x5e, 0x6f, 0x79, 0xc8, 0xc2, 0xac,
			0x8b, 0xf7, 0x78, 0x19, 0xca, 0x05, 0xa6, 0xb2,
			0x78, 0x6c, 0x76, 0x26, 0x2b, 0xf7, 0x37, 0x1c,
			0xef, 0x97, 0xb2, 0x18, 0xe9, 0x6f, 0x17, 0x5a,
			0x3c, 0xcd, 0xda, 0x2a, 0xcc, 0x05, 0x89, 0x03 },
		.sig_len = 64,
	},
	{
		.curve = ZPC_EC_CURVE_P384,
		.privkey = {
			0xad, 0xca, 0x36, 0x4e, 0xf1, 0x44, 0xa2, 0x1d,
			0xf6, 0x4b, 0x16, 0x36, 0x15, 0xe8, 0x34, 0x9c,
			0xf7, 0x4e, 0xe9, 0xdb, 0xf7, 0x28, 0x10, 0x42,
			0x15, 0xc5, 0x32, 0x07, 0x3a, 0x7f, 0x74, 0xe2,
			0xf6, 0x73, 0x85, 0x77, 0x9f, 0x7f, 0x74, 0xab,
			0x34, 0x4c, 0xc3, 0xc7, 0xda, 0x06, 0x1c, 0xf6 },
		.privkey_len = 48,
		.pubkey = {
			0xef, 0x94, 0x8d, 0xaa, 0xe6, 0x82, 0x42, 0x33,
			0x0a, 0x73, 0x58, 0xef, 0x73, 0xf2, 0x3b, 0x56,
			0xc0, 0x7e, 0x37, 0x12, 0x62, 0x66, 0xdb, 0x3f,
			0xa6, 0xee, 0xa2, 0x33, 0xa0, 0x4a, 0x9b, 0x3e,
			0x49, 0x15, 0x23, 0x3d, 0xd6, 0x75, 0x44, 0x27,
			0xcd, 0x4b, 0x71, 0xb7, 0x58, 0x54, 0x07, 0x7d,
			0x00, 0x94, 0x53, 0xef, 0x18, 0x28, 0xea, 0xff,
			0x9e, 0x17, 0xc8, 0x56, 0xd4, 0xfc, 0x18, 0x95,
			0xab, 0x60, 0x05, 0x13, 0x12, 0xc3, 0xe1, 0xdb,
			0x1e, 0x37, 0x66, 0x56, 0x64, 0x38, 0xb2, 0x99,
			0x0c, 0xbf, 0x99, 0x45, 0xc2, 0x54, 0x56, 0x19,
			0xe3, 0xe0, 0x14, 0x5b, 0xc6, 0xa7, 0x90, 0x04 },
		.pubkey_len = 96,
		.msg = {
			0xf8, 0xd0, 0x17, 0x04, 0x79, 0xb2, 0xd1, 0xa8,
			0xf5, 0x0c, 0x80, 0x55, 0x6e, 0x67, 0xff, 0x34,
			0x55, 0x92, 0xc8, 0xb7, 0xdc, 0xda, 0x4e, 0x4f,
			0x60, 0x99, 0xf9, 0x93, 0xc1, 0xa7, 0x1b, 0xff,
			0x6d, 0x3b, 0x60, 0x19, 0x07, 0x15, 0xae, 0x12,
			0x15, 0xa8, 0xa7, 0x59, 0xa8, 0xeb, 0x13, 0xdf },
		.msg_len = 48,
		.sig = {
			0xdd, 0xa9, 0x94, 0xb9, 0xc4, 0x28, 0xb5, 0x7e,
			0x9f, 0x8b, 0xba, 0xeb, 0xba, 0x0d, 0x68, 0x2e,
			0x3a, 0xac, 0x6e, 0xd8, 0x28, 0xe3, 0xa1, 0xe9,
			0x9a, 0x7f, 0xc4, 0xc8, 0x04, 0xbf, 0xf8, 0xdf,
			0x15, 0x11, 0x37, 0xf5, 0x39, 0xc7, 0x38, 0x9d,
			0x80, 0xe2, 0x3d, 0x9f, 0x3e, 0xe4, 0x97, 0xbf,
			0xa0, 0xd6, 0xb1, 0x0c, 0xef, 0xfd, 0x0e, 0x1b,
			0x29, 0xcf, 0x78, 0x44, 0x76, 0xf9, 0x17, 0x3b,
			0xa6, 0xec, 0xd2, 0xcf, 0xc7, 0x92, 0x97, 0x25,
			0xf2, 0xd6, 0xe2, 0x4e, 0x0d, 0xb5, 0xa4, 0x72,
			0x16, 0x83, 0x64, 0x0e, 0xaa, 0x2b, 0xbe, 0x15,
			0x1f, 0xb5, 0x75, 0x60, 0xf9, 0xce, 0x59, 0x4b },
		.sig_len = 96,
	},
	{
		.curve = ZPC_EC_CURVE_P521,
		.privkey = {
			0x01, 0xf9, 0x86, 0x96, 0x77, 0x22, 0x21, 0xe6,
			0xcc, 0xcd, 0x55, 0x69, 0xed, 0x8a, 0xed, 0x3c,
			0x43, 0x5e, 0xe8, 0x6a, 0x04, 0x68, 0x9c, 0x7a,
			0x64, 0xd2, 0x0c, 0x30, 0xf6, 0xfe, 0x1c, 0x59,
			0xcc, 0x10, 0xc6, 0xd2, 0x91, 0x02, 0x61, 0xd3,
			0x0c, 0x3b, 0x96, 0x11, 0x7a, 0x66, 0x9e, 0x19,
			0xcf, 0xe5, 0xb6, 0x96, 0xb6, 0x8f, 0xee, 0xac,
			0xf6, 0x1f, 0x6a, 0x3d, 0xea, 0x55, 0xe6, 0xe5,
			0x83, 0x7a },
		.privkey_len = 66,
		.pubkey = {
			0x00, 0x70, 0x02, 0x87, 0x2c, 0x20, 0x0e, 0x16,
			0xd5, 0x7e, 0x8e, 0x53, 0xf7, 0xbc, 0xe6, 0xe9,
			0xa7, 0x83, 0x2c, 0x38, 0x7f, 0x6f, 0x9c, 0x29,
			0xc6, 0xb7, 0x55, 0x26, 0x26, 0x2c, 0x57, 0xbc,
			0x2b, 0x56, 0xd6, 0x3e, 0x95, 0x58, 0xc5, 0x76,
			0x1c, 0x1d, 0x62, 0x70, 0x83, 0x57, 0xf5, 0x86,
			0xd3, 0xaa, 0xb4, 0x1c, 0x6a, 0x7c, 0xa3, 0xbf,
			0x6c, 0x32, 0xd9, 0xc3, 0xca, 0x40, 0xf9, 0xa2,
			0x79, 0x6a, 0x01, 0xfe, 0x3e, 0x52, 0x47, 0x2e,
			0xf2, 0x24, 0xfb, 0x38, 0xd5, 0xa0, 0xa1, 0x48,
			0x75, 0xb5, 0x2c, 0x2f, 0x50, 0xb8, 0x2b, 0x99,
			0xee, 0xa9, 0x8d, 0x82, 0x6c, 0x77, 0xe6, 0xa9,
			0xcc, 0xf7, 0x98, 0xde, 0x5f, 0xfa, 0x92, 0xa0,
			0xd6, 0x59, 0x65, 0xf7, 0x40, 0xc7, 0x02, 0xa3,
			0x02, 0x7b, 0xe6, 0x6b, 0x9c, 0x84, 0x4f, 0x1b,
			0x2e, 0x96, 0xc1, 0x34, 0xeb, 0x3f, 0xdf, 0x3e,
			0xdd, 0xdc, 0xf1, 0x1c },
		.pubkey_len = 132,
		.msg = {
			0x72, 0x30, 0x64, 0x2b, 0x79, 0xee, 0xd2, 0xfd,
			0x50, 0xf1, 0x9f, 0x79, 0xf9, 0x43, 0xd6, 0x7d,
			0x6e, 0xf6, 0x09, 0xec, 0x06, 0xc9, 0xad, 0xbb,
			0x4b, 0x0a, 0x62, 0x12, 0x69, 0x26, 0x08, 0x0e,
			0xcd, 0x47, 0x49, 0x22, 0xd1, 0xaf, 0x6c, 0x01,
			0xf4, 0xc3, 0x54, 0xaf, 0xfd, 0xe0, 0x16, 0xb2,
			0x84, 0xb1, 0x3d, 0xbb, 0x31, 0x22, 0x55, 0x5d,
			0xea, 0x2a, 0x2e, 0x6c, 0xa2, 0xa3, 0x57, 0xdc },
		.msg_len = 64,
		.sig = {
			0x00, 0xd7, 0x32, 0xba, 0x8b, 0x3e, 0x9c, 0x9e,
			0x0a, 0x49, 0x52, 0x49, 0xe1, 0x52, 0xe5, 0xbe,
			0xe6, 0x9d, 0x94, 0xe9, 0xff, 0x01, 0x2d, 0x00,
			0x1b, 0x14, 0x0d, 0x4b, 0x5d, 0x08, 0x2a, 0xa9,
			0xdf, 0x77, 0xe1, 0x0b, 0x65, 0xf1, 0x15, 0xa5,
			0x94, 0xa5, 0x01, 0x14, 0x72, 0x2d, 0xb4, 0x2f,
			0xa5, 0xfb, 0xe4, 0x57, 0xc5, 0xbd, 0x05, 0xe7,
			0xac, 0x7e, 0xe5, 0x10, 0xaa, 0x68, 0xfe, 0x7b,
			0x1e, 0x7f, 0x01, 0x34, 0xac, 0x5e, 0x1e, 0xe3,
			0x39, 0x72, 0x7d, 0xf8, 0x0c, 0x35, 0xff, 0x5b,
			0x28, 0x91, 0x59, 0x6d, 0xd1, 0x4d, 0x6c, 0xfd,
			0x13, 0x7b, 0xaf, 0xd5, 0x0a, 0xb9, 0x8e, 0x2c,
			0x1a, 0xb4, 0x00, 0x8a, 0x0b, 0xd0, 0x35, 0x52,
			0x61, 0x8d, 0x21, 0x79, 0x12, 0xa9, 0xec, 0x50,
			0x2a, 0x90, 0x2f, 0x23, 0x53, 0xe7, 0x57, 0xc3,
			0xb5, 0x77, 0x63, 0x09, 0xf7, 0xf2, 0xcf, 0xeb,
			0xf9, 0x13, 0xe9, 0xcd },
		.sig_len = 132,
	},
	{
		.curve = ZPC_EC_CURVE_ED25519,
		.privkey = {
			0x83, 0x3f, 0xe6, 0x24, 0x09, 0x23, 0x7b, 0x9d,
			0x62, 0xec, 0x77, 0x58, 0x75, 0x20, 0x91, 0x1e,
			0x9a, 0x75, 0x9c, 0xec, 0x1d, 0x19, 0x75, 0x5b,
			0x7d, 0xa9, 0x01, 0xb9, 0x6d, 0xca, 0x3d, 0x42 },
		.privkey_len = 32,
		.pubkey = {
			0xec, 0x17, 0x2b, 0x93, 0xad, 0x5e, 0x56, 0x3b,
			0xf4, 0x93, 0x2c, 0x70,	0xe1, 0x24, 0x50, 0x34,
			0xc3, 0x54, 0x67, 0xef, 0x2e, 0xfd, 0x4d, 0x64,
			0xeb, 0xf8, 0x19, 0x68, 0x34, 0x67, 0xe2, 0xbf },
		.pubkey_len = 32,
		.msg = {
			0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba,
			0xcc, 0x41, 0x73, 0x49, 0xae, 0x20, 0x41, 0x31,
			0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2,
			0x0a, 0x9e, 0xee, 0xe6, 0x4b, 0x55, 0xd3, 0x9a,
			0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8,
			0x36, 0xba, 0x3c, 0x23, 0xa3, 0xfe, 0xeb, 0xbd,
			0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8, 0x0e,
			0x2a, 0x9a, 0xc9, 0x4f, 0xa5, 0x4c, 0xa4, 0x9f },
		.msg_len = 64,
		.sig = {
			0xdc, 0x2a, 0x44, 0x59, 0xe7, 0x36, 0x96, 0x33,
			0xa5, 0x2b, 0x1b, 0xf2, 0x77, 0x83, 0x9a, 0x00,
			0x20, 0x10, 0x09, 0xa3, 0xef, 0xbf, 0x3e, 0xcb,
			0x69, 0xbe, 0xa2, 0x18, 0x6c, 0x26, 0xb5, 0x89,
			0x09, 0x35, 0x1f, 0xc9, 0xac, 0x90, 0xb3, 0xec,
			0xfd, 0xfb, 0xc7, 0xc6, 0x64, 0x31, 0xe0, 0x30,
			0x3d, 0xca, 0x17, 0x9c, 0x13, 0x8a, 0xc1, 0x7a,
			0xd9, 0xbe, 0xf1, 0x17, 0x73, 0x31, 0xa7, 0x04 },
		.sig_len = 64,
	},
	{
		.curve = ZPC_EC_CURVE_ED448,
		.privkey = {
			0xcd, 0x23, 0xd2, 0x4f, 0x71, 0x42, 0x74, 0xe7,
			0x44, 0x34, 0x32, 0x37, 0xb9, 0x32, 0x90, 0xf5,
			0x11, 0xf6, 0x42, 0x5f, 0x98, 0xe6, 0x44, 0x59,
			0xff, 0x20, 0x3e, 0x89, 0x85, 0x08, 0x3f, 0xfd,
			0xf6, 0x05, 0x00, 0x55, 0x3a, 0xbc, 0x0e, 0x05,
			0xcd, 0x02, 0x18, 0x4b, 0xdb, 0x89, 0xc4, 0xcc,
			0xd6, 0x7e, 0x18, 0x79, 0x51, 0x26, 0x7e, 0xb3,
			0x28 },
		.privkey_len = 57,
		.pubkey = {
			0xdc, 0xea, 0x9e, 0x78, 0xf3, 0x5a, 0x1b, 0xf3,
			0x49, 0x9a, 0x83, 0x1b, 0x10, 0xb8, 0x6c, 0x90,
			0xaa, 0xc0, 0x1c, 0xd8, 0x4b, 0x67, 0xa0, 0x10,
			0x9b, 0x55, 0xa3, 0x6e, 0x93, 0x28, 0xb1, 0xe3,
			0x65, 0xfc, 0xe1, 0x61, 0xd7, 0x1c, 0xe7, 0x13,
			0x1a, 0x54, 0x3e, 0xa4, 0xcb, 0x5f, 0x7e, 0x9f,
			0x1d, 0x8b, 0x00, 0x69, 0x64, 0x47, 0x00, 0x14,
			0x00 },
		.pubkey_len = 57,
		.msg = {
			0x0c, 0x3e, 0x54, 0x40, 0x74, 0xec, 0x63, 0xb0,
			0x26, 0x5e, 0x0c },
		.msg_len = 11,
		.sig = {
			0x1f, 0x0a, 0x88, 0x88, 0xce, 0x25, 0xe8, 0xd4,
			0x58, 0xa2, 0x11, 0x30, 0x87, 0x9b, 0x84, 0x0a,
			0x90, 0x89, 0xd9, 0x99, 0xaa, 0xba, 0x03, 0x9e,
			0xaf, 0x3e, 0x3a, 0xfa, 0x09, 0x0a, 0x09, 0xd3,
			0x89, 0xdb, 0xa8, 0x2c, 0x4f, 0xf2, 0xae, 0x8a,
			0xc5, 0xcd, 0xfb, 0x7c, 0x55, 0xe9, 0x4d, 0x5d,
			0x96, 0x1a, 0x29, 0xfe, 0x01, 0x09, 0x94, 0x1e,
			0x00, 0xb8, 0xdb, 0xde, 0xea, 0x6d, 0x3b, 0x05,
			0x10, 0x68, 0xdf, 0x72, 0x54, 0xc0, 0xcd, 0xc1,
			0x29, 0xcb, 0xe6, 0x2d, 0xb2, 0xdc, 0x95, 0x7d,
			0xbb, 0x47, 0xb5, 0x1f, 0xd3, 0xf2, 0x13, 0xfb,
			0x86, 0x98, 0xf0, 0x64, 0x77, 0x42, 0x50, 0xa5,
			0x02, 0x89, 0x61, 0xc9, 0xbf, 0x8f, 0xfd, 0x97,
			0x3f, 0xe5, 0xd5, 0xc2, 0x06, 0x49, 0x2b, 0x14,
			0x0e, 0x00 },
		.sig_len = 114,
	},
};

const char *
testlib_env_aes_key_mkvp(void)
{
	char *env;

	env = getenv(ENV_AES_KEY_MKVP);
	return env;
}

const char *
testlib_env_ec_key_mkvp(void)
{
	char *env;

	env = getenv(ENV_EC_KEY_MKVP);
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
testlib_env_ec_key_apqns(const char *apqns[257])
{
	char *env, *tok;
	int i;

	env = getenv(ENV_EC_KEY_APQNS);
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

int
testlib_env_ec_key_type(void)
{
	int type = -1;	/* Invalid key-type. */
	char *env = NULL;

	env = getenv(ENV_EC_KEY_TYPE);
	if (env == NULL)
		goto ret;

	if (strcmp(env, "ZPC_EC_KEY_TYPE_CCA") == 0)
		type = ZPC_EC_KEY_TYPE_CCA;
	else if (strcmp(env, "ZPC_EC_KEY_TYPE_EP11") == 0)
		type = ZPC_EC_KEY_TYPE_EP11;

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

unsigned int testlib_env_ec_key_flags(void)
{
    int flags = 0;	/* Default flags. */
    long flagslong = LONG_MIN;
	char *env = NULL, *endptr = NULL;

	env = getenv(ENV_EC_KEY_FLAGS);
	if (env == NULL || env[0] == '\0')
		goto ret;

    flagslong = strtol(env, &endptr, 0);
    if (*endptr != '\0' || flagslong < 0 || flagslong > UINT_MAX)
        goto ret;

    flags = (unsigned int)flagslong;
ret:
    return flags;
}

zpc_ec_curve_t testlib_env_ec_key_curve(void)
{
	zpc_ec_curve_t curve;
	char *env = NULL;
	size_t i;

	env = getenv(ENV_EC_KEY_CURVE);
	if (env == NULL || env[0] == '\0') {
		curve = ZPC_EC_CURVE_NOT_SET;
		goto ret;
	}

	for (i = 0; i < strlen(env); i++)
		env[i] = toupper(env[i]);

	if (strcmp(env, "P256") == 0)
		curve = ZPC_EC_CURVE_P256;
	else if (strcmp(env, "P384") == 0)
		curve = ZPC_EC_CURVE_P384;
	else if (strcmp(env, "P521") == 0)
		curve = ZPC_EC_CURVE_P521;
	else if (strcmp(env, "ED25519") == 0)
		curve = ZPC_EC_CURVE_ED25519;
	else if (strcmp(env, "ED448") == 0)
		curve = ZPC_EC_CURVE_ED448;
	else
		curve = ZPC_EC_CURVE_INVALID;

ret:
	return curve;
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

/**
 * This is a wrapper around testlib_hexstr2buf() to convert the given hexstring
 * into a fixed-length, right-aligned byte buffer. It's needed to correctly
 * convert keys and signatures from NIST tests. The routine has the same
 * external behavior as testlib_hexstr2buf, i.e. the calling routine must
 * free the returned buffer.
 */
unsigned char *
testlib_hexstr2fixedbuf(const char *hexstr, size_t tolen)
{
	char temp[132 + 1] = { 0 };
	unsigned char *buf, *str = NULL;
	size_t fromlen;
	int err = 1;

	if (hexstr == NULL || tolen == 0)
		goto ret;

	/* Final length of returned str must be tolen */
	buf = (unsigned char *)calloc(1, tolen);
	if (buf == NULL)
		goto ret;

	/* Pre-pend a leading '0' if necessary, testlib_hexstr2buf wants an
	 * even number of digits */
	if (strlen(hexstr) % 2 != 0) {
		temp[0] = '0';
		memcpy(&temp[1], hexstr, strlen(hexstr));
	} else {
		memcpy(&temp[0], hexstr, strlen(hexstr));
	}

	/* Convert buffer */
	str = testlib_hexstr2buf((char *)&temp, &fromlen);
	assert(tolen >= fromlen);

	/* str gets right-aligned in buf if tolen > fromlen */
	memcpy(buf + tolen - fromlen, str, fromlen);

	err = 0;

ret:
	free(str);
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
