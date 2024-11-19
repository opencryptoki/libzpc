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

/*
 * This file must be created by the tester before running tests with key
 * type ZPC_AES_KEY_TYPE_PVSECRET or ZPC_EC_KEY_TYPE_PVSECRET.
 * The file must contain the output from the pvsecret utility list command.
 * The pvsecret utility is part of s390-tools.
 *
 * Example:
 *
 *   # pvsecret list >pvsecret-list.out
 *   # export ZPC_TEST_PVSECRET_LIST_FILE=pvsecret-list.out
 */
#define ENV_PVSECRET_LIST_FILE       "ZPC_TEST_PVSECRET_LIST_FILE"

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
	else if (strcmp(env, "ZPC_AES_KEY_TYPE_PVSECRET") == 0)
		type = ZPC_AES_KEY_TYPE_PVSECRET;

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
	else if (strcmp(env, "ZPC_EC_KEY_TYPE_PVSECRET") == 0)
		type = ZPC_EC_KEY_TYPE_PVSECRET;

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

char * testlib_env_pvsecret_list_file(void)
{
	return getenv(ENV_PVSECRET_LIST_FILE);
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

const char *curve2string[] = {
	"P256",
	"P384",
	"P521",
	"ED25519",
	"ED448",
};

typedef enum {
	EXTRACT_ID,
	EXTRACT_PUBKEY,
	EXTRACT_PRIVKEY,
	EXTRACT_SECRETKEY,
} testkey_extract_mode_t;

const char *type2string(int type)
{
	switch (type) {
	case ZPC_AES_KEY_TYPE_CCA_DATA:
	case ZPC_AES_KEY_TYPE_CCA_CIPHER:
	case ZPC_EC_KEY_TYPE_CCA:
		return "CCA";
	case ZPC_AES_KEY_TYPE_EP11:
	case ZPC_EC_KEY_TYPE_EP11:
		return "EP11";
	default:
		return "PVSECRET";
	}
}

/*
 * A key with given type must be present in the 'pvsecret list' output file
 * that must be created by the tester before running the tests.
 * Note: the strings checked here are created by the pvsecret utility. So
 * whenever the pvsecret utility would use different strings, this must be
 * adapted here.
 */
int pvsec_found(const char *buffer, int pvsectype)
{
	switch (pvsectype) {
	case ZPC_AES_SECRET_AES_128:
		if (strstr(buffer, "AES-128-KEY") != NULL)
			return 1;
		break;
	case ZPC_AES_SECRET_AES_192:
		if (strstr(buffer, "AES-192-KEY") != NULL)
			return 1;
		break;
	case ZPC_AES_SECRET_AES_256:
		if (strstr(buffer, "AES-256-KEY") != NULL)
			return 1;
		break;
	case ZPC_EC_SECRET_ECDSA_P256:
		if (strstr(buffer, "EC-SECP256R1-PRIVATE-KEY") != NULL)
			return 1;
		break;
	case ZPC_EC_SECRET_ECDSA_P384:
		if (strstr(buffer, "EC-SECP384R1-PRIVATE-KEY") != NULL)
			return 1;
		break;
	case ZPC_EC_SECRET_ECDSA_P521:
		if (strstr(buffer, "EC-SECP521R1-PRIVATE-KEY") != NULL)
			return 1;
		break;
	case ZPC_EC_SECRET_EDDSA_ED25519:
		if (strstr(buffer, "EC-ED25519-PRIVATE-KEY") != NULL)
			return 1;
		break;
	case ZPC_EC_SECRET_EDDSA_ED448:
		if (strstr(buffer, "EC-ED448-PRIVATE-KEY") != NULL)
			return 1;
		break;
	default:
		break;
	}

	return 0;
}

/*
 * Convert a given hex string of the form " 0xabcde ...." into a byte array.
 * Note that a leading space char is expected at the beginning of the string.
 */
int extract_bytes(const char *buffer, unsigned char *outbuf, unsigned int *outlen)
{
	unsigned char *sec = NULL;
	char *tmp;
	size_t seclen;
	int rc = 1;

	/* Remove leading ' 0x' and ending newline */
	tmp = (char *)buffer + 3;
	tmp[strlen(tmp) - 1] = 0;

	/* Convert hex string to byte array */
	sec = testlib_hexstr2buf(tmp, &seclen);
	if (sec != NULL && seclen > 0) {
		memcpy(outbuf, sec, seclen);
		*outlen = seclen;
		rc = 0;
		goto ret;
	}

ret:
	free(sec);

	return rc;
}

/*
 * Extract the pvsecret ID or secret key data from a text file created with
 * the 'pvsecret' utility. The name of the text file must be specified via
 * env variable ZPC_TEST_PVSECRET_LIST_FILE. If no pvsecret of this type is
 * contained in the file (and thus on this system), return an error.
 *
 * The pvsecrets-list file contains AES pvsecret IDs in this form:
 *
 * 2 AES-128-KEY:
 *  0x8cf9659cdea52a5c9ece7446593becc58a3ac519a14d8d54297ab5a01562b7b9
 * 3 AES-192-KEY:
 *  0x5498c4450db472397b0637f536491d11dbaee860cf47a05c6af822f0787a1aaf
 * 4 AES-256-KEY:
 *  0x7237b089a3fcdbef82404477f1f28e20d66de8c80a7dea00cd10520293eefeff
 * ...
 *
 * The tester may optionally add the clear secret key of a pvsecret like:
 *
 * 5 AES-128-KEY:
 *  0x8cf9659cdea52a5c9e ...   <- secret ID
 *  0xbe0274e3f3b36 ...   <- clear secret key
 * 6 AES-XTS-256-KEY:
 * ...
 *
 * @return 0 success, outbuf contains extracted byte array
 *         1 error opening list file
 *         2 no pvsecret found for given type
 */
int testlib_get_aes_data(int size, unsigned char *outbuf,
			unsigned int *outlen, testkey_extract_mode_t mode)
{
	FILE *fd;
	const unsigned int BUF_LEN = 300;
	char buffer[BUF_LEN] = { 0, };
	char *fn;
	int i, pvsectype, rc, lines_to_skip;

	switch (mode) {
	case EXTRACT_ID:
		lines_to_skip = 1;
		break;
	case EXTRACT_SECRETKEY:
		lines_to_skip = 2;
		break;
	default:
		return 3; /* should not occur */
	}

	switch (size) {
	case 128:
		pvsectype = ZPC_AES_SECRET_AES_128;
		break;
	case 192:
		pvsectype = ZPC_AES_SECRET_AES_192;
		break;
	default: /* 256 */
		pvsectype = ZPC_AES_SECRET_AES_256;
		break;
	}

	fn = testlib_env_pvsecret_list_file();
	if (!fn)
		return 1;

	if ((fd = fopen(fn, "r")) == NULL)
		return 1;

	while (fgets(buffer, BUF_LEN, fd)) {
		if (pvsec_found(buffer, pvsectype)) {
			for (i = 0; i < lines_to_skip; i++) {
				if (!fgets(buffer, BUF_LEN, fd)) { /* skip to next line */
					rc = 2;
					goto ret;
				}
			}
			if (extract_bytes(buffer, outbuf, outlen) == 0) {
				rc = 0;
				goto ret;
			}
		}
	}

	rc = 2;

ret:
	fclose(fd);

	return rc;
}

int testlib_set_aes_key_from_pvsecret(struct zpc_aes_key *aes_key, int keysize)
{
	unsigned char pvsec_id[32] = { 0, };
	unsigned int id_len;
	size_t i;
	int rc;

	rc = testlib_get_aes_data(keysize, pvsec_id, &id_len, EXTRACT_ID);
	switch (rc) {
	case 0:
		rc = zpc_aes_key_import(aes_key, pvsec_id, 32);
		if (rc != 0) {
			printf("[    ERROR ] zpc_aes_key_import from 'AES-%d-KEY' pvsecret failed with rc = %d.\n",
					keysize, rc);
			printf("Tried with ID:\n");
			for (i = 0; i < sizeof(pvsec_id); i++)
				printf("%02X%c",pvsec_id[i],((i+1)%16)?' ':'\n');
		}
		break;
	case 1:
		printf("[  WARNING ] Could not open pvsecret list file. Probably "
			"ZPC_TEST_PVSECRET_LIST_FILE not set, or file does not exist.\n");
		break;
	case 2:
		printf("[  WARNING ] No AES pvsecret with size %d available on this system.\n",
			keysize);
		break;
	}

	return rc;
}

int testlib_set_aes_key_from_file(struct zpc_aes_key *aes_key, int type, int size)
{
	unsigned char pvsec_id[32] = { 0, };
	unsigned char keybytes[256] = { 0, };
	unsigned int idlen, byteslen;
	int rc;

	rc = testlib_get_aes_data(size, pvsec_id, &idlen, EXTRACT_ID);
	switch (rc) {
	case 0:
		break;
	case 1:
		printf("[  WARNING ] Could not open pvsecret list file. Probably "
			"ZPC_TEST_PVSECRET_LIST_FILE not set, or file does not exist.\n");
		goto ret;
	case 2:
		printf("[  WARNING ] No AES pvsecret with size %d available on this system.\n",
				size);
		goto ret;
	}

	rc = testlib_get_aes_data(size, keybytes, &byteslen, EXTRACT_SECRETKEY);
	if (rc != 0) {
		printf("[     INFO ] Cannot obtain clear key bytes for 'AES-%d-KEY' from list file.\n",
			size);
		goto ret;
	}

	rc = zpc_aes_key_import_clear(aes_key, keybytes);
	if (rc != 0) {
		printf("[     INFO ] Cannot import clear key data for %s-type 'AES-%d-KEY' from list file, rc = %d.\n",
			type2string(type), size, rc);
		goto ret;
	}

	rc = 0;
	printf("[       OK ] Imported clear key data for %s-type 'AES-%d-KEY' from list file.\n",
		type2string(type), size);

ret:
	return rc;
}

/*
 * Extract the pvsecret ID, public or private key data from a text file created
 * with the 'pvsecret' utility. The name of the text file must be specified via
 * env variable ZPC_TEST_EC_KEY_PVSECTYPE. If no pvsecret of this type is
 * contained in the file (and thus on this system), return an error.
 *
 * The pvsecrets-list file contains EC pvsecret IDs in this form:
 *
 *  9 EC-SECP384R1-PRIVATE-KEY:
 *   0xf972ce506dad11195af5e2f3647237752ff2a064c9ad16b133d56062242cb4d0
 *  10 EC-SECP521R1-PRIVATE-KEY:
 *   0xc4c2acd778caafee6c184eaf99dcefb83b43197b9f6d190ffb73460ea417d944
 *  11 EC-ED25519-PRIVATE-KEY:
 *   0x3d5f4f95cdb1cdfc71014efa1a669fd42599a0ce2000d914a409e48bccaed584
 *  12 EC-ED448-PRIVATE-KEY:
 *   0x40159448e5203c70a9ec00f9490ae5c7d60e00bcb1bca2ed32c8b6b1224cd45a
 * ...
 *
 * The tester may optionally add the clear public and private key of a pvsecret
 * like:
 *
 * 11 EC-ED25519-PRIVATE-KEY:
 *  0x3d5f4f95cdb1cdfc71014efa ...     <- pvsecret ID
 *  0xf898c8e1ba10b2aadc787a713d70a787 ...     <- clear public key
 *  0x3fecd5c7cb294bd89b68a5959cc59d634f51fb6e8 ... <- clear private key
 * 12 EC-ED448-PRIVATE-KEY:
 * ...
 *
 * Note that for p256, p384, and p521 only uncompressed public keys can be
 * added and the leading compress indicator byte 0x04 must be removed.
 *
 * @return 0 success, outbuf contains 32-byte EC pvsecret ID
 *         1 error opening list file
 *         2 no pvsecret found for given type
 */
int testlib_get_ec_data(zpc_ec_curve_t curve, unsigned char *outbuf,
			unsigned int *outlen, testkey_extract_mode_t mode)
{
	FILE *fd;
	const unsigned int BUF_LEN = 300;
	char buffer[BUF_LEN] = { 0, };
	char *fn;
	int i, pvsectype, rc, lines_to_skip;

	switch (mode) {
	case EXTRACT_ID:
		lines_to_skip = 1;
		break;
	case EXTRACT_PUBKEY:
		lines_to_skip = 2;
		break;
	case EXTRACT_PRIVKEY:
		lines_to_skip = 3;
		break;
	default:
		return 3; /* should not occur */
	}

	switch (curve) {
	case ZPC_EC_CURVE_P256:
		pvsectype = ZPC_EC_SECRET_ECDSA_P256;
		break;
	case ZPC_EC_CURVE_P384:
		pvsectype = ZPC_EC_SECRET_ECDSA_P384;
		break;
	case ZPC_EC_CURVE_P521:
		pvsectype = ZPC_EC_SECRET_ECDSA_P521;
		break;
	case ZPC_EC_CURVE_ED25519:
		pvsectype = ZPC_EC_SECRET_EDDSA_ED25519;
		break;
	default:
		pvsectype = ZPC_EC_SECRET_EDDSA_ED448;
		break;
	}

	fn = testlib_env_pvsecret_list_file();
	if (!fn)
		return 1;

	if ((fd = fopen(fn, "r")) == NULL)
		return 1;

	while (fgets(buffer, BUF_LEN, fd)) {
		if (pvsec_found(buffer, pvsectype)) {
			for (i = 0; i < lines_to_skip; i++) {
				if (!fgets(buffer, BUF_LEN, fd)) { /* skip to next line */
					rc = 2;
					goto ret;
				}
			}
			if (extract_bytes(buffer, outbuf, outlen) == 0) {
				rc = 0;
				goto ret;
			}
		}
	}

	rc = 2;

ret:
	fclose(fd);

	return rc;
}

/*
 * Obtain an EC public key from a text file, first created with the 'pvsecret'
 * utility, related to the given pvsecret type env variable ZPC_TEST_EC_KEY_CURVE.
 * The tester may add an EC/Ed public key manually by inserting the public key
 * clear key value after the related pvsecret ID:
 *
 * 12 EC-ED25519-PRIVATE-KEY:
 *  0x3d5f4f95cdb1cdfc71014efa ... 2000d914a409e48bccaed584 <- secret ID
 *  0xf898c8e1 ...787a7170a787b40031e75a01c282195d997e1c770d47 <- pubkey value
 * ...
 *
 * @return 0 success, pubkey contains pubkey value and publen its byte length
 *         1 error opening list file
 *         2 no pubkey found for given pvsecret ID
 */
int testlib_add_ec_public_key(const char *pvsec_id, unsigned char *pubkey,
			unsigned int *publen)
{
	FILE *fd;
	const unsigned int BUF_LEN = 300;
	char buffer[BUF_LEN] = { 0, };
	char *fn;
	int rc;
	unsigned char *bytes;
	size_t bytelen;
	char *tmp;

	fn = testlib_env_pvsecret_list_file();
	if (!fn)
		return 1;

	if ((fd = fopen(fn, "r")) == NULL)
		return 1;

	while (fgets(buffer, BUF_LEN, fd)) {
		if (strstr(buffer, "0x") != NULL) {
			/* Remove leading ' 0x' and ending newline */
			tmp = (char *)buffer + 3;
			tmp[strlen(tmp) - 1] = 0;
			bytes = testlib_hexstr2buf(tmp, &bytelen);
			if (bytes != NULL && bytelen > 0 && memcmp(bytes, pvsec_id, bytelen) == 0) {
				if (fgets(buffer, BUF_LEN, fd)) { /* skip to next line */
					if (strstr(buffer, "0x") != NULL) {
						if (extract_bytes(buffer, pubkey, publen) == 0) {
							rc = 0;
							goto ret;
						}
					}
				}
			}
		}
	}

	rc = 2;

ret:
	fclose(fd);

	return rc;
}

int testlib_set_ec_key_from_pvsecret(struct zpc_ec_key *ec_key, int type,
			zpc_ec_curve_t curve)
{
	unsigned char pvsec_id[32] = { 0, };
	unsigned char pubkey[256] = { 0, };
	unsigned int i, id_len, publen;
	int rc;

	rc = testlib_get_ec_data(curve, pvsec_id, &id_len, EXTRACT_ID);
	switch (rc) {
	case 0:
		rc = zpc_ec_key_import(ec_key, pvsec_id, id_len);
		if (rc != 0) {
			printf("[    ERROR ] zpc_ec_key_import from 'EC-%s-PRIVATE-KEY' pvsecret failed with rc = %d.\n",
				curve2string[curve], rc);
			printf("Tried with ID:\n");
			for (i = 0; i < sizeof(pvsec_id); i++)
				printf("%02X%c",pvsec_id[i],((i+1)%16)?' ':'\n');
		} else {
			rc = testlib_add_ec_public_key((const char *)pvsec_id, pubkey, &publen);
			if (rc == 0) {
				rc = zpc_ec_key_import_clear(ec_key, pubkey, publen, NULL, 0);
				if (rc == 0) {
					printf("[       OK ] Added clear public key for %s-type 'EC-%s-PRIVATE-KEY' from list file.\n",
						type2string(type), curve2string[curve]);
				} else {
					printf("[    ERROR ] Cannot import clear public key for %s-type 'EC-%s-PRIVATE-KEY' from list file, rc = %d.\n",
						type2string(type), curve2string[curve], rc);
				}
			} else {
				printf("[     INFO ] No clear public key for %s-type 'EC-%s-PRIVATE-KEY' available in list file.\n",
					type2string(type), curve2string[curve]);
			}
		}
		break;
	case 1:
		printf("[  WARNING ] Could not open pvsecret list file. Probably "
			"ZPC_TEST_PVSECRET_LIST_FILE not set, or file does not exist.\n");
		break;
	case 2:
		printf("[  WARNING ] No EC/Ed pvsecret for curve %s available on this system.\n",
			curve2string[curve]);
		break;
	}

	return rc;
}

int testlib_set_ec_key_from_file(struct zpc_ec_key *ec_key, int type, zpc_ec_curve_t curve)
{
	unsigned char pvsec_id[32] = { 0, };
	unsigned char privkey[256] = { 0, };
	unsigned char pubkey[256] = { 0, };
	unsigned int idlen, privlen, publen;
	int rc;

	rc = testlib_get_ec_data(curve, pvsec_id, &idlen, EXTRACT_ID);
	switch (rc) {
	case 0:
		break;
	case 1:
		printf("[  WARNING ] Could not open pvsecret list file. Probably "
			"ZPC_TEST_PVSECRET_LIST_FILE not set, or file does not exist.\n");
		goto ret;
	case 2:
		printf("[  WARNING ] No EC/Ed pvsecret for curve %s available on this system.\n",
			curve2string[curve]);
		goto ret;
	}

	rc = testlib_get_ec_data(curve, pubkey, &publen, EXTRACT_PUBKEY);
	if (rc != 0) {
		printf("[     INFO ] Cannot obtain clear public key bytes for 'EC-%s-PRIVATE-KEY' from list file.\n",
			curve2string[curve]);
		goto ret;
	}

	rc = testlib_get_ec_data(curve, privkey, &privlen, EXTRACT_PRIVKEY);
	if (rc != 0) {
		printf("[     INFO ] Cannot obtain clear private key bytes for 'EC-%s-PRIVATE-KEY' from list file.\n",
			curve2string[curve]);
		goto ret;
	}

	rc = zpc_ec_key_import_clear(ec_key, pubkey, publen, privkey, privlen);
	if (rc != 0) {
		printf("[     INFO ] Cannot import clear key data for %s-type 'EC-%s-PRIVATE-KEY' from list file, rc = %d.\n",
			type2string(type), curve2string[curve], rc);
		goto ret;
	}

	rc = 0;
	printf("[       OK ] Imported clear key data for %s-type 'EC-%s-PRIVATE-KEY' from list file, rc = %d.\n",
		type2string(type), curve2string[curve], rc);

ret:
	return rc;
}
