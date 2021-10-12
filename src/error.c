/*
 * Copyright IBM Corp. 2021
 *
 * libzpc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "zpc/error.h"

#include <stddef.h>

/*
 * Map error code to error string.
 */
const char *
zpc_error_string(int err)
{
	/* Error string index equals error code. */
	static const char *errstr[] = {
		"success",
		"argument 1 NULL",
		"argument 2 NULL",
		"argument 3 NULL",
		"argument 4 NULL",
		"argument 5 NULL",
		"argument 6 NULL",
		"argument 7 NULL",
		"argument 8 NULL",
		"argument 1 out of range",
		"argument 2 out of range",
		"argument 3 out of range",
		"argument 4 out of range",
		"argument 5 out of range",
		"argument 6 out of range",
		"argument 7 out of range",
		"argument 8 out of range",
		"malloc failed",
		"no key is set",
		"invalid key size",
		"IV not set",
		"invalid IV size",
		"invalid tag size",
		"tag mismatch",
		"function not supported",
		"output buffer too small",
		"APQNs not set",
		"invalid key type",
		"key type not set",
		"PKEY_GENSECK2 ioctl failed",
		"PKEY_CLR2SECK2 ioctl failed",
		"PKEY_BLOB2PROTK2 ioctl failed",
		"wrapping key verification pattern mismatch",
		"opening /dev/pkey failed",
		"ciphertext too long",
		"message too long",
		"additional authenticated data too long",
		"RESERVED",
		"parse error",
		"APQN not found in APQN list",
		"MKVP too long",
		"RESERVED",
		"initializing a lock failed",
		"object is in use",
		"PKEY_APQNS4KT ioctl failed",
		"key-size not set",
		"PKEY_GENPROTK ioctl failed",
		"protected-key only",
		"keys are equal",
		"not supported",
		"LAST"
	};
	const char *rc;

	if (err < 0 || (size_t)err >= sizeof(errstr) / sizeof(errstr[0]))
		rc = "undefined error code";
	else
		rc = errstr[err];

	return rc;
}
