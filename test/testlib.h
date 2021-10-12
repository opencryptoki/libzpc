/*
 * Copyright IBM Corp. 2021
 *
 * libzpc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef TESTLIB_H
# define TESTLIB_H

# include "gtest/gtest.h"

# ifdef __cplusplus
/* *INDENT-OFF* */
extern "C" {
/* *INDENT-ON* */
# endif

# include <stddef.h>

# define UNUSED(x)	(void)(x)
# define NMEMB(x)	(sizeof(x) / sizeof(x[0]))

/*
 * GTEST_SKIP_ assumes the caller to be the test function that is to
 * be skipped. So this one has to be implemented as a macro.
 */
# define TESTLIB_ENV_AES_KEY_CHECK()													        \
do {		                                                                                    \
        const char *apqns[257];                                                                       \
        const char *mkvp;															            \
        int size, type, rc;																        \
																					            \
        size = testlib_env_aes_key_size();									                    \
        switch (size) {                                                                         \
        case 128:   /* fall-through */                                                          \
        case 192:   /* fall-through */                                                          \
        case 256:   /* fall-through */                                                          \
            break;                                                                              \
        case -1:														                        \
            GTEST_SKIP_("ZPC_TEST_AES_KEY_SIZE environment variable not set.");                 \
            break;                                                                              \
        default:                                                                                \
            GTEST_SKIP_("ZPC_TEST_AES_KEY_SIZE environment variable set to invalid key-size."); \
            break;                                                                              \
        }			                                                                            \
        											                                            \
        type = testlib_env_aes_key_type();											            \
        if (type == -1)																            \
                GTEST_SKIP_("ZPC_TEST_AES_KEY_TYPE environment variable not set.");	            \
                                                                                                \
        mkvp = testlib_env_aes_key_mkvp();                                                      \
        rc = testlib_env_aes_key_apqns(apqns);                                                  \
        if (rc == 0 && mkvp != NULL)                                                            \
            GTEST_SKIP_("Both ZPC_TEST_AES_KEY_MKVP and ZPC_TEST_AES_KEY_APQNS environment variables set.");    \
        if (rc != 0 && mkvp == NULL)                                                            \
            GTEST_SKIP_("ZPC_TEST_AES_KEY_MKVP and ZPC_TEST_AES_KEY_APQNS environment variables unset.");       \
} while (0)

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;

const char *testlib_env_aes_key_mkvp(void);
int testlib_env_aes_key_apqns(const char *[257]);
void testlib_env_aes_key_check(void);
int testlib_env_aes_key_size(void);
int testlib_env_aes_key_type(void);
unsigned int testlib_env_aes_key_flags(void);

unsigned char *testlib_hexstr2buf(const char *, size_t *);
char *testlib_buf2hexstr(const unsigned char *, size_t);

# ifdef __cplusplus
/* *INDENT-OFF* */
}
/* *INDENT-ON* */
# endif
#endif
