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

#include "zpc/ecc_key.h"
#include "zpc/hmac.h"

# define UNUSED(x)	(void)(x)
# define NMEMB(x)	(sizeof(x) / sizeof(x[0]))

/*
 * GTEST_SKIP_ assumes the caller to be the test function that is to
 * be skipped. So this one has to be implemented as a macro.
 */
# define TESTLIB_ENV_AES_KEY_CHECK()                                           \
do {                                                                           \
        const char *apqns[257];                                                \
        const char *mkvp;                                                      \
        int size, type, rc;                                                    \
                                                                               \
        size = testlib_env_aes_key_size();                                     \
        switch (size) {                                                        \
        case 128:   /* fall-through */                                         \
        case 192:   /* fall-through */                                         \
        case 256:   /* fall-through */                                         \
            break;                                                             \
        case -1:                                                               \
            GTEST_SKIP_("ZPC_TEST_AES_KEY_SIZE environment variable not set."); \
            break;                                                             \
        default:                                                               \
            GTEST_SKIP_("ZPC_TEST_AES_KEY_SIZE environment variable set to invalid key-size."); \
            break;                                                             \
        }                                                                      \
                                                                               \
        type = testlib_env_aes_key_type();                                     \
        if (type == -1)                                                        \
                GTEST_SKIP_("ZPC_TEST_AES_KEY_TYPE environment variable not set."); \
                                                                               \
        if (type != ZPC_AES_KEY_TYPE_PVSECRET) {                               \
            mkvp = testlib_env_aes_key_mkvp();                                 \
            rc = testlib_env_aes_key_apqns(apqns);                             \
            if (rc == 0 && mkvp != NULL)                                       \
                GTEST_SKIP_("Both ZPC_TEST_AES_KEY_MKVP and ZPC_TEST_AES_KEY_APQNS environment variables set."); \
            if (rc != 0 && mkvp == NULL)                                       \
                GTEST_SKIP_("ZPC_TEST_AES_KEY_MKVP and ZPC_TEST_AES_KEY_APQNS environment variables unset."); \
        }                                                                      \
} while (0)

# define TESTLIB_AES_ECB_HW_CAPS_CHECK()                                       \
do {                                                                           \
        int rc;                                                                \
        struct zpc_aes_ecb *ctx;                                               \
                                                                               \
        rc = zpc_aes_ecb_alloc(&ctx);                                          \
        switch (rc) {                                                          \
        case ZPC_ERROR_DEVPKEY:                                                \
            GTEST_SKIP_("HW_CAPS check (AES-ECB): opening /dev/pkey failed."); \
            break;                                                             \
        case ZPC_ERROR_HWCAPS:                                                 \
            GTEST_SKIP_("HW_CAPS check (AES-ECB): no hw capabilities for AES-ECB."); \
            break;                                                             \
        case ZPC_ERROR_MALLOC:                                                 \
            GTEST_SKIP_("HW_CAPS check (AES-ECB): cannot allocate AES ctx object."); \
            break;                                                             \
        default:                                                               \
            zpc_aes_ecb_free(&ctx);                                            \
            break;                                                             \
        }                                                                      \
} while (0)

# define TESTLIB_AES_CBC_HW_CAPS_CHECK()                                       \
do {                                                                           \
        int rc;                                                                \
        struct zpc_aes_cbc *ctx;                                               \
                                                                               \
        rc = zpc_aes_cbc_alloc(&ctx);                                          \
        switch (rc) {                                                          \
        case ZPC_ERROR_DEVPKEY:                                                \
            GTEST_SKIP_("HW_CAPS check (AES-CBC): opening /dev/pkey failed."); \
            break;                                                             \
        case ZPC_ERROR_HWCAPS:                                                 \
            GTEST_SKIP_("HW_CAPS check (AES-CBC): no hw capabilities for AES-CBC."); \
            break;                                                             \
        case ZPC_ERROR_MALLOC:                                                 \
            GTEST_SKIP_("HW_CAPS check (AES-CBC): cannot allocate AES ctx object."); \
            break;                                                             \
        default:                                                               \
            zpc_aes_cbc_free(&ctx);                                            \
            break;                                                             \
        }                                                                      \
} while (0)

# define TESTLIB_AES_CMAC_HW_CAPS_CHECK()                                      \
do {                                                                           \
        int rc;                                                                \
        struct zpc_aes_cmac *ctx;                                              \
                                                                               \
        rc = zpc_aes_cmac_alloc(&ctx);                                         \
        switch (rc) {                                                          \
        case ZPC_ERROR_DEVPKEY:                                                \
            GTEST_SKIP_("HW_CAPS check (AES-CMAC): opening /dev/pkey failed.");\
            break;                                                             \
        case ZPC_ERROR_HWCAPS:                                                 \
            GTEST_SKIP_("HW_CAPS check (AES-CMAC): no hw capabilities for AES-CMAC."); \
            break;                                                             \
        case ZPC_ERROR_MALLOC:                                                 \
            GTEST_SKIP_("HW_CAPS check (AES-CMAC): cannot allocate AES ctx object."); \
            break;                                                             \
        default:                                                               \
            zpc_aes_cmac_free(&ctx);                                           \
            break;                                                             \
        }                                                                      \
} while (0)

# define TESTLIB_AES_CCM_HW_CAPS_CHECK()                                       \
do {                                                                           \
        int rc;                                                                \
        struct zpc_aes_ccm *ctx;                                               \
                                                                               \
        rc = zpc_aes_ccm_alloc(&ctx);                                          \
        switch (rc) {                                                          \
        case ZPC_ERROR_DEVPKEY:                                                \
            GTEST_SKIP_("HW_CAPS check (AES-CCM): opening /dev/pkey failed."); \
            break;                                                             \
        case ZPC_ERROR_HWCAPS:                                                 \
            GTEST_SKIP_("HW_CAPS check (AES-CCM): no hw capabilities for AES-CCM."); \
            break;                                                             \
        case ZPC_ERROR_MALLOC:                                                 \
            GTEST_SKIP_("HW_CAPS check (AES-CCM): cannot allocate AES ctx object."); \
            break;                                                             \
        default:                                                               \
            zpc_aes_ccm_free(&ctx);                                            \
            break;                                                             \
        }                                                                      \
} while (0)

# define TESTLIB_AES_GCM_HW_CAPS_CHECK()                                       \
do {                                                                           \
        int rc;                                                                \
        struct zpc_aes_gcm *ctx;                                               \
                                                                               \
        rc = zpc_aes_gcm_alloc(&ctx);                                          \
        switch (rc) {                                                          \
        case ZPC_ERROR_DEVPKEY:                                                \
            GTEST_SKIP_("HW_CAPS check (AES-GCM): opening /dev/pkey failed."); \
            break;                                                             \
        case ZPC_ERROR_HWCAPS:                                                 \
            GTEST_SKIP_("HW_CAPS check (AES-GCM): no hw capabilities for AES-GCM."); \
            break;                                                             \
        case ZPC_ERROR_MALLOC:                                                 \
            GTEST_SKIP_("HW_CAPS check (AES-GCM): cannot allocate AES ctx object."); \
            break;                                                             \
        default:                                                               \
            zpc_aes_gcm_free(&ctx);                                            \
            break;                                                             \
        }                                                                      \
} while (0)

# define TESTLIB_AES_XTS_HW_CAPS_CHECK()                                       \
do {                                                                           \
        int rc;                                                                \
        struct zpc_aes_xts *ctx;                                               \
                                                                               \
        rc = zpc_aes_xts_alloc(&ctx);                                          \
        switch (rc) {                                                          \
        case ZPC_ERROR_DEVPKEY:                                                \
            GTEST_SKIP_("HW_CAPS check (AES-XTS): opening /dev/pkey failed."); \
            break;                                                             \
        case ZPC_ERROR_HWCAPS:                                                 \
            GTEST_SKIP_("HW_CAPS check (AES-XTS): no hw capabilities for AES-XTS."); \
            break;                                                             \
        case ZPC_ERROR_MALLOC:                                                 \
            GTEST_SKIP_("HW_CAPS check (AES-XTS): cannot allocate AES ctx object."); \
            break;                                                             \
        default:                                                               \
            zpc_aes_xts_free(&ctx);                                            \
            break;                                                             \
        }                                                                      \
} while (0)

# define TESTLIB_AES_XTS_KEY_SIZE_CHECK(size)                                  \
do {                                                                           \
        if (size != 128 && size != 256) {                                      \
            GTEST_SKIP_("Key size check (AES-XTS): only 128 and 256 bits supported by CPACF."); \
        }                                                                      \
} while (0)

# define TESTLIB_AES_SW_CAPS_CHECK(type)                                       \
do {                                                                           \
        int rc;                                                                \
        struct zpc_aes_key *aes_key;                                           \
                                                                               \
        rc = zpc_aes_key_alloc(&aes_key);                                      \
        if (rc != 0)                                                           \
            GTEST_SKIP_("SW_CAPS check (AES): Cannot allocate key object.");   \
                                                                               \
        rc = zpc_aes_key_set_type(aes_key, type);                              \
        if ((type == ZPC_AES_KEY_TYPE_CCA_DATA ||                              \
             type == ZPC_AES_KEY_TYPE_CCA_CIPHER) &&                           \
            rc == ZPC_ERROR_CCA_HOST_LIB_NOT_AVAILABLE) {                      \
            zpc_aes_key_free(&aes_key);                                        \
            GTEST_SKIP_("SW_CAPS check (AES): CCA host lib not available or too old."); \
        }                                                                      \
        if (type == ZPC_AES_KEY_TYPE_EP11 &&                                   \
            rc == ZPC_ERROR_EP11_HOST_LIB_NOT_AVAILABLE) {                     \
            zpc_aes_key_free(&aes_key);                                        \
            GTEST_SKIP_("SW_CAPS check (AES): EP11 host lib not available or too old."); \
        }                                                                      \
        if (type == ZPC_AES_KEY_TYPE_PVSECRET &&                               \
            rc == ZPC_ERROR_UV_PVSECRETS_NOT_AVAILABLE) {                      \
            zpc_aes_key_free(&aes_key);                                        \
            GTEST_SKIP_("SW_CAPS check (AES): UV retrievable secrets not available."); \
        }                                                                      \
        if (rc != 0) {                                                         \
            zpc_aes_key_free(&aes_key);                                        \
            GTEST_SKIP_("SW_CAPS check (AES): Unexpected error when setting key type."); \
        }                                                                      \
        zpc_aes_key_free(&aes_key);                                            \
} while (0)

# define TESTLIB_AES_KERNEL_CAPS_CHECK(type)                                   \
do {                                                                           \
        int rc;                                                                \
        struct zpc_aes_key *aes_key;                                           \
                                                                               \
        rc = zpc_aes_key_alloc(&aes_key);                                      \
        if (rc != 0)                                                           \
            GTEST_SKIP_("KERNEL_CAPS check (AES): Cannot allocate key object."); \
        rc = zpc_aes_key_set_type(aes_key, type);                              \
        if (type == ZPC_AES_KEY_TYPE_PVSECRET &&                               \
            rc == ZPC_ERROR_UV_PVSECRETS_NOT_AVAILABLE) {                      \
            zpc_aes_key_free(&aes_key);                                        \
            GTEST_SKIP_("KERNEL_CAPS check (AES): UV retrievable secrets not supported on this system."); \
        }                                                                      \
        if (type != ZPC_AES_KEY_TYPE_PVSECRET) {                               \
            rc = zpc_aes_key_set_mkvp(aes_key, NULL); /* cannot fail */        \
            rc = zpc_aes_key_set_size(aes_key, 128); /* cannot fail */         \
            rc = zpc_aes_key_generate(aes_key);                                \
            if (rc == ZPC_ERROR_IOCTLGENSECK2) {                               \
                zpc_aes_key_free(&aes_key);                                    \
                GTEST_SKIP_("KERNEL_CAPS check (AES): ioctl PKEY_GENSECK2 not supported by kernel."); \
            }                                                                  \
            if (rc != 0) {                                                     \
                zpc_aes_key_free(&aes_key);                                    \
                GTEST_SKIP_("KERNEL_CAPS check (AES): Unexpected error when generating test key."); \
            }                                                                  \
        }                                                                      \
                                                                               \
        zpc_aes_key_free(&aes_key);                                            \
} while (0)

# define TESTLIB_AES_NEW_MK_CHECK(type,mkvp,apqns)                             \
do {                                                                           \
        int rc;                                                                \
        struct zpc_aes_key *aes_key;                                           \
                                                                               \
        if (type == ZPC_AES_KEY_TYPE_PVSECRET)                                 \
            break; /* silently skip check */                                   \
                                                                               \
        rc = zpc_aes_key_alloc(&aes_key);                                      \
        if (rc != 0)                                                           \
            GTEST_SKIP_("NEW_MK check (AES): Cannot allocate key object.");    \
                                                                               \
        rc = zpc_aes_key_set_type(aes_key, type);                              \
        if ((type == ZPC_AES_KEY_TYPE_CCA_DATA ||                              \
             type == ZPC_AES_KEY_TYPE_CCA_CIPHER) &&                           \
            rc == ZPC_ERROR_CCA_HOST_LIB_NOT_AVAILABLE) {                      \
            zpc_aes_key_free(&aes_key);                                        \
            GTEST_SKIP_("NEW_MK check (AES): CCA host lib not available or too old."); \
        }                                                                      \
        if (type == ZPC_AES_KEY_TYPE_EP11 &&                                   \
            rc == ZPC_ERROR_EP11_HOST_LIB_NOT_AVAILABLE) {                     \
            zpc_aes_key_free(&aes_key);                                        \
            GTEST_SKIP_("NEW_MK check (AES): EP11 host lib not available or too old."); \
        }                                                                      \
        if (mkvp != NULL) {                                                    \
            rc = zpc_aes_key_set_mkvp(aes_key, mkvp);                          \
            if (rc != 0) {                                                     \
                zpc_aes_key_free(&aes_key);                                    \
                GTEST_SKIP_("NEW_MK check (AES): error setting mkvp.");        \
            }                                                                  \
        } else {                                                               \
            rc = zpc_aes_key_set_apqns(aes_key, apqns);                        \
            if (rc != 0) {                                                     \
                zpc_aes_key_free(&aes_key);                                    \
                GTEST_SKIP_("NEW_MK check (AES): error setting apqns.");       \
            }                                                                  \
        }                                                                      \
        rc = zpc_aes_key_set_size(aes_key, 128); /* cannot fail */             \
        rc = zpc_aes_key_generate(aes_key);                                    \
        if (rc != 0) {                                                         \
            zpc_aes_key_free(&aes_key);                                        \
            GTEST_SKIP_("NEW_MK check (AES): unexpected error when generating test key."); \
        }                                                                      \
        if (type != ZPC_AES_KEY_TYPE_PVSECRET) {                               \
            rc = zpc_aes_key_reencipher(aes_key, ZPC_AES_KEY_REENCIPHER_CURRENT_TO_NEW); \
            if (rc != 0) {                                                     \
                zpc_aes_key_free(&aes_key);                                    \
                GTEST_SKIP_("NEW_MK check (AES): new MK not set for this APQN/MKVP."); \
            }                                                                  \
        }                                                                      \
        zpc_aes_key_free(&aes_key);                                            \
} while (0)

# define TESTLIB_ENV_EC_KEY_CHECK()                                            \
do {                                                                           \
        const char *apqns[257];                                                \
        const char *mkvp;                                                      \
        int type, rc;                                                          \
        int curve = testlib_env_ec_key_curve();                                \
                                                                               \
        switch (curve) {                                                       \
        case ZPC_EC_CURVE_P256:      /* fall-through */                        \
        case ZPC_EC_CURVE_P384:      /* fall-through */                        \
        case ZPC_EC_CURVE_P521:      /* fall-through */                        \
        case ZPC_EC_CURVE_ED25519:   /* fall-through */                        \
        case ZPC_EC_CURVE_ED448:     /* fall-through */                        \
            break;                                                             \
        case ZPC_EC_CURVE_INVALID:                                             \
            GTEST_SKIP_("ZPC_TEST_EC_KEY_CURVE environment variable set to invalid value."); \
            break;                                                             \
        default:                                                               \
            GTEST_SKIP_("ZPC_TEST_EC_KEY_CURVE environment variable not set."); \
            break;                                                             \
        }                                                                      \
                                                                               \
        type = testlib_env_ec_key_type();                                      \
        if (type == -1)                                                        \
                GTEST_SKIP_("ZPC_TEST_EC_KEY_TYPE environment variable not set."); \
                                                                               \
        if (type != ZPC_EC_KEY_TYPE_PVSECRET) {                                \
            mkvp = testlib_env_ec_key_mkvp();                                  \
            rc = testlib_env_ec_key_apqns(apqns);                              \
            if (rc == 0 && mkvp != NULL)                                       \
                GTEST_SKIP_("Both ZPC_TEST_EC_KEY_MKVP and ZPC_TEST_EC_KEY_APQNS environment variables set."); \
            if (rc != 0 && mkvp == NULL)                                           \
                GTEST_SKIP_("ZPC_TEST_EC_KEY_MKVP and ZPC_TEST_EC_KEY_APQNS environment variables unset."); \
        }                                                                      \
} while (0)

# define TESTLIB_EC_HW_CAPS_CHECK()                                            \
do {                                                                           \
        int rc;                                                                \
        struct zpc_ecdsa_ctx *ctx;                                             \
                                                                               \
        rc = zpc_ecdsa_ctx_alloc(&ctx);                                        \
        switch (rc) {                                                          \
        case ZPC_ERROR_DEVPKEY:                                                \
            GTEST_SKIP_("HW_CAPS check: opening /dev/pkey failed.");           \
            break;                                                             \
        case ZPC_ERROR_HWCAPS:                                                 \
            GTEST_SKIP_("HW_CAPS check: no hw capabilities for ECDSA.");       \
            break;                                                             \
        case ZPC_ERROR_MALLOC:                                                 \
            GTEST_SKIP_("HW_CAPS check: cannot allocate ECDSA ctx object.");   \
            break;                                                             \
        default:                                                               \
            zpc_ecdsa_ctx_free(&ctx);                                          \
            break;                                                             \
        }                                                                      \
} while (0)

# define TESTLIB_EC_SW_CAPS_CHECK(type)                                        \
do {                                                                           \
        int rc;                                                                \
        struct zpc_ec_key *ec_key;                                             \
                                                                               \
        rc = zpc_ec_key_alloc(&ec_key);                                        \
        if (rc != 0)                                                           \
            GTEST_SKIP_("SW_CAPS check (EC): Cannot allocate key object.");    \
                                                                               \
        rc = zpc_ec_key_set_type(ec_key, type);                                \
        if (type == ZPC_EC_KEY_TYPE_CCA &&                                     \
            rc == ZPC_ERROR_CCA_HOST_LIB_NOT_AVAILABLE) {                      \
            zpc_ec_key_free(&ec_key);                                          \
            GTEST_SKIP_("SW_CAPS check (EC): CCA host lib not available or too old (min CCA 7.0)."); \
        }                                                                      \
        if (type == ZPC_EC_KEY_TYPE_EP11 &&                                    \
            rc == ZPC_ERROR_EP11_HOST_LIB_NOT_AVAILABLE) {                     \
            zpc_ec_key_free(&ec_key);                                          \
            GTEST_SKIP_("SW_CAPS check (EC): EP11 host lib not available or too old (min EP11 3.0)."); \
        }                                                                      \
        if (type == ZPC_EC_KEY_TYPE_PVSECRET &&                                \
            rc == ZPC_ERROR_UV_PVSECRETS_NOT_AVAILABLE) {                      \
            zpc_ec_key_free(&ec_key);                                          \
            GTEST_SKIP_("SW_CAPS check (EC): PVSECRET support not available on this system."); \
        }                                                                      \
        if (rc != 0) {                                                         \
            zpc_ec_key_free(&ec_key);                                          \
            GTEST_SKIP_("HW_CAPS check (EC): unexpected error when setting key type."); \
        }                                                                      \
        zpc_ec_key_free(&ec_key);                                              \
} while (0)

# define TESTLIB_EC_KERNEL_CAPS_CHECK(type,mkvp,apqns)                         \
do {                                                                           \
        int rc;                                                                \
        struct zpc_ec_key *ec_key;                                             \
                                                                               \
        rc = zpc_ec_key_alloc(&ec_key);                                        \
        if (rc != 0)                                                           \
            GTEST_SKIP_("KERNEL_CAPS check (EC): Cannot allocate key object."); \
                                                                               \
        rc = zpc_ec_key_set_mkvp(ec_key, NULL); /* cannot fail */              \
        rc = zpc_ec_key_set_curve(ec_key, ZPC_EC_CURVE_P256); /* cannot fail */ \
        rc = zpc_ec_key_set_type(ec_key, type);                                \
        if (type == ZPC_EC_KEY_TYPE_PVSECRET &&                                \
            rc == ZPC_ERROR_UV_PVSECRETS_NOT_AVAILABLE) {                      \
            zpc_ec_key_free(&ec_key);                                          \
            GTEST_SKIP_("KERNEL_CAPS check (EC): PVSECRET support not available on this system."); \
        }                                                                      \
        if (rc != 0) {                                                         \
            zpc_ec_key_free(&ec_key);                                          \
            GTEST_SKIP_("KERNEL_CAPS check (EC): error setting key type.");    \
        }                                                                      \
        if (mkvp != NULL) {                                                    \
            rc = zpc_ec_key_set_mkvp(ec_key, mkvp);                            \
            if (rc != 0) {                                                     \
                zpc_ec_key_free(&ec_key);                                      \
                GTEST_SKIP_("KERNEL_CAPS check (EC): error setting mkvp.");    \
            }                                                                  \
        } else {                                                               \
            rc = zpc_ec_key_set_apqns(ec_key, apqns);                          \
            switch (rc) {                                                      \
            case 0:                                                            \
                break;                                                         \
            case ZPC_ERROR_APQNS_INVALID_VERSION:                              \
                zpc_ec_key_free(&ec_key);                                      \
                GTEST_SKIP_("KERNEL_CAPS check (EC): probably card older than CEX7."); \
            default:                                                           \
                zpc_ec_key_free(&ec_key);                                      \
                GTEST_SKIP_("KERNEL_CAPS check (EC): error setting apqns.");   \
            }                                                                  \
        }                                                                      \
        if (type != ZPC_EC_KEY_TYPE_PVSECRET) {                                \
            rc = zpc_ec_key_generate(ec_key);                                  \
            if (rc == ZPC_ERROR_IOCTLBLOB2PROTK3) {                            \
                zpc_ec_key_free(&ec_key);                                      \
                GTEST_SKIP_("KERNEL_CAPS check (EC): ioctl PKEY_KBLOB2PROTK3 not supported by kernel."); \
            }                                                                  \
            if (rc != 0) {                                                     \
                zpc_ec_key_free(&ec_key);                                      \
                GTEST_SKIP_("KERNEL_CAPS check (EC): Unexpected error when generating test key."); \
            }                                                                  \
        }                                                                      \
                                                                               \
        zpc_ec_key_free(&ec_key);                                              \
} while (0)

/**
 * The reencipher tests require current and new master keys set in the
 * related CCA or EP11 APQNs. For CCA, also "reencipher old to current" is
 * supported, but currently not tested to keep tests independent of key types.
 * Either mkvp or apqns must be specified (not NULL)
 */
# define TESTLIB_EC_NEW_MK_CHECK(type,mkvp,apqns)                              \
do {                                                                           \
        int rc;                                                                \
        struct zpc_ec_key *ec_key;                                             \
                                                                               \
        if (type == ZPC_EC_KEY_TYPE_PVSECRET)                                  \
            break; /* silently skip check */                                   \
                                                                               \
        rc = zpc_ec_key_alloc(&ec_key);                                        \
        if (rc != 0)                                                           \
            GTEST_SKIP_("NEW_MK check (EC): Cannot allocate key object.");     \
                                                                               \
        rc = zpc_ec_key_set_type(ec_key, type);                                \
        if (type == ZPC_EC_KEY_TYPE_CCA &&                                     \
            rc == ZPC_ERROR_CCA_HOST_LIB_NOT_AVAILABLE) {                      \
            zpc_ec_key_free(&ec_key);                                          \
            GTEST_SKIP_("NEW_MK check (EC): CCA host lib not available or too old (min CCA 7.0).");  \
        }                                                                      \
        if (type == ZPC_EC_KEY_TYPE_EP11 &&                                    \
            rc == ZPC_ERROR_EP11_HOST_LIB_NOT_AVAILABLE) {                     \
            zpc_ec_key_free(&ec_key);                                          \
            GTEST_SKIP_("NEW_MK check (EC): EP11 host lib not available or too old (min EP11 3.0)."); \
        }                                                                      \
        if (mkvp != NULL) {                                                    \
            rc = zpc_ec_key_set_mkvp(ec_key, mkvp);                            \
            if (rc != 0) {                                                     \
                zpc_ec_key_free(&ec_key);                                      \
                GTEST_SKIP_("NEW_MK check (EC): error setting mkvp.");         \
            }                                                                  \
        } else {                                                               \
            rc = zpc_ec_key_set_apqns(ec_key, apqns);                          \
            if (rc != 0) {                                                     \
                zpc_ec_key_free(&ec_key);                                      \
                GTEST_SKIP_("NEW_MK check (EC): error setting apqns.");        \
            }                                                                  \
        }                                                                      \
        rc = zpc_ec_key_set_curve(ec_key, ZPC_EC_CURVE_P256);/* cannot fail */ \
        rc = zpc_ec_key_generate(ec_key);                                      \
        if (rc != 0) {                                                         \
            zpc_ec_key_free(&ec_key);                                          \
            GTEST_SKIP_("NEW_MK check (EC): error generating test key.");      \
        }                                                                      \
        rc = zpc_ec_key_reencipher(ec_key, ZPC_EC_KEY_REENCIPHER_CURRENT_TO_NEW); \
        if (rc != 0) {                                                         \
            zpc_ec_key_free(&ec_key);                                          \
            GTEST_SKIP_("NEW_MK check (EC): new MK not set for this APQN/MKVP."); \
        }                                                                      \
        zpc_ec_key_free(&ec_key);                                              \
} while (0)

# define TESTLIB_APQN_CAPS_CHECK(apqns, mkvp, type, size, flags)               \
do {                                                                           \
        int rc;                                                                \
        struct zpc_aes_key *aes_key;                                           \
        const u8 key[32] = {0};                                                \
        if (type == ZPC_AES_KEY_TYPE_PVSECRET)                                 \
            break; /* silently skip check */                                   \
        rc = zpc_aes_key_alloc(&aes_key);                                      \
        if (rc != 0)                                                           \
            GTEST_SKIP_("APQN_CAPS check: Cannot allocate key object.");       \
        rc = zpc_aes_key_set_type(aes_key, type);                              \
        rc += zpc_aes_key_set_size(aes_key, size);                             \
        rc += zpc_aes_key_set_flags(aes_key, flags);                           \
        if (rc != 0)                                                           \
            GTEST_SKIP_("APQN_CAPS check: Cannot set type, size, and flags."); \
        if (apqns != NULL)                                                     \
            rc = zpc_aes_key_set_apqns(aes_key, apqns);                        \
        if (rc != 0)                                                           \
            GTEST_SKIP_("APQN_CAPS check: Cannot set apqns.");                 \
        if (mkvp != NULL)                                                      \
            rc = zpc_aes_key_set_mkvp(aes_key, mkvp);                          \
        if (rc != 0)                                                           \
            GTEST_SKIP_("APQN_CAPS check: Cannot set mkvp.");                  \
        rc = zpc_aes_key_import_clear(aes_key, key);                           \
        switch (rc) {                                                          \
        case ZPC_ERROR_IOCTLCLR2SECK2:                                         \
            GTEST_SKIP_("APQN_CAPS check: Cannot create a protected key, "     \
                        "probably card older than CEX7 or no MK set.");        \
        default:                                                               \
            break;                                                             \
        }                                                                      \
        zpc_aes_key_free(&aes_key);                                            \
} while (0)

# define TESTLIB_ENV_HMAC_KEY_CHECK()                                          \
do {                                                                           \
        int type;                                                              \
        zpc_hmac_hashfunc_t hfunc = testlib_env_hmac_hashfunc();               \
                                                                               \
        switch (hfunc) {                                                       \
        case ZPC_HMAC_HASHFUNC_SHA_224:                                        \
        case ZPC_HMAC_HASHFUNC_SHA_256:                                        \
        case ZPC_HMAC_HASHFUNC_SHA_384:                                        \
        case ZPC_HMAC_HASHFUNC_SHA_512:                                        \
            break;                                                             \
        case ZPC_HMAC_HASHFUNC_NOT_SET:                                        \
            GTEST_SKIP_("ZPC_TEST_HMAC_HASH_FUNCTION environment variable not set."); \
            break;                                                             \
        default:                                                               \
            GTEST_SKIP_("ZPC_TEST_HMAC_HASH_FUNCTION environment variable set to invalid value."); \
            break;                                                             \
        }                                                                      \
                                                                               \
        type = testlib_env_hmac_key_type();                                    \
        switch (type) {                                                        \
        case ZPC_HMAC_KEY_TYPE_PVSECRET:                                       \
            break;                                                             \
        case -1:                                                               \
            GTEST_SKIP_("ZPC_TEST_HMAC_KEY_TYPE environment variable set to invalid value."); \
        default:                                                               \
            GTEST_SKIP_("ZPC_TEST_HMAC_KEY_TYPE environment variable not set."); \
            break;                                                             \
        }                                                                      \
} while (0)

/*
 * Check MSA 11 (protected key HMAC) availability.
 */
# define TESTLIB_HMAC_HW_CAPS_CHECK()                                          \
do {                                                                           \
        int rc;                                                                \
        struct zpc_hmac *hmac;                                                 \
                                                                               \
        rc = zpc_hmac_alloc(&hmac);                                            \
        switch (rc) {                                                          \
        case ZPC_ERROR_DEVPKEY:                                                \
            GTEST_SKIP_("HW_CAPS check (HMAC): opening /dev/pkey failed.");    \
            break;                                                             \
        case ZPC_ERROR_HWCAPS:                                                 \
            GTEST_SKIP_("HW_CAPS check (HMAC): no HW capabilities for HMAC."); \
            break;                                                             \
        case ZPC_ERROR_MALLOC:                                                 \
            GTEST_SKIP_("HW_CAPS check (HMAC): cannot allocate HMAC context.");\
            break;                                                             \
        default:                                                               \
            zpc_hmac_free(&hmac);                                              \
            break;                                                             \
        }                                                                      \
} while (0)

/*
 * Check availability of PVSECRET support. This requires that we are running
 * in a secure execution guest under KVM.
 */
# define TESTLIB_HMAC_SW_CAPS_CHECK(type)                                      \
do {                                                                           \
        int rc;                                                                \
        struct zpc_hmac_key *hmac_key;                                         \
                                                                               \
        rc = zpc_hmac_key_alloc(&hmac_key);                                    \
        if (rc != 0) {                                                         \
            zpc_hmac_key_free(&hmac_key);                                      \
            GTEST_SKIP_("SW_CAPS check (HMAC): zpc_hmac_key_alloc failed.");   \
            break;                                                             \
        }                                                                      \
        rc = zpc_hmac_key_set_type(hmac_key, type);                            \
        switch (rc) {                                                          \
        case ZPC_ERROR_DEVPKEY:                                                \
            zpc_hmac_key_free(&hmac_key);                                      \
            GTEST_SKIP_("SW_CAPS check (HMAC): opening /dev/pkey failed.");    \
            break;                                                             \
        case ZPC_ERROR_HWCAPS:                                                 \
            zpc_hmac_key_free(&hmac_key);                                      \
            GTEST_SKIP_("SW_CAPS check (HMAC): no HW capabilities for HMAC."); \
            break;                                                             \
        case ZPC_ERROR_UV_PVSECRETS_NOT_AVAILABLE:                             \
            zpc_hmac_key_free(&hmac_key);                                      \
            GTEST_SKIP_("SW_CAPS check (HMAC): PVSECRET support not available on this system.");\
            break;                                                             \
        default:                                                               \
            zpc_hmac_key_free(&hmac_key);                                      \
            break;                                                             \
        }                                                                      \
} while (0)

/*
 * Check if kernel PKEY module supports protected key HMAC via PCKMO.
 */
# define TESTLIB_HMAC_KERNEL_CAPS_CHECK()                                      \
do {                                                                           \
        int rc;                                                                \
        struct zpc_hmac_key *key;                                              \
        unsigned char buf[64];                                                 \
                                                                               \
        rc = zpc_hmac_key_alloc(&key);                                         \
        if (rc != 0) {                                                         \
            zpc_hmac_key_free(&key);                                           \
            GTEST_SKIP_("KERNEL_CAPS check (HMAC): zpc_hmac_key_alloc failed."); \
        }                                                                      \
        rc = zpc_hmac_key_set_hash_function(key, ZPC_HMAC_HASHFUNC_SHA_256);   \
        if (rc != 0) {                                                         \
            zpc_hmac_key_free(&key);                                           \
            GTEST_SKIP_("KERNEL_CAPS check (HMAC): Cannot set hash function."); \
        }                                                                      \
        rc = zpc_hmac_key_import_clear(key, buf, sizeof(buf));                 \
        if (rc != 0) {                                                         \
            zpc_hmac_key_free(&key);                                           \
            GTEST_SKIP_("KERNEL_CAPS check (HMAC): no kernel support for HMAC."); \
        }                                                                      \
        zpc_hmac_key_free(&key);                                               \
} while (0)

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;

struct EC_TEST_VECTOR {
	int curve;
	unsigned char privkey[66];
	int privkey_len;
	unsigned char pubkey[132];
	int pubkey_len;
	unsigned char msg[64];
	int msg_len;
	unsigned char sig[144];
	int sig_len;
};
extern const struct EC_TEST_VECTOR ec_tv[5];

const char *testlib_env_aes_key_mkvp(void);
int testlib_env_aes_key_apqns(const char *[257]);
void testlib_env_aes_key_check(void);
int testlib_env_aes_key_size(void);
int testlib_env_aes_key_type(void);
unsigned int testlib_env_aes_key_flags(void);

const char *testlib_env_ec_key_mkvp(void);
int testlib_env_ec_key_apqns(const char *[257]);
void testlib_env_ec_key_check(void);
zpc_ec_curve_t testlib_env_ec_key_curve(void);
int testlib_env_ec_key_type(void);
unsigned int testlib_env_ec_key_flags(void);

zpc_hmac_hashfunc_t testlib_env_hmac_hashfunc(void);
int testlib_env_hmac_key_type(void);

int testlib_get_aes_pvsecret_id(int keysize, unsigned char outbuf[32]);
int testlib_set_aes_key_from_pvsecret(struct zpc_aes_key *aes_key, int size);
int testlib_set_aes_key_from_file(struct zpc_aes_key *aes_key, int type, int size);
int testlib_get_ec_pvsecret_id(zpc_ec_curve_t curve, unsigned char outbuf[32]);
int testlib_set_ec_key_from_pvsecret(struct zpc_ec_key *ec_key, int type, zpc_ec_curve_t curve);
int testlib_set_ec_key_from_file(struct zpc_ec_key *ec_key, int type, zpc_ec_curve_t curve);
int testlib_set_hmac_key_from_pvsecret(struct zpc_hmac_key *hmac_key, size_t size);
int testlib_set_hmac_key_from_file(struct zpc_hmac_key *hmac_key, int type, size_t size);

unsigned char *testlib_hexstr2buf(const char *, size_t *);
unsigned char *testlib_hexstr2fixedbuf(const char *hexstr, size_t tolen);
char *testlib_buf2hexstr(const unsigned char *, size_t);

# ifdef __cplusplus
/* *INDENT-OFF* */
}
/* *INDENT-ON* */
# endif
#endif
