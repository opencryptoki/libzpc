// SPDX-License-Identifier: MIT
// Copyright contributors to the libzpc project
// Derived from OpenSSL source
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/prov_ssl.h>

#include "provider.h"
#include "ossl.h"
#include "tls.h"

/* taken from include/internal/tlsgroups.h */
#define OSSL_TLS_GROUP_ID_secp256r1	0x0017
#define OSSL_TLS_GROUP_ID_secp384r1	0x0018
#define OSSL_TLS_GROUP_ID_secp521r1	0x0019

/* taken from providers/common/capabilities.c */
#define TLS_GROUP_ENTRY(tlsname, realname, algorithm, idx)		\
{									\
	OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_GROUP_NAME,		\
			       tlsname, sizeof(tlsname)),		\
	OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_GROUP_NAME_INTERNAL,	\
			       realname, sizeof(realname)),		\
	OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_GROUP_ALG,		\
			       algorithm, sizeof(algorithm)),		\
	OSSL_PARAM_uint(OSSL_CAPABILITY_TLS_GROUP_ID,			\
			(unsigned int *)&group_list[idx].group_id),	\
	OSSL_PARAM_uint(OSSL_CAPABILITY_TLS_GROUP_SECURITY_BITS,	\
			(unsigned int *)&group_list[idx].secbits),	\
	OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_MIN_TLS,		\
		       (unsigned int *)&group_list[idx].mintls),	\
	OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_MAX_TLS,		\
		       (unsigned int *)&group_list[idx].maxtls),	\
	OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_MIN_DTLS,		\
		       (unsigned int *)&group_list[idx].mindtls),	\
	OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_MAX_DTLS,		\
		       (unsigned int *)&group_list[idx].maxdtls),	\
	OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_IS_KEM,		\
		       (unsigned int *)&group_list[idx].is_kem),	\
	OSSL_PARAM_END							\
}

typedef struct tls_group_constants_st {
	unsigned int group_id; /* Group ID */
	unsigned int secbits; /* Bits of security */
	int mintls; /* Minimum TLS version, -1 unsupported */
	int maxtls; /* Maximum TLS version (or 0 for undefined) */
	int mindtls; /* Minimum DTLS version, -1 unsupported */
	int maxdtls; /* Maximum DTLS version (or 0 for undefined) */
	int is_kem; /* Indicates utility as KEM */
} TLS_GROUP_CONSTANTS;

static const TLS_GROUP_CONSTANTS group_list[] = {
	[0] = { OSSL_TLS_GROUP_ID_secp256r1, 128, TLS1_VERSION, 0, DTLS1_VERSION, 0, 0 },
	[1] = { OSSL_TLS_GROUP_ID_secp384r1, 192, TLS1_VERSION, 0, DTLS1_VERSION, 0, 0 },
	[2] = { OSSL_TLS_GROUP_ID_secp521r1, 256, TLS1_VERSION, 0, DTLS1_VERSION, 0, 0 },
};

static const OSSL_PARAM tls_group_list[][11] = {
	TLS_GROUP_ENTRY("secp256r1", "prime256v1", "EC", 0),
	TLS_GROUP_ENTRY("P-256", "prime256v1", "EC", 0),
	TLS_GROUP_ENTRY("secp384r1", "secp384r1", "EC", 1),
	TLS_GROUP_ENTRY("P-384", "secp384r1", "EC", 1),
	TLS_GROUP_ENTRY("secp521r1", "secp521r1", "EC", 2),
	TLS_GROUP_ENTRY("P-521", "secp521r1", "EC", 2),
};

int tls_group_capabilities(OSSL_CALLBACK *cb, void *arg)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(tls_group_list); i++) {
		if (cb(tls_group_list[i], arg) != OSSL_RV_OK)
			return OSSL_RV_ERR;
	}

	return OSSL_RV_OK;
}
