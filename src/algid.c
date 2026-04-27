// SPDX-License-Identifier: MIT
// Copyright contributors to the libzpc project
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/objects.h>

#include "provider.h"
#include "ossl.h"
#include "algid.h"

#define DER_OID_HDR(OLEN)	0x30, (OLEN + 2), 0x06, (OLEN)
#define OID_ECDSA_SHA1		0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04
#define OID_ECDSA_SHA2		0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03
#define OID_ECDSA_SHA3		0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03
#define OID_EDDSA		0x2B, 0x65

#define DER_ECDSA_SHA1		DER_OID_HDR(7), OID_ECDSA_SHA1, 0x01
#define DER_ECDSA_SHA2_224	DER_OID_HDR(8), OID_ECDSA_SHA2, 0x01
#define DER_ECDSA_SHA2_256	DER_OID_HDR(8), OID_ECDSA_SHA2, 0x02
#define DER_ECDSA_SHA2_384	DER_OID_HDR(8), OID_ECDSA_SHA2, 0x03
#define DER_ECDSA_SHA2_512	DER_OID_HDR(8), OID_ECDSA_SHA2, 0x04
#define DER_ECDSA_SHA3_224	DER_OID_HDR(9), OID_ECDSA_SHA3, 0x09
#define DER_ECDSA_SHA3_256	DER_OID_HDR(9), OID_ECDSA_SHA3, 0x0A
#define DER_ECDSA_SHA3_384	DER_OID_HDR(9), OID_ECDSA_SHA3, 0x0B
#define DER_ECDSA_SHA3_512	DER_OID_HDR(9), OID_ECDSA_SHA3, 0x0C
#define DER_EDDSA_25519		DER_OID_HDR(3), OID_EDDSA, 0x70
#define DER_EDDSA_448		DER_OID_HDR(3), OID_EDDSA, 0x71

struct ecdsa_algid {
	int type;
	const unsigned char *der;
	size_t derlen;
};
#define ECDSA_ALGID(md, MD) {				\
	.type = NID_##md,				\
	.der = der_ECDSA_##MD,				\
	.derlen = sizeof(der_ECDSA_##MD)		\
}

struct eddsa_algid {
	const char *alg;
	const unsigned char *der;
	size_t derlen;
};
#define EDDSA_ALGID(curve) {				\
	.alg = SN_ED##curve,				\
	.der = der_EDDSA_##curve,			\
	.derlen = sizeof(der_EDDSA_##curve)		\
}

#define DER(TYPE, SUBTYPE)				\
	static unsigned char der_##TYPE##_##SUBTYPE[] = { DER_##TYPE##_##SUBTYPE }

DER(ECDSA, SHA1);
DER(ECDSA, SHA2_224);
DER(ECDSA, SHA2_256);
DER(ECDSA, SHA2_384);
DER(ECDSA, SHA2_512);
DER(ECDSA, SHA3_224);
DER(ECDSA, SHA3_256);
DER(ECDSA, SHA3_384);
DER(ECDSA, SHA3_512);

DER(EDDSA, 25519);
DER(EDDSA, 448);

static struct ecdsa_algid ecdsa_algid_map[] = {
	ECDSA_ALGID(sha1, SHA1),
	ECDSA_ALGID(sha224, SHA2_224),
	ECDSA_ALGID(sha256, SHA2_256),
	ECDSA_ALGID(sha384, SHA2_384),
	ECDSA_ALGID(sha512, SHA2_512),
	ECDSA_ALGID(sha3_224, SHA3_224),
	ECDSA_ALGID(sha3_256, SHA3_256),
	ECDSA_ALGID(sha3_384, SHA3_384),
	ECDSA_ALGID(sha3_512, SHA3_512),
};

static struct eddsa_algid eddsa_algid_map[] = {
	EDDSA_ALGID(25519),
	EDDSA_ALGID(448),
};

int algid_ecdsa(int type, OSSL_PARAM *p)
{
	struct ecdsa_algid *a = NULL;
	int rv = OSSL_RV_ERR;
	size_t i;

	for (i = 0; i < ARRAY_SIZE(ecdsa_algid_map); i++) {
		a = &ecdsa_algid_map[i];
		if (type != a->type)
			continue;
		break;
	}
	if (i == ARRAY_SIZE(ecdsa_algid_map))
		goto out;

	rv = OSSL_PARAM_set_octet_string(p, a->der, a->derlen);
out:
	return rv;
}

int algid_eddsa(const char *alg, OSSL_PARAM *p)
{
	struct eddsa_algid *a = NULL;
	int rv = OSSL_RV_ERR;
	size_t i;

	for (i = 0; i < ARRAY_SIZE(eddsa_algid_map); i++) {
		a = &eddsa_algid_map[i];
		if (OPENSSL_strcasecmp(alg, a->alg) == 0)
			continue;
		break;
	}
	if (i == ARRAY_SIZE(eddsa_algid_map))
		goto out;

	rv = OSSL_PARAM_set_octet_string(p, a->der, a->derlen);
out:
	return rv;
}
