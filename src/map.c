// SPDX-License-Identifier: MIT
// Copyright contributors to the libzpc project
#include <openssl/crypto.h>
#include <openssl/core_names.h>
#include <openssl/core_object.h>
#include <openssl/obj_mac.h>

#include "provider.h"
#include "map.h"

static struct {
	const char *alg;
	union {
		int key_size;
		zpc_ec_curve_t key_curve;
	};
	int object_type;
	char *data_type;
} alg_map[] = {
	{
		.alg = SN_X9_62_prime256v1,
		.key_curve = ZPC_EC_CURVE_P256,
		.object_type = OSSL_OBJECT_PKEY,
		.data_type = PROV_NAME_EC,
	}, {
		.alg = SN_secp384r1,
		.key_curve = ZPC_EC_CURVE_P384,
		.object_type = OSSL_OBJECT_PKEY,
		.data_type = PROV_NAME_EC,
	}, {
		.alg = SN_secp521r1,
		.key_curve = ZPC_EC_CURVE_P521,
		.object_type = OSSL_OBJECT_PKEY,
		.data_type = PROV_NAME_EC,
	}, {
		.alg = SN_ED25519,
		.key_curve = ZPC_EC_CURVE_ED25519,
		.object_type = OSSL_OBJECT_PKEY,
		.data_type = PROV_NAME_ED25519,
	}, {
		.alg = SN_ED448,
		.key_curve = ZPC_EC_CURVE_ED448,
		.object_type = OSSL_OBJECT_PKEY,
		.data_type = PROV_NAME_ED448,
	}, { 0 },
};

char *alg2data_type(const char *alg)
{
	char *rv = NULL;
	size_t i;

	if (!alg)
		return rv;

	for (i = 0; alg_map[i].alg; i++) {
		if (OPENSSL_strcasecmp(alg_map[i].alg, alg) == 0) {
			rv = alg_map[i].data_type;
			break;
		}
	}

	return rv;
}

int alg2object_type(const char *alg)
{
	int rv = OSSL_OBJECT_UNKNOWN;
	size_t i;

	if (!alg)
		return rv;

	for (i = 0; alg_map[i].alg; i++) {
		if (OPENSSL_strcasecmp(alg_map[i].alg, alg) == 0) {
			rv = alg_map[i].object_type;
			break;
		}
	}

	return rv;
}

zpc_ec_curve_t alg2key_curve(const char *alg)
{
	zpc_ec_curve_t rv = ZPC_EC_CURVE_INVALID;
	size_t i;

	if (!alg)
		return rv;

	for (i = 0; alg_map[i].alg; i++) {
		if (OPENSSL_strcasecmp(alg_map[i].alg, alg) == 0) {
			rv = alg_map[i].key_curve;
			break;
		}
	}

	return rv;
}

int alg2key_size(const char *alg)
{
	int rv = 0;
	size_t i;

	if (!alg)
		return rv;

	for (i = 0; alg_map[i].alg; i++) {
		if (OPENSSL_strcasecmp(alg_map[i].alg, alg) == 0) {
			rv = alg_map[i].key_size;
			break;
		}
	}

	return rv;
}

char *obj_data_type(const struct obj *obj)
{
	const char *alg = obj ? obj->origin_alg : NULL;
	return alg2data_type(alg);
}

int obj_object_type(const struct obj *obj)
{
	const char *alg = obj ? obj->origin_alg : NULL;
	return alg2object_type(alg);
}

zpc_ec_curve_t obj_key_curve(const struct obj *obj)
{
	const char *alg = obj ? obj->origin_alg : NULL;
	return alg2key_curve(alg);
}

int obj_key_size(const struct obj *obj)
{
	const char *alg = obj ? obj->origin_alg : NULL;
	return alg2key_size(alg);
}
