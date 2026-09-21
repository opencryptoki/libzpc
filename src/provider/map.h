// SPDX-License-Identifier: MIT
// Copyright contributors to the libzpc project
#ifndef _MAP_H
#define _MAP_H

#include <zpc/ecc_key.h>

#include "object.h"

char *alg2data_type(const char *alg);
int alg2object_type(const char *alg);
zpc_ec_curve_t alg2key_curve(const char *alg);
int alg2key_size(const char *alg);

char *obj_data_type(const struct obj *alg);
int obj_object_type(const struct obj *alg);
zpc_ec_curve_t obj_key_curve(const struct obj *alg);
int obj_key_size(const struct obj *alg);

#endif /* _MAP_H */
