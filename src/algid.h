// SPDX-License-Identifier: MIT
// Copyright contributors to the libzpc project
#ifndef _ALGID_H
#define _ALGID_H

#include <openssl/params.h>

int algid_ecdsa(int type, OSSL_PARAM *p);
int algid_eddsa(const char *alg, OSSL_PARAM *p);

#endif /* _ALGID_H */
