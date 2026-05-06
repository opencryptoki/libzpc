// SPDX-License-Identifier: MIT
// Copyright contributors to the libzpc project
#ifndef OPENSSL_H
#define OPENSSL_H

#include <stdio.h>
#include <openssl/evp.h>

int openssl_init(void);

void openssl_term(void);

int openssl_process_config(const char *label, const char *uri, size_t lineno);

EVP_PKEY_CTX *openssl_get_pkey_context(EVP_PKEY *pkey);
EVP_MD_CTX *openssl_get_digest_sign_context(EVP_PKEY *pkey,
					    const char *mdname);
EVP_MD_CTX *openssl_get_digest_verify_context(EVP_PKEY *pkey,
					      const char *mdname);

#endif
