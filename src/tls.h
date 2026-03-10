// SPDX-License-Identifier: MIT
// Copyright contributors to the libzpc project
#ifndef _TLS_H
#define _TLS_H

#include <openssl/core.h>

int tls_group_capabilities(OSSL_CALLBACK *cb, void *arg);

#endif /* _TLS_H */
