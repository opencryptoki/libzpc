// SPDX-License-Identifier: MIT
// Copyright contributors to the libzpc project
#ifndef OPENSSL_H
#define OPENSSL_H

#include <stdio.h>

int openssl_init(void);

void openssl_term(void);

int openssl_process_config(const char *label, const char *uri, size_t lineno);

#endif
