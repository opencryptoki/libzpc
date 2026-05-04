// SPDX-License-Identifier: MIT
// Copyright contributors to the libzpc project
#ifndef CONFIG_H
#define CONFIG_H

#include <stdio.h>

int config_process(int (*cb)(const char *label, const char *uri,
			     size_t lineno));

#endif
