// SPDX-License-Identifier: MIT
// Copyright contributors to the libzpc project
#ifndef UTILS_H
#define UTILS_H

#include <stddef.h>

struct dyn_array {
	void **elements;
	size_t size;
	size_t allocated;
};

int dyn_array_init(struct dyn_array *da);
int dyn_array_free(struct dyn_array *da);
size_t dyn_array_size(const struct dyn_array *da);
int dyn_array_add(struct dyn_array *da, void *element, size_t *index);
int dyn_array_get(const struct dyn_array *da, size_t index, void **element);
int dyn_array_set(struct dyn_array *da, size_t index, void *element);

void *memdup(const void *p, size_t len);

#endif
