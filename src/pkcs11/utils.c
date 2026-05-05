// SPDX-License-Identifier: MIT
// Copyright contributors to the libzpc project
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "utils.h"

#define DYN_ARRAY_CHUNK_SIZE	32

int dyn_array_init(struct dyn_array *da)
{
	if (!da)
		return 0;

	da->elements = NULL;
	da->size = 0;
	da->allocated = 0;

	return 1;
}

int dyn_array_free(struct dyn_array *da)
{
	if (!da)
		return 0;

	if (da->elements)
		free(da->elements);

	da->elements = NULL;
	da->size = 0;
	da->allocated = 0;

	return 1;
}

size_t dyn_array_size(const struct dyn_array *da)
{
	if (!da)
		return 0;

	return da->size;
}

int dyn_array_add(struct dyn_array *da, void *element, size_t *index)
{
	void **tmp;
	size_t new_alloc;

	if (!da)
		return 0;

	if (da->allocated == 0 || da->allocated <= da->size) {
		new_alloc = da->allocated + DYN_ARRAY_CHUNK_SIZE;
		if (new_alloc < da->allocated ||
		    new_alloc > SIZE_MAX / sizeof(void *))
			return 0;

		tmp = realloc(da->elements, new_alloc * sizeof(void *));
		if (!tmp)
			return 0;

		da->elements = tmp;
		da->allocated = new_alloc;
	}

	if (index)
		*index = da->size;

	da->elements[da->size++] = element;
	return 1;
}

int dyn_array_get(const struct dyn_array *da, size_t index, void **element)
{
	if (!da || !element)
		return 0;

	if (index >= da->size)
		return 0;

	*element = da->elements[index];
	return 1;
}

int dyn_array_set(struct dyn_array *da, size_t index, void *element)
{
	if (!da)
		return 0;

	if (index >= da->size)
		return 0;

	da->elements[index] = element;
	return 1;
}

void *memdup(const void *p, size_t len)
{
	void *ret;

	if (!p || len == 0)
		return NULL;

	ret = malloc(len);
	if (ret)
		memcpy(ret, p, len);

	return ret;
}
