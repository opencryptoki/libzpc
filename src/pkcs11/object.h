// SPDX-License-Identifier: MIT
// Copyright contributors to the libzpc project
#ifndef OBJECT_H
#define OBJECT_H

#include "pkcs11.h"

#define MAX_ATTRIBUTES	64

typedef unsigned long object_id_t;

struct pkcs11_object {
	CK_OBJECT_CLASS class;
	const char *label;
	char unique_id[sizeof(object_id_t) * 2 + 1];
	CK_KEY_TYPE keytype;
	CK_ULONG id;

	CK_ATTRIBUTE attrs[MAX_ATTRIBUTES];
	CK_ULONG num_attrs;
};

int object_init(struct pkcs11_object **obj, const char *label, CK_ULONG id,
		CK_OBJECT_CLASS class, CK_KEY_TYPE keytype);
void object_free(struct pkcs11_object *obj);

#endif
