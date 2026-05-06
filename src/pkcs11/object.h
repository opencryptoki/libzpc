// SPDX-License-Identifier: MIT
// Copyright contributors to the libzpc project
#ifndef OBJECT_H
#define OBJECT_H

#include <openssl/evp.h>
#include "pkcs11.h"
#include "utils.h"

#define MAX_ATTRIBUTES	64

typedef unsigned long object_id_t;

struct pkcs11_object {
	CK_OBJECT_HANDLE handle;
	CK_OBJECT_CLASS class;
	const char *label;
	char unique_id[sizeof(object_id_t) * 2 + 1];
	CK_KEY_TYPE keytype;
	CK_ULONG id;

	CK_ATTRIBUTE attrs[MAX_ATTRIBUTES];
	CK_ULONG num_attrs;

	union {
		struct {
			unsigned char *ec_params;
			size_t ec_params_len;
			unsigned char *ec_point;
			size_t ec_point_len;
			unsigned char *spki;
			size_t spki_len;
			size_t prime_len;
			EVP_PKEY *pkey;
		} ec_ed;
	} data;
};

int object_init(struct pkcs11_object **obj, const char *label, CK_ULONG id,
		CK_OBJECT_CLASS class, CK_KEY_TYPE keytype);
int object_get_size(struct pkcs11_object *obj, CK_ULONG *obj_size);
CK_RV object_get_attributes(struct pkcs11_object *obj, CK_ATTRIBUTE_PTR pTemplate,
			   CK_ULONG ulCount);
void object_free(struct pkcs11_object *obj);

int object_list_init(void);
void object_list_term(void);

int object_add_ec_ed_private_key(const char *label, CK_ULONG id,
				 CK_KEY_TYPE keytype,
				 const unsigned char *ec_params,
				 size_t ec_params_len,
				 const unsigned char *spki, size_t spki_len,
				 size_t prime_len,
				 EVP_PKEY *pkey);
int object_add_ec_ed_public_key(const char *label, CK_ULONG id,
				CK_KEY_TYPE keytype,
				const unsigned char *ec_params,
				size_t ec_params_len,
				const unsigned char *ec_point,
				size_t ec_point_len,
				const unsigned char *spki, size_t spki_len,
				size_t prime_len,
				EVP_PKEY *pkey);

int object_list_find(CK_ATTRIBUTE *pTemplate, CK_ULONG ulCount,
		     struct dyn_array *result);

int object_list_get(CK_OBJECT_HANDLE handle, struct pkcs11_object **obj);

#endif
