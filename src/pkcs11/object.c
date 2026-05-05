// SPDX-License-Identifier: MIT
// Copyright contributors to the libzpc project
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "object.h"
#include "utils.h"

static CK_BBOOL ck_true = CK_TRUE;
static CK_BBOOL ck_false = CK_FALSE;

/*
 * The object list is populated exclusively during C_Initialize and torn down
 * during C_Finalize. Both are single-threaded by the PKCS#11 spec. After
 * C_Initialize returns the list is read-only, so no locking is needed for
 * concurrent read access from multiple threads.
 */
static struct dyn_array objects;
static object_id_t object_id_counter = 0;

static int object_add_attr(struct pkcs11_object *obj, CK_ATTRIBUTE_TYPE type,
			   CK_VOID_PTR value, CK_ULONG len)
{
	if (!obj)
		return 0;

	if (obj->num_attrs >= MAX_ATTRIBUTES)
		return 0;

	obj->attrs[obj->num_attrs].type = type;
	obj->attrs[obj->num_attrs].pValue = value;
	obj->attrs[obj->num_attrs].ulValueLen = len;
	obj->num_attrs++;

	return 1;
}

static int object_add_ulong_attr(struct pkcs11_object *obj,
				 CK_ATTRIBUTE_TYPE type, CK_ULONG *val)
{
	return object_add_attr(obj, type, val, sizeof(*val));
}

static int object_add_bool_attr(struct pkcs11_object *obj,
				CK_ATTRIBUTE_TYPE type, CK_BBOOL *val)
{
	return object_add_attr(obj, type, val, sizeof(*val));
}

static int object_setup_public_key_default_attrs(struct pkcs11_object *obj)
{
	if (!obj)
		return 0;

	/* Public key object attributes */
	if (!object_add_attr(obj, CKA_SUBJECT, NULL, 0))
		return 0;
	if (!object_add_bool_attr(obj, CKA_ENCRYPT, &ck_false))
		return 0;
	if (!object_add_bool_attr(obj, CKA_VERIFY, &ck_true))
		return 0;
	if (!object_add_bool_attr(obj, CKA_VERIFY_RECOVER, &ck_false))
		return 0;
	if (!object_add_bool_attr(obj, CKA_WRAP, &ck_false))
		return 0;
	if (!object_add_bool_attr(obj, CKA_ENCAPSULATE, &ck_false))
		return 0;
	if (!object_add_bool_attr(obj, CKA_TRUSTED, &ck_false))
		return 0;
	if (!object_add_attr(obj, CKA_WRAP_TEMPLATE, NULL, 0))
		return 0;

	return 1;
}

static int object_setup_private_key_default_attrs(struct pkcs11_object *obj)
{
	if (!obj)
		return 0;

	/* Private key object attributes */
	if (!object_add_attr(obj, CKA_SUBJECT, NULL, 0))
		return 0;
	if (!object_add_bool_attr(obj, CKA_SENSITIVE, &ck_true))
		return 0;
	if (!object_add_bool_attr(obj, CKA_ALWAYS_SENSITIVE, &ck_true))
		return 0;
	if (!object_add_bool_attr(obj, CKA_EXTRACTABLE, &ck_false))
		return 0;
	if (!object_add_bool_attr(obj, CKA_NEVER_EXTRACTABLE, &ck_true))
		return 0;
	if (!object_add_bool_attr(obj, CKA_DECRYPT, &ck_false))
		return 0;
	if (!object_add_bool_attr(obj, CKA_SIGN, &ck_true))
		return 0;
	if (!object_add_bool_attr(obj, CKA_SIGN_RECOVER, &ck_false))
		return 0;
	if (!object_add_bool_attr(obj, CKA_UNWRAP, &ck_false))
		return 0;
	if (!object_add_bool_attr(obj, CKA_DECAPSULATE, &ck_false))
		return 0;
	if (!object_add_bool_attr(obj, CKA_WRAP_WITH_TRUSTED, &ck_false))
		return 0;
	if (!object_add_bool_attr(obj, CKA_ALWAYS_AUTHENTICATE, &ck_false))
		return 0;
	if (!object_add_attr(obj, CKA_UNWRAP_TEMPLATE, NULL, 0))
		return 0;
	if (!object_add_attr(obj, CKA_DERIVE_TEMPLATE, NULL, 0))
		return 0;

	return 1;
}

static int object_setup_default_attrs(struct pkcs11_object *obj)
{
	if (!obj)
		return 0;

	/* Common object attributes */
	if (!object_add_ulong_attr(obj, CKA_CLASS, &obj->class))
		return 0;

	/* Storage object attributes */
	if (!object_add_bool_attr(obj, CKA_TOKEN, &ck_true))
		return 0;
	if (!object_add_bool_attr(obj, CKA_PRIVATE, &ck_false))
		return 0;
	if (!object_add_bool_attr(obj, CKA_MODIFIABLE, &ck_false))
		return 0;
	if (!object_add_bool_attr(obj, CKA_COPYABLE, &ck_false))
		return 0;
	if (!object_add_bool_attr(obj, CKA_DESTROYABLE, &ck_false))
		return 0;
	if (!object_add_attr(obj, CKA_LABEL, (void *)obj->label,
			     strlen(obj->label)))
		return 0;
	snprintf(obj->unique_id, sizeof(obj->unique_id), "%0*lx",
		 (int)(sizeof(object_id_t) * 2),
		 __atomic_add_fetch(&object_id_counter, 1, __ATOMIC_RELAXED));
	if (!object_add_attr(obj, CKA_UNIQUE_ID, obj->unique_id,
			     sizeof(obj->unique_id) - 1))
		return 0;

	/* Key object attributes */
	if (!object_add_ulong_attr(obj, CKA_KEY_TYPE, &obj->keytype))
		return 0;
	if (!object_add_attr(obj, CKA_ID, &obj->id, sizeof(obj->id)))
		return 0;
	if (!object_add_attr(obj, CKA_START_DATE, NULL, 0))
		return 0;
	if (!object_add_attr(obj, CKA_END_DATE, NULL, 0))
		return 0;
	if (!object_add_bool_attr(obj, CKA_LOCAL, &ck_true))
		return 0;
	if (!object_add_bool_attr(obj, CKA_DERIVE, &ck_false))
		return 0;

	if (obj->class == CKO_PUBLIC_KEY &&
	    !object_setup_public_key_default_attrs(obj))
		return 0;
	if (obj->class == CKO_PRIVATE_KEY &&
	    !object_setup_private_key_default_attrs(obj))
		return 0;

	return 1;
}

int object_init(struct pkcs11_object **obj, const char *label, CK_ULONG id,
		CK_OBJECT_CLASS class, CK_KEY_TYPE keytype)
{
	struct pkcs11_object *o;

	if (!obj || !label)
		return 0;

	o = calloc(1, sizeof(*o));
	if (!o)
		return 0;

	o->class = class;

	o->label = strdup(label);
	if (!o->label)
		goto err;

	o->keytype = keytype;
	o->id = id;

	if (object_setup_default_attrs(o) != 1)
		goto err;

	*obj = o;
	return 1;

err:
	object_free(o);
	return 0;
}

static CK_ATTRIBUTE *object_find_attr(struct pkcs11_object *obj,
				      CK_ATTRIBUTE_TYPE type)
{
	CK_ULONG i;

	for (i = 0; i < obj->num_attrs; i++) {
		if (obj->attrs[i].type == type)
			return &obj->attrs[i];
	}

	return NULL;
}

void object_free(struct pkcs11_object *obj)
{
	if (!obj)
		return;

	if (obj->label)
		free((void *)obj->label);

	if (obj->keytype == CKK_EC || obj->keytype == CKK_EC_EDWARDS) {
		if (obj->data.ec_ed.ec_params)
			free(obj->data.ec_ed.ec_params);
		if (obj->data.ec_ed.ec_point)
			free(obj->data.ec_ed.ec_point);
		if (obj->data.ec_ed.spki)
			free(obj->data.ec_ed.spki);
		if (obj->data.ec_ed.pkey)
			EVP_PKEY_free(obj->data.ec_ed.pkey);
	}

	free(obj);
}

int object_list_init(void)
{
	if (!dyn_array_init(&objects))
		return 0;

	return 1;
}

void object_list_term(void)
{
	struct pkcs11_object *obj;
	size_t i;

	for (i = 0; i < dyn_array_size(&objects); i++) {
		if (!dyn_array_get(&objects, i, (void **)&obj))
			break;
		if (obj)
			object_free(obj);
	}

	dyn_array_free(&objects);
}


int object_add_ec_ed_private_key(const char *label, CK_ULONG id,
				 CK_KEY_TYPE keytype,
				 const unsigned char *ec_params,
				 size_t ec_params_len,
				 const unsigned char *spki, size_t spki_len,
				 size_t prime_len,
				 EVP_PKEY *pkey)
{
	struct pkcs11_object *obj = NULL;
	size_t index;

	if (!object_init(&obj, label, id, CKO_PRIVATE_KEY, keytype))
		goto err;

	obj->data.ec_ed.ec_params = memdup(ec_params, ec_params_len);
	obj->data.ec_ed.ec_params_len = ec_params_len;
	if (!obj->data.ec_ed.ec_params)
		goto err;
	obj->data.ec_ed.spki = memdup(spki, spki_len);
	obj->data.ec_ed.spki_len = spki_len;
	if (!obj->data.ec_ed.spki && obj->data.ec_ed.spki_len != 0)
		goto err;
	obj->data.ec_ed.prime_len = prime_len;

	if (!object_add_attr(obj, CKA_EC_PARAMS, obj->data.ec_ed.ec_params,
			     obj->data.ec_ed.ec_params_len))
		goto err;
	if (!object_add_attr(obj, CKA_VALUE, NULL, 0))
		goto err;
	if (!object_add_attr(obj, CKA_PUBLIC_KEY_INFO, obj->data.ec_ed.spki,
			     obj->data.ec_ed.spki_len))
		goto err;

	if (!EVP_PKEY_up_ref(pkey))
		goto err;
	obj->data.ec_ed.pkey = pkey;

	if (!dyn_array_add(&objects, obj, &index))
		goto err;

	obj->handle = index + 1; /* zero handle = invalid */

	return 1;

err:
	object_free(obj);
	return 0;
}

int object_add_ec_ed_public_key(const char *label, CK_ULONG id,
				CK_KEY_TYPE keytype,
				const unsigned char *ec_params,
				size_t ec_params_len,
				const unsigned char *ec_point,
				size_t ec_point_len,
				const unsigned char *spki, size_t spki_len,
				size_t prime_len,
				EVP_PKEY *pkey)
{
	struct pkcs11_object *obj = NULL;
	size_t index;

	if (!object_init(&obj, label, id, CKO_PUBLIC_KEY, keytype))
		goto err;

	obj->data.ec_ed.ec_params = memdup(ec_params, ec_params_len);
	obj->data.ec_ed.ec_params_len = ec_params_len;
	if (!obj->data.ec_ed.ec_params)
		goto err;
	obj->data.ec_ed.ec_point = memdup(ec_point, ec_point_len);
	obj->data.ec_ed.ec_point_len = ec_point_len;
	if (!obj->data.ec_ed.ec_point)
		goto err;
	obj->data.ec_ed.spki = memdup(spki, spki_len);
	obj->data.ec_ed.spki_len = spki_len;
	if (!obj->data.ec_ed.spki && obj->data.ec_ed.spki_len != 0)
		goto err;
	obj->data.ec_ed.prime_len = prime_len;

	if (!object_add_attr(obj, CKA_EC_PARAMS, obj->data.ec_ed.ec_params,
			     obj->data.ec_ed.ec_params_len))
		goto err;
	if (!object_add_attr(obj, CKA_EC_POINT, obj->data.ec_ed.ec_point,
			     obj->data.ec_ed.ec_point_len))
		goto err;
	if (!object_add_attr(obj, CKA_PUBLIC_KEY_INFO, obj->data.ec_ed.spki,
			     obj->data.ec_ed.spki_len))
		goto err;

	if (!EVP_PKEY_up_ref(pkey))
		goto err;
	obj->data.ec_ed.pkey = pkey;

	if (!dyn_array_add(&objects, obj, &index))
		goto err;

	obj->handle = index + 1; /* zero handle = invalid */

	return 1;

err:
	object_free(obj);
	return 0;
}

static int object_match_attrs(CK_ATTRIBUTE *pTemplate, CK_ULONG ulCount,
			      struct pkcs11_object *obj)
{
	CK_ULONG i;
	CK_ATTRIBUTE *attr;

	for (i = 0; i < ulCount; i++) {
		attr = object_find_attr(obj, pTemplate[i].type);
		if (!attr)
			return 0;
		if (attr->ulValueLen != pTemplate[i].ulValueLen)
			return 0;
		if (attr->ulValueLen == 0)
			continue;
		if (!attr->pValue || !pTemplate[i].pValue)
			return 0;
		if (memcmp(attr->pValue, pTemplate[i].pValue,
			   attr->ulValueLen) != 0)
			return 0;
	}

	return 1;
}

int object_list_find(CK_ATTRIBUTE *pTemplate, CK_ULONG ulCount,
		     struct dyn_array *result)
{
	struct pkcs11_object *obj;
	size_t i;

	for (i = 0; i < dyn_array_size(&objects); i++) {
		if (!dyn_array_get(&objects, i, (void **)&obj))
			break;
		if (!obj)
			continue;

		if (!object_match_attrs(pTemplate, ulCount, obj))
			continue;

		if (!dyn_array_add(result, obj, NULL))
			return 0;
	}

	return 1;
}
