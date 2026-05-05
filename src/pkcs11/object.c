// SPDX-License-Identifier: MIT
// Copyright contributors to the libzpc project
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "object.h"

static CK_BBOOL ck_true = CK_TRUE;
static CK_BBOOL ck_false = CK_FALSE;

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

void object_free(struct pkcs11_object *obj)
{
	if (!obj)
		return;

	if (obj->label)
		free((void *)obj->label);

	free(obj);
}
