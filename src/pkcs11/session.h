// SPDX-License-Identifier: MIT
// Copyright contributors to the libzpc project
#ifndef SESSION_H
#define SESSION_H

#include <openssl/evp.h>
#include "pkcs11.h"
#include "utils.h"
#include "object.h"

struct pkcs11_session {
	CK_SESSION_HANDLE handle;
	CK_SESSION_INFO info;

	CK_FLAGS op_active;
	CK_FLAGS op_multi_init;
	CK_FLAGS op_multi;

	struct {
		struct dyn_array found;
		size_t pos;
	} find;
	struct {
		CK_MECHANISM_TYPE mechanism;
		struct pkcs11_object *key;
		EVP_MD_CTX *md_ctx;
		EVP_PKEY_CTX *pkey_ctx;
	} sign;
	struct {
		CK_MECHANISM_TYPE mechanism;
		struct pkcs11_object *key;
		CK_BYTE *signature;
		CK_ULONG signature_len;
		EVP_MD_CTX *md_ctx;
		EVP_PKEY_CTX *pkey_ctx;
	} verify;
};

int session_init(struct pkcs11_session **sess, CK_SLOT_ID slot, CK_FLAGS flags);
CK_RV session_op_init(struct pkcs11_session *sess, CK_FLAGS op_flags);
CK_RV session_op_single(struct pkcs11_session *sess, CK_FLAGS op_flags);
CK_RV session_op_multi(struct pkcs11_session *sess, CK_FLAGS op_flags);
int session_op_cleanup(struct pkcs11_session *sess, CK_FLAGS op_flags);
void session_free(struct pkcs11_session *sess);

int session_list_init(void);
void session_list_term(void);

int session_add_session(CK_SLOT_ID slot, CK_FLAGS flags,
			CK_SESSION_HANDLE *handle);
int session_get_session(CK_SESSION_HANDLE handle, struct pkcs11_session **sess);
int session_remove_session(CK_SESSION_HANDLE handle);
int session_remove_all(void);

void session_set_login_state(CK_BBOOL login);
CK_BBOOL session_get_login_state(void);
int session_get_counts(CK_ULONG *count, CK_ULONG *rw_count);

#endif
