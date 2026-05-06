// SPDX-License-Identifier: MIT
// Copyright contributors to the libzpc project
#ifndef SIGNATURE_H
#define SIGNATURE_H

#include "pkcs11.h"
#include "object.h"
#include "session.h"

CK_RV signature_sign_init(struct pkcs11_session *sess,
			  struct pkcs11_object *key,
			  CK_MECHANISM_PTR pMechanism);
CK_RV signature_sign(struct pkcs11_session *sess,
		     CK_BYTE_PTR pData, CK_ULONG ulDataLen,
		     CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen);
CK_RV signature_sign_update(struct pkcs11_session *sess,
			    CK_BYTE_PTR pData, CK_ULONG ulDataLen);
CK_RV signature_sign_final(struct pkcs11_session *sess,
			   CK_BYTE_PTR pSignature,
			   CK_ULONG_PTR pulSignatureLen);
void signature_sign_cleanup(struct pkcs11_session *sess);

CK_RV signature_verify_init(struct pkcs11_session *sess,
			    struct pkcs11_object *key,
			    CK_MECHANISM_PTR pMechanism,
			    CK_BYTE_PTR pSignature,
			    CK_ULONG ulSignatureLen);
CK_RV signature_verify(struct pkcs11_session *sess,
		       CK_BYTE_PTR pData, CK_ULONG ulDataLen,
		       CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen);
CK_RV signature_verify_update(struct pkcs11_session *sess,
			      CK_BYTE_PTR pData, CK_ULONG ulDataLen);
CK_RV signature_verify_final(struct pkcs11_session *sess,
			     CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen);
void signature_verify_cleanup(struct pkcs11_session *sess);

#endif
