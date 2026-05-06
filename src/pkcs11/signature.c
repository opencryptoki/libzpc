// SPDX-License-Identifier: MIT
// Copyright contributors to the libzpc project
#include <stddef.h>
#include <openssl/obj_mac.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include "signature.h"
#include "openssl.h"

static CK_RV signature_check_operation(CK_FLAGS op, struct pkcs11_object *key)
{
	switch (op) {
	case CKF_SIGN:
		if (key->class != CKO_PRIVATE_KEY)
			return CKR_KEY_FUNCTION_NOT_PERMITTED;
		break;

	case CKF_VERIFY:
		if (key->class != CKO_PUBLIC_KEY)
			return CKR_KEY_FUNCTION_NOT_PERMITTED;
		break;

	default:
		return CKR_MECHANISM_INVALID;
	}

	return CKR_OK;
}

static CK_RV signature_check_mechanism(CK_MECHANISM *mech,
				       struct pkcs11_object *key,
				       CK_FLAGS op)
{
	CK_EDDSA_PARAMS *eddsa_param;

	switch (mech->mechanism) {
	case CKM_ECDSA:
	case CKM_ECDSA_SHA1:
	case CKM_ECDSA_SHA224:
	case CKM_ECDSA_SHA256:
	case CKM_ECDSA_SHA384:
	case CKM_ECDSA_SHA512:
	case CKM_ECDSA_SHA3_224:
	case CKM_ECDSA_SHA3_256:
	case CKM_ECDSA_SHA3_384:
	case CKM_ECDSA_SHA3_512:
		if (mech->pParameter || mech->ulParameterLen != 0)
			return CKR_MECHANISM_PARAM_INVALID;

		if (key->keytype != CKK_EC)
			return CKR_KEY_TYPE_INCONSISTENT;

		return signature_check_operation(op, key);

	case CKM_EDDSA:
		if (mech->pParameter &&
		    mech->ulParameterLen != sizeof(CK_EDDSA_PARAMS))
			return CKR_MECHANISM_PARAM_INVALID;
		if (!mech->pParameter && mech->ulParameterLen != 0)
			return CKR_MECHANISM_PARAM_INVALID;

		eddsa_param = mech->pParameter;
		if (eddsa_param) {
			if (eddsa_param->phFlag == CK_TRUE) {
				fprintf(stderr,
					"zpcpkcs11: EDDSA with pre-hash is not supported\n");
				return CKR_MECHANISM_PARAM_INVALID;
			}
			if (eddsa_param->ulContextDataLen != 0) {
				fprintf(stderr,
					"zpcpkcs11: EDDSA with non-empty context is not supported\n");
				return CKR_MECHANISM_PARAM_INVALID;
			}
		}

		if (key->keytype != CKK_EC_EDWARDS)
			return CKR_KEY_TYPE_INCONSISTENT;

		return signature_check_operation(op, key);

	default:
		return CKR_MECHANISM_INVALID;
	}

	return CKR_OK;
}

static const char *signature_get_mdname_for_mech(CK_MECHANISM_TYPE mech)
{
	switch(mech) {
	case CKM_ECDSA_SHA1:
		return OBJ_nid2sn(NID_sha1);
	case CKM_ECDSA_SHA224:
		return OBJ_nid2sn(NID_sha224);
	case CKM_ECDSA_SHA256:
		return OBJ_nid2sn(NID_sha256);
	case CKM_ECDSA_SHA384:
		return OBJ_nid2sn(NID_sha384);
	case CKM_ECDSA_SHA512:
		return OBJ_nid2sn(NID_sha512);
	case CKM_ECDSA_SHA3_224:
		return OBJ_nid2sn(NID_sha3_224);
	case CKM_ECDSA_SHA3_256:
		return OBJ_nid2sn(NID_sha3_256);
	case CKM_ECDSA_SHA3_384:
		return OBJ_nid2sn(NID_sha3_384);
	case CKM_ECDSA_SHA3_512:
		return OBJ_nid2sn(NID_sha3_512);
	default:
		return NULL;
	}
}

static EVP_MD_CTX *signature_get_digest_context(EVP_PKEY *pkey,
						CK_MECHANISM_TYPE mech,
						CK_FLAGS op)
{
	const char *mdname;

	mdname = signature_get_mdname_for_mech(mech);
	if (!mdname && mech != CKM_EDDSA)
		return NULL;

	switch (op) {
	case CKF_SIGN:
		return openssl_get_digest_sign_context(pkey, mdname);
	case CKF_VERIFY:
		return openssl_get_digest_verify_context(pkey, mdname);
	default:
		return NULL;
	}
}

static CK_RV signature_decode_ec_signature(size_t prime_len,
					   const unsigned char *enc_sig,
					   size_t enc_sig_len,
					   unsigned char **raw_sig,
					   size_t *raw_sig_len)
{
	ECDSA_SIG *sig = NULL;
	const BIGNUM *r, *s;
	CK_RV rc = CKR_OK;

	if (!enc_sig) {
		*raw_sig_len = 2 * prime_len;
		if (raw_sig)
			*raw_sig = NULL;
		return CKR_OK;
	}

	sig = d2i_ECDSA_SIG(NULL, &enc_sig, enc_sig_len);
	if (!sig) {
		rc = CKR_FUNCTION_FAILED;
		goto out;
	}

	ECDSA_SIG_get0(sig, &r, &s);

	*raw_sig_len = 2 * prime_len;
	*raw_sig = calloc(1, *raw_sig_len);
	if (!*raw_sig) {
		rc = CKR_HOST_MEMORY;
		goto out;
	}

	if (BN_bn2binpad(r, *raw_sig, prime_len) <= 0 ||
	    BN_bn2binpad(s, (*raw_sig) + prime_len, prime_len) <= 0) {
		rc = CKR_FUNCTION_FAILED;
		goto out;
	}

out:
	if (sig)
		ECDSA_SIG_free(sig);
	if (rc != CKR_OK && *raw_sig) {
		free(*raw_sig);
		*raw_sig = NULL;
		*raw_sig_len = 0;
	}

	return rc;
}

static CK_RV signature_encode_ec_signature(size_t prime_len,
					   const unsigned char *raw_sig,
					   size_t raw_sig_len,
					   unsigned char **enc_sig,
					   size_t *enc_sig_len)
{
	ECDSA_SIG *sig = NULL;
	BIGNUM *r = NULL, *s = NULL;
	CK_RV rc = CKR_OK;
	int len;

	if (raw_sig_len != 2 * prime_len)
		return CKR_SIGNATURE_LEN_RANGE;

	sig = ECDSA_SIG_new();
	if (!sig) {
		rc = CKR_HOST_MEMORY;
		goto out;
	}

	r = BN_bin2bn(raw_sig, prime_len, NULL);
	s = BN_bin2bn(raw_sig + prime_len, prime_len, NULL);
	if (!r || !s) {
		rc = CKR_FUNCTION_FAILED;
		goto out;
	}

	if (!ECDSA_SIG_set0(sig, r, s)) {
		rc = CKR_FUNCTION_FAILED;
		goto out;
	}
	r = NULL;
	s = NULL;

	*enc_sig = NULL;
	*enc_sig_len = 0;

	len = i2d_ECDSA_SIG(sig, enc_sig);
	if (len <= 0) {
		rc = CKR_FUNCTION_FAILED;
		goto out;
	}
	*enc_sig_len = len;

out:
	if (sig)
		ECDSA_SIG_free(sig);
	if (r)
		BN_free(r);
	if (s)
		BN_free(s);

	return rc;
}

static CK_RV signature_sign_verify_init_ctxs(struct pkcs11_object *key,
					     CK_MECHANISM_PTR pMechanism,
					     CK_FLAGS op,
					     EVP_PKEY_CTX **pkey_ctx,
					     EVP_MD_CTX **md_ctx)
{
	switch (pMechanism->mechanism) {
	case CKM_ECDSA:
		*md_ctx = NULL;
		*pkey_ctx = openssl_get_pkey_context(key->data.ec_ed.pkey);
		if (!*pkey_ctx)
			return CKR_FUNCTION_FAILED;

		switch (op) {
		case CKF_SIGN:
			if (EVP_PKEY_sign_init(*pkey_ctx) != 1) {
				fprintf(stderr,
					"zpcpkcs11: EVP_PKEY_sign_init failed\n");
				ERR_print_errors_fp(stderr);
				EVP_PKEY_CTX_free(*pkey_ctx);
				*pkey_ctx = NULL;
				return CKR_FUNCTION_FAILED;
			}
			break;
		case CKF_VERIFY:
			if (EVP_PKEY_verify_init(*pkey_ctx) != 1) {
				fprintf(stderr,
					"zpcpkcs11: EVP_PKEY_verify_init failed\n");
				ERR_print_errors_fp(stderr);
				EVP_PKEY_CTX_free(*pkey_ctx);
				*pkey_ctx = NULL;
				return CKR_FUNCTION_FAILED;
			}
			break;
		default:
			return CKR_MECHANISM_INVALID;
		}
		break;

	case CKM_ECDSA_SHA1:
	case CKM_ECDSA_SHA224:
	case CKM_ECDSA_SHA256:
	case CKM_ECDSA_SHA384:
	case CKM_ECDSA_SHA512:
	case CKM_ECDSA_SHA3_224:
	case CKM_ECDSA_SHA3_256:
	case CKM_ECDSA_SHA3_384:
	case CKM_ECDSA_SHA3_512:
	case CKM_EDDSA:
		*pkey_ctx = NULL;
		*md_ctx = signature_get_digest_context(key->data.ec_ed.pkey,
						       pMechanism->mechanism,
						       op);
		if (!*md_ctx)
			return CKR_FUNCTION_FAILED;
		break;

	default:
		return CKR_MECHANISM_INVALID;
	}

	return CKR_OK;
}

CK_RV signature_sign_init(struct pkcs11_session *sess,
			  struct pkcs11_object *key,
			  CK_MECHANISM_PTR pMechanism)
{
	CK_RV rc;

	if (!sess || !key || !pMechanism)
		return CKR_ARGUMENTS_BAD;

	rc = signature_check_mechanism(pMechanism, key, CKF_SIGN);
	if (rc != CKR_OK)
		return rc;

	rc = signature_sign_verify_init_ctxs(key, pMechanism, CKF_SIGN,
					     &sess->sign.pkey_ctx,
					     &sess->sign.md_ctx);
	if (rc != CKR_OK)
		return rc;

	sess->sign.mechanism = pMechanism->mechanism;
	sess->sign.key = key;

	return CKR_OK;
}

static CK_RV signature_query_pkcs11_len(CK_BBOOL encoded, size_t prime_len,
					size_t ossl_siglen, size_t *pkcs11_len)
{
	if (encoded)
		return signature_decode_ec_signature(prime_len, NULL,
						     ossl_siglen, NULL,
						     pkcs11_len);
	*pkcs11_len = ossl_siglen;
	return CKR_OK;
}

static CK_RV signature_sign_produce_pkey(EVP_PKEY_CTX *ctx,
					 const unsigned char *data,
					 size_t datalen,
					 size_t ossl_siglen,
					 unsigned char **sig_out,
					 size_t *siglen_out)
{
	unsigned char *sig;

	sig = calloc(1, ossl_siglen);
	if (!sig)
		return CKR_HOST_MEMORY;

	*siglen_out = ossl_siglen;
	if (EVP_PKEY_sign(ctx, sig, siglen_out, data, datalen) != 1) {
		fprintf(stderr, "zpcpkcs11: EVP_PKEY_sign failed\n");
		ERR_print_errors_fp(stderr);
		free(sig);
		return CKR_FUNCTION_FAILED;
	}

	*sig_out = sig;
	return CKR_OK;
}

/*
 * Allocate a buffer of ossl_siglen bytes, produce the signature with
 * EVP_DigestSign, and hand ownership of the buffer to the caller.
 * The size query has already been done by the caller; ossl_siglen is its result.
 */
static CK_RV signature_sign_produce_digest(EVP_MD_CTX *ctx,
					   const unsigned char *data,
					   size_t datalen,
					   size_t ossl_siglen,
					   unsigned char **sig_out,
					   size_t *siglen_out)
{
	unsigned char *sig;

	sig = calloc(1, ossl_siglen);
	if (!sig)
		return CKR_HOST_MEMORY;

	*siglen_out = ossl_siglen;
	if (EVP_DigestSign(ctx, sig, siglen_out, data, datalen) != 1) {
		fprintf(stderr, "zpcpkcs11: EVP_DigestSign failed\n");
		ERR_print_errors_fp(stderr);
		free(sig);
		return CKR_FUNCTION_FAILED;
	}

	*sig_out = sig;
	return CKR_OK;
}

static CK_RV signature_sign_produce_digest_final(EVP_MD_CTX *ctx,
						 size_t ossl_siglen,
						 unsigned char **sig_out,
						 size_t *siglen_out)
{
	unsigned char *sig;

	sig = calloc(1, ossl_siglen);
	if (!sig)
		return CKR_HOST_MEMORY;

	*siglen_out = ossl_siglen;
	if (EVP_DigestSignFinal(ctx, sig, siglen_out) != 1) {
		fprintf(stderr, "zpcpkcs11: EVP_DigestSignFinal failed\n");
		ERR_print_errors_fp(stderr);
		free(sig);
		return CKR_FUNCTION_FAILED;
	}

	*sig_out = sig;
	return CKR_OK;
}

static CK_RV signature_sign_finish(CK_BBOOL encoded, size_t prime_len,
				   unsigned char *ossl_sig, size_t ossl_siglen,
				   CK_BYTE_PTR pSignature,
				   CK_ULONG_PTR pulSignatureLen)
{
	unsigned char *sig = ossl_sig;
	size_t siglen = ossl_siglen;
	unsigned char *raw_sig = NULL;
	size_t raw_siglen = 0;
	CK_RV rc = CKR_OK;

	if (encoded) {
		rc = signature_decode_ec_signature(prime_len, ossl_sig,
						   ossl_siglen,
						   &raw_sig, &raw_siglen);
		free(ossl_sig);
		if (rc != CKR_OK)
			return rc;
		sig = raw_sig;
		siglen = raw_siglen;
	}

	if (!pSignature) {
		*pulSignatureLen = siglen;
	} else if (*pulSignatureLen < siglen) {
		rc = CKR_BUFFER_TOO_SMALL;
		*pulSignatureLen = siglen;
	} else {
		memcpy(pSignature, sig, siglen);
		*pulSignatureLen = siglen;
	}

	free(sig);
	return rc;
}

CK_RV signature_sign(struct pkcs11_session *sess,
		     CK_BYTE_PTR pData, CK_ULONG ulDataLen,
		     CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	CK_BBOOL encoded_signature = CK_TRUE;
	size_t ossl_siglen = 0, pkcs11_len = 0, prime_len = 0;
	unsigned char *ossl_sig = NULL;
	CK_RV rc;

	switch (sess->sign.mechanism) {
	case CKM_ECDSA:
		encoded_signature = CK_TRUE;
		prime_len = sess->sign.key->data.ec_ed.prime_len;

		if (EVP_PKEY_sign(sess->sign.pkey_ctx, NULL, &ossl_siglen,
				  pData, ulDataLen) != 1) {
			fprintf(stderr, "zpcpkcs11: EVP_PKEY_sign failed\n");
			ERR_print_errors_fp(stderr);
			return CKR_FUNCTION_FAILED;
		}

		rc = signature_query_pkcs11_len(encoded_signature, prime_len,
						ossl_siglen, &pkcs11_len);
		if (rc != CKR_OK)
			return rc;

		/*
		 * Stop here for a size query or too-small buffer - calling
		 * EVP_PKEY_sign to produce the signature would consume the
		 * context and prevent a retry on the next call.
		 */
		if (!pSignature || *pulSignatureLen < pkcs11_len) {
			*pulSignatureLen = pkcs11_len;
			return (!pSignature) ?
					CKR_OK : CKR_BUFFER_TOO_SMALL;
		}

		rc = signature_sign_produce_pkey(sess->sign.pkey_ctx,
						 pData, ulDataLen, ossl_siglen,
						 &ossl_sig, &ossl_siglen);
		break;

	case CKM_EDDSA:
		encoded_signature = CK_FALSE;
		/* Fall through */
	case CKM_ECDSA_SHA1:
	case CKM_ECDSA_SHA224:
	case CKM_ECDSA_SHA256:
	case CKM_ECDSA_SHA384:
	case CKM_ECDSA_SHA512:
	case CKM_ECDSA_SHA3_224:
	case CKM_ECDSA_SHA3_256:
	case CKM_ECDSA_SHA3_384:
	case CKM_ECDSA_SHA3_512:
		prime_len = sess->sign.key->data.ec_ed.prime_len;

		if (EVP_DigestSign(sess->sign.md_ctx, NULL, &ossl_siglen,
				   pData, ulDataLen) != 1) {
			fprintf(stderr, "zpcpkcs11: EVP_DigestSign failed\n");
			ERR_print_errors_fp(stderr);
			return CKR_FUNCTION_FAILED;
		}

		rc = signature_query_pkcs11_len(encoded_signature, prime_len,
						ossl_siglen, &pkcs11_len);
		if (rc != CKR_OK)
			return rc;

		/*
		 * Stop here for a size query or too-small buffer - calling
		 * EVP_DigestSign to produce the signature would consume the
		 * context and prevent a retry on the next call.
		 */
		if (!pSignature || *pulSignatureLen < pkcs11_len) {
			*pulSignatureLen = pkcs11_len;
			return (!pSignature) ?
					CKR_OK : CKR_BUFFER_TOO_SMALL;
		}

		rc = signature_sign_produce_digest(sess->sign.md_ctx,
						   pData, ulDataLen,
						   ossl_siglen,
						   &ossl_sig, &ossl_siglen);
		break;

	default:
		return CKR_MECHANISM_INVALID;
	}

	if (rc != CKR_OK)
		return rc;

	return signature_sign_finish(encoded_signature, prime_len,
				     ossl_sig, ossl_siglen,
				     pSignature, pulSignatureLen);
}

CK_RV signature_sign_update(struct pkcs11_session *sess,
			    CK_BYTE_PTR pData, CK_ULONG ulDataLen)
{
	switch (sess->sign.mechanism) {
	case CKM_ECDSA_SHA1:
	case CKM_ECDSA_SHA224:
	case CKM_ECDSA_SHA256:
	case CKM_ECDSA_SHA384:
	case CKM_ECDSA_SHA512:
	case CKM_ECDSA_SHA3_224:
	case CKM_ECDSA_SHA3_256:
	case CKM_ECDSA_SHA3_384:
	case CKM_ECDSA_SHA3_512:
		if (EVP_DigestSignUpdate(sess->sign.md_ctx,
					 pData, ulDataLen) != 1) {
			fprintf(stderr,
				"zpcpkcs11: EVP_DigestSignUpdate failed\n");
			ERR_print_errors_fp(stderr);
			return CKR_FUNCTION_FAILED;
		}
		break;

	/* CKM_ECDSA and CKM_EDDSA do not support multi-part operations. */
	default:
		return CKR_MECHANISM_INVALID;
	}

	return CKR_OK;
}

CK_RV signature_sign_final(struct pkcs11_session *sess,
			   CK_BYTE_PTR pSignature,
			   CK_ULONG_PTR pulSignatureLen)
{
	CK_BBOOL encoded_signature = CK_TRUE;
	size_t ossl_siglen = 0, pkcs11_len = 0, prime_len = 0;
	unsigned char *ossl_sig = NULL;
	CK_RV rc;

	switch (sess->sign.mechanism) {
	case CKM_ECDSA_SHA1:
	case CKM_ECDSA_SHA224:
	case CKM_ECDSA_SHA256:
	case CKM_ECDSA_SHA384:
	case CKM_ECDSA_SHA512:
	case CKM_ECDSA_SHA3_224:
	case CKM_ECDSA_SHA3_256:
	case CKM_ECDSA_SHA3_384:
	case CKM_ECDSA_SHA3_512:
		encoded_signature = CK_TRUE;
		prime_len = sess->sign.key->data.ec_ed.prime_len;

		if (EVP_DigestSignFinal(sess->sign.md_ctx, NULL,
					&ossl_siglen) != 1) {
			fprintf(stderr,
				"zpcpkcs11: EVP_DigestSignFinal failed\n");
			ERR_print_errors_fp(stderr);
			return CKR_FUNCTION_FAILED;
		}

		rc = signature_query_pkcs11_len(encoded_signature, prime_len,
						ossl_siglen, &pkcs11_len);
		if (rc != CKR_OK)
			return rc;

		/*
		 * Stop here for a size query or too-small buffer - calling
		 * EVP_DigestSignFinal to produce the signature would consume
		 * the context and prevent a retry on the next call.
		 */
		if (!pSignature || *pulSignatureLen < pkcs11_len) {
			*pulSignatureLen = pkcs11_len;
			return (!pSignature) ?
					CKR_OK : CKR_BUFFER_TOO_SMALL;
		}

		rc = signature_sign_produce_digest_final(sess->sign.md_ctx,
							 ossl_siglen,
							 &ossl_sig,
							 &ossl_siglen);
		break;

	/* CKM_ECDSA and CKM_EDDSA do not support multi-part operations. */
	default:
		return CKR_MECHANISM_INVALID;
	}

	if (rc != CKR_OK)
		return rc;

	return signature_sign_finish(encoded_signature, prime_len,
				     ossl_sig, ossl_siglen,
				     pSignature, pulSignatureLen);
}

void signature_sign_cleanup(struct pkcs11_session *sess)
{
	if (!sess)
		return;

	if (sess->sign.pkey_ctx)
		EVP_PKEY_CTX_free(sess->sign.pkey_ctx);
	if (sess->sign.md_ctx)
		EVP_MD_CTX_free(sess->sign.md_ctx);

	sess->sign.key = NULL;
	sess->sign.mechanism = 0;
	sess->sign.pkey_ctx = NULL;
	sess->sign.md_ctx = NULL;
}

CK_RV signature_verify_init(struct pkcs11_session *sess,
			    struct pkcs11_object *key,
			    CK_MECHANISM_PTR pMechanism,
			    CK_BYTE_PTR pSignature,
			    CK_ULONG ulSignatureLen)
{
	CK_RV rc;

	if (!sess || !key || !pMechanism)
		return CKR_ARGUMENTS_BAD;

	rc = signature_check_mechanism(pMechanism, key, CKF_VERIFY);
	if (rc != CKR_OK)
		return rc;

	rc = signature_sign_verify_init_ctxs(key, pMechanism, CKF_VERIFY,
					     &sess->verify.pkey_ctx,
					     &sess->verify.md_ctx);
	if (rc != CKR_OK)
		return rc;

	sess->verify.signature = memdup(pSignature, ulSignatureLen);
	if (!sess->verify.signature && ulSignatureLen != 0) {
		signature_verify_cleanup(sess);
		return CKR_HOST_MEMORY;
	}
	sess->verify.signature_len = ulSignatureLen;

	sess->verify.mechanism = pMechanism->mechanism;
	sess->verify.key = key;

	return CKR_OK;
}

static CK_RV signature_verify_prepare_sig(CK_BBOOL encoded, size_t prime_len,
					  CK_BYTE_PTR pSignature,
					  CK_ULONG ulSignatureLen,
					  unsigned char **ossl_sig,
					  size_t *ossl_siglen)
{
	if (!encoded) {
		*ossl_sig = pSignature;
		*ossl_siglen = ulSignatureLen;
		return CKR_OK;
	}

	*ossl_sig = NULL;
	*ossl_siglen = 0;
	return signature_encode_ec_signature(prime_len,
					     pSignature, ulSignatureLen,
					     ossl_sig, ossl_siglen);
}

static CK_RV signature_verify_translate_ret(int ret, const char *fn_name)
{
	if (ret == 1)
		return CKR_OK;
	if (ret == 0)
		return CKR_SIGNATURE_INVALID;

	fprintf(stderr, "zpcpkcs11: %s failed\n", fn_name);
	ERR_print_errors_fp(stderr);
	return CKR_FUNCTION_FAILED;
}

CK_RV signature_verify(struct pkcs11_session *sess,
		       CK_BYTE_PTR pData, CK_ULONG ulDataLen,
		       CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
	CK_BBOOL encoded_signature = CK_TRUE;
	size_t prime_len, ossl_siglen = 0;
	unsigned char *ossl_sig = NULL;
	int ret;
	CK_RV rc;

	switch (sess->verify.mechanism) {
	case CKM_EDDSA:
		encoded_signature = CK_FALSE;
		break;
	}

	prime_len = sess->verify.key->data.ec_ed.prime_len;

	rc = signature_verify_prepare_sig(encoded_signature, prime_len,
					  pSignature, ulSignatureLen,
					  &ossl_sig, &ossl_siglen);
	if (rc != CKR_OK)
		return rc;

	switch (sess->verify.mechanism) {
	case CKM_ECDSA:
		ret = EVP_PKEY_verify(sess->verify.pkey_ctx, ossl_sig,
				      ossl_siglen, pData, ulDataLen);
		rc = signature_verify_translate_ret(ret, "EVP_PKEY_verify");
		break;

	case CKM_EDDSA:
	case CKM_ECDSA_SHA1:
	case CKM_ECDSA_SHA224:
	case CKM_ECDSA_SHA256:
	case CKM_ECDSA_SHA384:
	case CKM_ECDSA_SHA512:
	case CKM_ECDSA_SHA3_224:
	case CKM_ECDSA_SHA3_256:
	case CKM_ECDSA_SHA3_384:
	case CKM_ECDSA_SHA3_512:
		ret = EVP_DigestVerify(sess->verify.md_ctx, ossl_sig,
				       ossl_siglen, pData, ulDataLen);
		rc = signature_verify_translate_ret(ret, "EVP_DigestVerify");
		break;

	default:
		rc = CKR_MECHANISM_INVALID;
		break;
	}

	if (encoded_signature && ossl_sig)
		OPENSSL_free(ossl_sig);

	return rc;
}

CK_RV signature_verify_update(struct pkcs11_session *sess,
			      CK_BYTE_PTR pData, CK_ULONG ulDataLen)
{
	switch (sess->verify.mechanism) {
	case CKM_ECDSA_SHA1:
	case CKM_ECDSA_SHA224:
	case CKM_ECDSA_SHA256:
	case CKM_ECDSA_SHA384:
	case CKM_ECDSA_SHA512:
	case CKM_ECDSA_SHA3_224:
	case CKM_ECDSA_SHA3_256:
	case CKM_ECDSA_SHA3_384:
	case CKM_ECDSA_SHA3_512:
		if (EVP_DigestVerifyUpdate(sess->verify.md_ctx,
					   pData, ulDataLen) != 1) {
			fprintf(stderr,
				"zpcpkcs11: EVP_DigestVerifyUpdate failed\n");
			ERR_print_errors_fp(stderr);
			return CKR_FUNCTION_FAILED;
		}
		break;

	/* CKM_ECDSA and CKM_EDDSA do not support multi-part operations. */
	default:
		return CKR_MECHANISM_INVALID;
	}

	return CKR_OK;
}

CK_RV signature_verify_final(struct pkcs11_session *sess,
			     CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
	CK_BBOOL encoded_signature = (sess->verify.mechanism != CKM_EDDSA);
	size_t prime_len = sess->verify.key->data.ec_ed.prime_len;
	unsigned char *ossl_sig = NULL;
	size_t ossl_siglen = 0;
	int ret;
	CK_RV rc;

	rc = signature_verify_prepare_sig(encoded_signature, prime_len,
				pSignature, ulSignatureLen,
				&ossl_sig, &ossl_siglen);
	if (rc != CKR_OK)
		return rc;

	switch (sess->verify.mechanism) {
	case CKM_ECDSA_SHA1:
	case CKM_ECDSA_SHA224:
	case CKM_ECDSA_SHA256:
	case CKM_ECDSA_SHA384:
	case CKM_ECDSA_SHA512:
	case CKM_ECDSA_SHA3_224:
	case CKM_ECDSA_SHA3_256:
	case CKM_ECDSA_SHA3_384:
	case CKM_ECDSA_SHA3_512:
		ret = EVP_DigestVerifyFinal(sess->verify.md_ctx,
					    ossl_sig, ossl_siglen);
		rc = signature_verify_translate_ret(ret,
						    "EVP_DigestVerifyFinal");
		break;

	/* CKM_ECDSA and CKM_EDDSA do not support multi-part operations. */
	default:
		rc = CKR_MECHANISM_INVALID;
		break;
	}

	if (encoded_signature && ossl_sig)
		OPENSSL_free(ossl_sig);

	return rc;
}

void signature_verify_cleanup(struct pkcs11_session *sess)
{
	if (!sess)
		return;

	if (sess->verify.pkey_ctx)
		EVP_PKEY_CTX_free(sess->verify.pkey_ctx);
	if (sess->verify.md_ctx)
		EVP_MD_CTX_free(sess->verify.md_ctx);

	sess->verify.key = NULL;
	sess->verify.mechanism = 0;
	sess->verify.pkey_ctx = NULL;
	sess->verify.md_ctx = NULL;

	if (sess->verify.signature)
		free(sess->verify.signature);
	sess->verify.signature = NULL;
	sess->verify.signature_len = 0;
}
