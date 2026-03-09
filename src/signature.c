// SPDX-License-Identifier: MIT
// Copyright contributors to the libzpc project
#include <stdbool.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/x509.h>

#include "provider.h"
#include "signature.h"
#include "object.h"
#include "ossl.h"
#include "map.h"
#include "algid.h"
#include "zpc/ecdsa_ctx.h"

/* REVISIT deterministic nonce support (OSSL_SIGNATURE_PARAM_NONCE_TYPE) */

#define ASN1_SIG_HDR	8
#define MAX_RAW_SIGSZ	256

typedef int (*set_ctx_params_fn)(void *, const OSSL_PARAM *);

enum sig_op {
	SIG_OP_UNDEF = 0,
	SIG_OP_SIGN,
	SIG_OP_VERIFY,
};

enum sig_fmt {
	SIG_FMT_UNDEF = 0,
	SIG_FMT_RAW,
	SIG_FMT_DER,
};

static const int ecdsa_curves[] = {
	ZPC_EC_CURVE_P256,
	ZPC_EC_CURVE_P384,
	ZPC_EC_CURVE_P521,
};

static const int ed25519_curves[] = {
	ZPC_EC_CURVE_ED25519,
};

static const int ed448_curves[] = {
	ZPC_EC_CURVE_ED448,
};

/* supported instance strings */
static const char *ed25519 = "Ed25519";
static const char *ed448 = "Ed448";
static const unsigned char *edctx = { 0 };

struct sig_ctx {
	struct provider_ctx *pctx;
	char *propq;

	EVP_MD_CTX *fwd_md_ctx;
	struct zpc_ecdsa_ctx *zpc_ctx;

	struct obj *obj;
	enum sig_op op;
	enum sig_fmt fmt;

	const int *curves;
	size_t curves_len;

	set_ctx_params_fn set_ctx_params;

	const char *ed_instance;
	const unsigned char *ed_ctx;
	size_t ed_ctxlen;
};

static bool valid_curve(int curve, const int *curves, size_t curves_len)
{
	for (size_t i = 0; i < curves_len; i++)
		if (curve == curves[i])
			return true;

	return false;
}

static int raw2der(const unsigned char *raw, size_t rawlen,
		   unsigned char *der, size_t *derlen)
{
	BIGNUM *r = NULL, *s = NULL;
	ECDSA_SIG *ec_sig = NULL;
	int rv = OSSL_RV_ERR;
	size_t _derlen;

	if (!raw || !rawlen || !derlen ||
	    (*derlen < (rawlen + ASN1_SIG_HDR)))
		goto out;

	ec_sig = ECDSA_SIG_new();
	if (!ec_sig)
		goto out;

	if (!(r = BN_bin2bn(raw, rawlen / 2, NULL)) ||
	    !(s = BN_bin2bn(raw + rawlen / 2, rawlen / 2, NULL)) ||
	    ECDSA_SIG_set0(ec_sig, r, s) != OSSL_RV_OK) {
		BN_clear_free(r);
		BN_clear_free(s);
		goto out;
	}

	_derlen = i2d_ECDSA_SIG(ec_sig, &der);
	if (_derlen <= 0)
		goto out;

	*derlen = _derlen;
	rv = OSSL_RV_OK;
out:
	ECDSA_SIG_free(ec_sig);
	return rv;
}

static int der2raw(const unsigned char *der, size_t derlen,
		   unsigned char *raw, size_t *rawlen)
{
	ECDSA_SIG *ec_sig = NULL;
	int rv = OSSL_RV_ERR;
	const BIGNUM *r, *s;
	size_t _rawlen;

	if (!der || !derlen || !rawlen)
		goto out;
	_rawlen = *rawlen;

	ec_sig = d2i_ECDSA_SIG(NULL, &der, derlen);
	if (!ec_sig)
		goto out;

	r = ECDSA_SIG_get0_r(ec_sig);
	s = ECDSA_SIG_get0_s(ec_sig);
	if (!r || !s)
		goto out;

	if ((BN_bn2binpad(r, raw, _rawlen / 2) == -1) ||
	    (BN_bn2binpad(s, raw + _rawlen / 2, _rawlen / 2) == -1))
		goto out;

	rv = OSSL_RV_OK;
out:
	ECDSA_SIG_free(ec_sig);
	return rv;
}

static struct sig_ctx *sig_newctx(struct provider_ctx *pctx, const char *propq,
				  const int *curves, size_t curves_len,
				  enum sig_fmt fmt, set_ctx_params_fn set_ctx_params,
				  const char *ed_instance,
				  const unsigned char *ed_ctx, size_t ed_ctxlen)
{
	struct zpc_ecdsa_ctx *zpc_ctx = NULL;
	struct sig_ctx *sctx = NULL;
	char *pq = NULL;
	int rc;

	if (!pctx || fmt == SIG_FMT_UNDEF)
		goto err;

	rc = zpc_ecdsa_ctx_alloc(&zpc_ctx);
	if (rc) {
		PROV_ERR_raise(pctx, rc);
		goto err;
	}

	sctx = OPENSSL_zalloc(sizeof(struct sig_ctx));
	if (!sctx)
		goto err;

	if (propq &&
	    !(pq = OPENSSL_strdup(propq)))
		goto err;

	sctx->pctx = pctx;
	sctx->zpc_ctx = zpc_ctx;
	sctx->propq = pq;
	sctx->curves = curves;
	sctx->curves_len = curves_len;
	sctx->fmt = fmt;
	sctx->set_ctx_params = set_ctx_params;
	sctx->ed_instance = ed_instance;
	sctx->ed_ctx = ed_ctx;
	sctx->ed_ctxlen = ed_ctxlen;

	return sctx;
err:
	OPENSSL_free(sctx);
	zpc_ecdsa_ctx_free(&zpc_ctx);
	return NULL;
}

static int sig_sctx_set_md(struct sig_ctx *sctx, const char *mdname,
			   const OSSL_PARAM params[])
{
	EVP_MD_CTX *md_ctx = NULL;
	EVP_MD *md = NULL;

	if (!sctx)
		return OSSL_RV_ERR;

	if (mdname) {
		if (!(md = EVP_MD_fetch(sctx->pctx->libctx, mdname, PROV_PROP_FWD)) ||
		    !(md_ctx = EVP_MD_CTX_new()) ||
		    (EVP_DigestInit_ex2(md_ctx, md, params) != OSSL_RV_OK)) {
			EVP_MD_free(md);
			EVP_MD_CTX_free(md_ctx);
			return OSSL_RV_ERR;
		}
	}

	EVP_MD_CTX_free(sctx->fwd_md_ctx);
	sctx->fwd_md_ctx = md_ctx;

	EVP_MD_free(md);
	return OSSL_RV_OK;
}

static int sig_init(struct sig_ctx *sctx, struct obj *obj,
		    const OSSL_PARAM params[],
		    enum sig_op op)
{
	int rc;

	if (!sctx)
		return OSSL_RV_ERR;

	if (obj) {
		if (!valid_curve(obj_key_curve(obj),
				 sctx->curves, sctx->curves_len))
			return OSSL_RV_ERR;

		if ((rc = zpc_ecdsa_ctx_set_key(sctx->zpc_ctx, obj->ec_key))) {
			PROV_ERR_raise(sctx->pctx, rc);
			return OSSL_RV_ERR;
		}
	}

	obj_free(sctx->obj);
	sctx->obj = obj_get(obj);

	sctx->op = op;

	return sctx->set_ctx_params ?
		sctx->set_ctx_params(sctx, params) :
		OSSL_RV_OK;
}

static int sig_digest_init(struct sig_ctx *sctx, const char *mdname,
			   struct obj *obj, const OSSL_PARAM params[],
			   enum sig_op op)
{
	int rv;

	if (!sctx)
		return OSSL_RV_ERR;

	rv = sctx->fwd_md_ctx ?
		EVP_MD_CTX_reset(sctx->fwd_md_ctx) :
		sig_sctx_set_md(sctx, mdname, params);
	if (rv != OSSL_RV_OK)
		return rv;

	return sig_init(sctx, obj, params, op);
}

static int sig_sign_raw(struct sig_ctx *sctx,
			unsigned char *sig, size_t *siglen, size_t sigsize,
			const unsigned char *tbs, size_t tbslen)
{
	int rc;

	*siglen = sigsize;
	if ((rc = zpc_ecdsa_sign(sctx->zpc_ctx, tbs, tbslen, sig, siglen)))
		PROV_ERR_raise(sctx->pctx, rc);

	return rc ? OSSL_RV_ERR : OSSL_RV_OK;
}

static int sig_sign_der(struct sig_ctx *sctx,
			unsigned char *sig, size_t *siglen, size_t sigsize,
			const unsigned char *tbs, size_t tbslen)
{
	unsigned char raw[MAX_RAW_SIGSZ];
	unsigned char *_sig;
	size_t rawlen;
	int rv;

	rawlen = MIN(sigsize, MAX_RAW_SIGSZ);
	_sig = sig ? raw : NULL;

	rv = sig_sign_raw(sctx, _sig, &rawlen, rawlen, tbs, tbslen);
	if (rv != OSSL_RV_OK)
		return rv;

	if (!sig) {
		if (siglen)
			*siglen = rawlen + ASN1_SIG_HDR;
	} else {
		rv = raw2der(raw, rawlen, sig, siglen);
	}

	return rv;
}

static int sig_verify_raw(struct sig_ctx *sctx,
			  const unsigned char *sig, size_t siglen,
			  const unsigned char *tbs, size_t tbslen)
{
	int rc;

	if (!sctx ||
	    !sctx->zpc_ctx ||
	    sctx->op != SIG_OP_VERIFY)
		return OSSL_RV_ERR;

	if ((rc = zpc_ecdsa_verify(sctx->zpc_ctx, tbs, tbslen, sig, siglen)))
		PROV_ERR_raise(sctx->pctx, rc);

	return rc ? OSSL_RV_ERR : OSSL_RV_OK;
}

static int sig_verify_der(struct sig_ctx *sctx,
			  const unsigned char *sig, size_t siglen,
			  const unsigned char *tbs, size_t tbslen)
{
	unsigned char raw[MAX_RAW_SIGSZ];
	size_t rawlen;
	int rv;

	/* calculate raw signature size */
	if (zpc_ecdsa_sign(sctx->zpc_ctx, tbs, tbslen, NULL, &rawlen))
		return OSSL_RV_ERR;

	rv = der2raw(sig, siglen, raw, &rawlen);
	if (rv != OSSL_RV_OK)
		return rv;

	return sig_verify_raw(sctx, raw, rawlen, tbs, tbslen);
}

#define DISP_SIG(tname, name) DECL_DISPATCH_FUNC(signature, tname, name)
DISP_SIG(newctx, ecdsa_newctx);
DISP_SIG(newctx, ed25519_newctx);
DISP_SIG(newctx, ed448_newctx);
DISP_SIG(dupctx, sig_dupctx);
DISP_SIG(freectx, sig_freectx);

DISP_SIG(sign_init, sig_sign_init);
DISP_SIG(sign, sig_sign);

DISP_SIG(verify_init, sig_verify_init);
DISP_SIG(verify, sig_verify);

DISP_SIG(digest_sign_init, sig_digest_sign_init);
DISP_SIG(digest_sign_init, ed_digest_sign_init);
DISP_SIG(digest_sign_update, sig_digest_update);
DISP_SIG(digest_sign_final, sig_digest_sign_final);

DISP_SIG(digest_verify_init, sig_digest_verify_init);
DISP_SIG(digest_verify_init, ed_digest_verify_init);
DISP_SIG(digest_verify_update, sig_digest_update);
DISP_SIG(digest_verify_final, sig_digest_verify_final);

DISP_SIG(gettable_ctx_params, ecdsa_gettable_ctx_params);
DISP_SIG(get_ctx_params, ecdsa_get_ctx_params);
DISP_SIG(settable_ctx_params, ecdsa_settable_ctx_params);
DISP_SIG(set_ctx_params, ecdsa_set_ctx_params);

DISP_SIG(gettable_ctx_params, eddsa_gettable_ctx_params);
DISP_SIG(get_ctx_params, eddsa_get_ctx_params);
DISP_SIG(settable_ctx_params, eddsa_settable_ctx_params);
DISP_SIG(set_ctx_params, eddsa_set_ctx_params);
#undef DISP_SIG

/* dispatch */
static void *ecdsa_newctx(void *vpctx, const char *propq)
{
	return sig_newctx(vpctx, propq, ecdsa_curves, ARRAY_SIZE(ecdsa_curves),
			  SIG_FMT_DER, ecdsa_set_ctx_params, NULL, NULL, 0);
}

static void *ed25519_newctx(void *vpctx, const char *propq)
{
	return sig_newctx(vpctx, propq, ed25519_curves, ARRAY_SIZE(ed25519_curves),
			  SIG_FMT_RAW, eddsa_set_ctx_params, ed25519, edctx, 0);
}

static void *ed448_newctx(void *vpctx, const char *propq)
{
	return sig_newctx(vpctx, propq, ed448_curves, ARRAY_SIZE(ed448_curves),
			  SIG_FMT_RAW, eddsa_set_ctx_params, ed448, edctx, 0);
}

static void sig_freectx(void *vsctx)
{
	struct sig_ctx *sctx = (struct sig_ctx *)vsctx;

	if (!sctx)
		return;

	obj_free(sctx->obj);
	zpc_ecdsa_ctx_free(&sctx->zpc_ctx);
	EVP_MD_CTX_free(sctx->fwd_md_ctx);
	OPENSSL_free(sctx->propq);
	OPENSSL_free(sctx);
}

#if !OPENSSL_VERSION_PREREQ(3, 1)
static EVP_MD_CTX *EVP_MD_CTX_dup(const EVP_MD_CTX *in)
{
	EVP_MD_CTX *out = EVP_MD_CTX_new();

	if (out != NULL && !EVP_MD_CTX_copy_ex(out, in)) {
		EVP_MD_CTX_free(out);
		out = NULL;
	}
	return out;
}
#endif

static void *sig_dupctx(void *vsctx)
{
	struct sig_ctx *sctx_src = (struct sig_ctx *)vsctx;
	struct sig_ctx *sctx_dst = NULL;
	int rc;

	if (!sctx_src ||
	    !(sctx_dst = sig_newctx(sctx_src->pctx, sctx_src->propq,
				    sctx_src->curves, sctx_src->curves_len,
				    sctx_src->fmt, sctx_src->set_ctx_params,
				    sctx_src->ed_instance, sctx_src->ed_ctx,
				    sctx_src->ed_ctxlen)))
		return NULL;

	if (sctx_src->fwd_md_ctx &&
	    !(sctx_dst->fwd_md_ctx = EVP_MD_CTX_dup(sctx_src->fwd_md_ctx)))
		goto err;

	if (sctx_src->obj &&
	    (rc = zpc_ecdsa_ctx_set_key(sctx_dst->zpc_ctx,
					sctx_src->obj->ec_key))) {
		PROV_ERR_raise(sctx_dst->pctx, rc);
		goto err;
	}

	sctx_dst->obj = obj_get(sctx_src->obj);
	sctx_dst->op = sctx_src->op;

	return sctx_dst;
err:
	sig_freectx(sctx_dst);
	return NULL;
}

/* dispatch prehashed sign/verify */
static int sig_sign_init(void *vsctx, void *provkey,
			 const OSSL_PARAM params[])
{
	return sig_init(vsctx, provkey, params, SIG_OP_SIGN);
}

static int sig_verify_init(void *vsctx, void *provkey,
			   const OSSL_PARAM params[])
{
	return sig_init(vsctx, provkey, params, SIG_OP_VERIFY);
}

static int sig_sign(void *vsctx, unsigned char *sig, size_t *siglen,
		    size_t sigsize, const unsigned char *tbs, size_t tbslen)
{
	struct sig_ctx *sctx = (struct sig_ctx *)vsctx;
	size_t _siglen;
	int rv;

	if (!sctx || !tbs ||
	    !sctx->zpc_ctx ||
	    sctx->op != SIG_OP_SIGN)
		return OSSL_RV_ERR;

	_siglen = siglen ? *siglen : sigsize;

	rv = (sctx->fmt == SIG_FMT_RAW) ?
		sig_sign_raw(sctx, sig, &_siglen, sigsize, tbs, tbslen) :
		sig_sign_der(sctx, sig, &_siglen, sigsize, tbs, tbslen);

	if (rv == OSSL_RV_OK)
		if (siglen)
			*siglen = _siglen;

	return rv;
}

static int sig_verify(void *vsctx, const unsigned char *sig, size_t siglen,
		      const unsigned char *tbs, size_t tbslen)
{
	struct sig_ctx *sctx = (struct sig_ctx *)vsctx;

	if (!sctx || !sig || !tbs ||
	    !sctx->zpc_ctx ||
	    sctx->op != SIG_OP_VERIFY)
		return OSSL_RV_ERR;

	return (sctx->fmt == SIG_FMT_RAW) ?
		sig_verify_raw(sctx, sig, siglen, tbs, tbslen) :
		sig_verify_der(sctx, sig, siglen, tbs, tbslen);
}

/* dispatch digest sign/verify */
static int sig_digest_sign_init(void *vsctx, const char *mdname,
				void *provkey, const OSSL_PARAM params[])
{
	return sig_digest_init(vsctx, mdname, provkey, params, SIG_OP_SIGN);
}

static int sig_digest_verify_init(void *vsctx, const char *mdname,
				  void *provkey, const OSSL_PARAM params[])
{
	return sig_digest_init(vsctx, mdname, provkey, params, SIG_OP_VERIFY);
}

static int sig_digest_update(void *vsctx, const unsigned char *data,
			      size_t datalen)
{
	struct sig_ctx *sctx = (struct sig_ctx *)vsctx;

	if (!sctx)
		return OSSL_RV_ERR;

	return EVP_DigestUpdate(sctx->fwd_md_ctx, data, datalen);
}

static int sig_digest_sign_final(void *vsctx, unsigned char *sig,
				 size_t *siglen, size_t sigsize)
{
	struct sig_ctx *sctx = (struct sig_ctx *)vsctx;
	unsigned char tbs[EVP_MAX_MD_SIZE];
	unsigned int tbslen = EVP_MAX_MD_SIZE;

	if (!sctx)
		return OSSL_RV_ERR;

	if (sig &&
	    EVP_DigestFinal_ex(sctx->fwd_md_ctx, tbs, &tbslen) != OSSL_RV_OK)
		return OSSL_RV_ERR;

	return sig_sign(sctx, sig, siglen, sigsize, tbs, tbslen);
}

static int sig_digest_verify_final(void *vsctx, const unsigned char *sig,
				   size_t siglen)
{
	struct sig_ctx *sctx = (struct sig_ctx *)vsctx;
	unsigned char tbs[EVP_MAX_MD_SIZE];
	unsigned int tbslen = EVP_MAX_MD_SIZE;

	if (!sctx)
		return OSSL_RV_ERR;

	if (EVP_DigestFinal_ex(sctx->fwd_md_ctx, tbs, &tbslen) != OSSL_RV_OK)
		return OSSL_RV_ERR;

	return sig_verify(sctx, sig, siglen, tbs, tbslen);
}

static int ed_digest_sign_init(void *vsctx, const char *mdname __unused,
			       void *provkey, const OSSL_PARAM params[])
{
	return sig_init(vsctx, provkey, params, SIG_OP_SIGN);
}

static int ed_digest_verify_init(void *vsctx, const char *mdname __unused,
				 void *provkey, const OSSL_PARAM params[])
{
	return sig_init(vsctx, provkey, params, SIG_OP_VERIFY);
}

/* dispatch get/set */
static const OSSL_PARAM *ecdsa_gettable_ctx_params(void *vsctx __unused,
						   void *vpctx __unused)
{
	static const OSSL_PARAM params[] = {
		OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_ALGORITHM_ID, NULL, 0),
		OSSL_PARAM_size_t(OSSL_SIGNATURE_PARAM_DIGEST_SIZE, NULL),
		OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
#ifdef OSSL_SIGNATURE_PARAM_NONCE_TYPE
		OSSL_PARAM_uint(OSSL_SIGNATURE_PARAM_NONCE_TYPE, 0),
#endif
		OSSL_PARAM_END,
	};
	return params;
}

static int ecdsa_get_ctx_params(void *vsctx, OSSL_PARAM params[])
{
	struct sig_ctx *sctx = (struct sig_ctx *)vsctx;
	OSSL_PARAM *p;

	if (!sctx)
		return OSSL_RV_ERR;

	p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_ALGORITHM_ID);
	if (p) {
		int type;

		if (!sctx->fwd_md_ctx)
			return OSSL_RV_ERR;

		type = EVP_MD_CTX_get_type(sctx->fwd_md_ctx);
		if (algid_ecdsa(type, p) != OSSL_RV_OK)
			return OSSL_RV_ERR;
	}

#ifdef OSSL_SIGNATURE_PARAM_NONCE_TYPE
	p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_NONCE_TYPE);
	if (p) {
		/* REVISIT deterministic nonce support */
		if (OSSL_PARAM_set_uint(p, 0) != OSSL_RV_OK)
			return OSSL_RV_ERR;
	}
#endif

	p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_DIGEST_SIZE);
	if (p) {
		int dsz = EVP_MD_CTX_get_size(sctx->fwd_md_ctx);

		if (dsz <= 0 || (OSSL_PARAM_set_size_t(p, dsz) != OSSL_RV_OK))
			return OSSL_RV_ERR;
	}

	p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_DIGEST);
	if (p) {
		const char *d = EVP_MD_CTX_get0_name(sctx->fwd_md_ctx);
		if (!d ||
		    OSSL_PARAM_set_utf8_string(p, d) != OSSL_RV_OK)
			return OSSL_RV_ERR;
	}

	return OSSL_RV_OK;
}

static const OSSL_PARAM *ecdsa_settable_ctx_params(void *vsctx __unused,
						   void *vpctx __unused)
{
	static const OSSL_PARAM params[] = {
		OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
#ifdef OSSL_SIGNATURE_PARAM_NONCE_TYPE
		OSSL_PARAM_uint(OSSL_SIGNATURE_PARAM_NONCE_TYPE, 0),
#endif
		OSSL_PARAM_END,
	};
	return params;
}

static int ecdsa_set_ctx_params(void *vsctx, const OSSL_PARAM params[])
{
	struct sig_ctx *sctx = (struct sig_ctx *)vsctx;
	const OSSL_PARAM *p;

	if (!sctx)
		return OSSL_RV_ERR;

#ifdef OSSL_SIGNATURE_PARAM_NONCE_TYPE
	p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_NONCE_TYPE);
	if (p) {
		unsigned int nonce_type;

		/* REVISIT deterministic nonce support */
		if ((OSSL_PARAM_get_uint(p, &nonce_type) != OSSL_RV_OK) ||
		    (nonce_type != 0))
			return OSSL_RV_ERR;
	}
#endif

	p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_DIGEST);
	if (p) {
		const char *mdname = NULL;

		if (OSSL_PARAM_get_utf8_string_ptr(p, &mdname) != OSSL_RV_OK ||
		    sig_sctx_set_md(sctx, mdname, params) != OSSL_RV_OK)
			return OSSL_RV_ERR;
	}

	return OSSL_RV_OK;
}

static const OSSL_PARAM *eddsa_gettable_ctx_params(void *vsctx __unused,
						   void *vpctx __unused)
{
	static const OSSL_PARAM params[] = {
		OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_ALGORITHM_ID, NULL, 0),
#ifdef OSSL_SIGNATURE_PARAM_INSTANCE
		OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_INSTANCE, NULL, 0),
#endif
#ifdef OSSL_SIGNATURE_PARAM_CONTEXT_STRING
		OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_CONTEXT_STRING, NULL, 0),
#endif
		OSSL_PARAM_END,
	};
	return params;
}

static int eddsa_get_ctx_params(void *vsctx, OSSL_PARAM params[])
{
	struct sig_ctx *sctx = (struct sig_ctx *)vsctx;
	OSSL_PARAM *p;

	if (!sctx)
		return OSSL_RV_ERR;

	p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_ALGORITHM_ID);
	if (p) {
		if (algid_eddsa(sctx->ed_instance, p) != OSSL_RV_OK)
			return OSSL_RV_ERR;
	}

#ifdef OSSL_SIGNATURE_PARAM_INSTANCE
	p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_INSTANCE);
	if (p) {
		if (OSSL_PARAM_set_utf8_string(p, sctx->ed_instance) != OSSL_RV_OK)
			return OSSL_RV_ERR;
	}
#endif

#ifdef OSSL_SIGNATURE_PARAM_CONTEXT_STRING
	p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_CONTEXT_STRING);
	if (p) {
		if (OSSL_PARAM_set_octet_string(p, sctx->ed_ctx, sctx->ed_ctxlen) != OSSL_RV_OK)
			return OSSL_RV_ERR;
	}
#endif

	return OSSL_RV_OK;
}

static const OSSL_PARAM *eddsa_settable_ctx_params(void *vsctx __unused,
						   void *vpctx __unused)
{
	static const OSSL_PARAM params[] = {
#ifdef OSSL_SIGNATURE_PARAM_INSTANCE
		OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_INSTANCE, NULL, 0),
#endif
#ifdef OSSL_SIGNATURE_PARAM_CONTEXT_STRING
		OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_CONTEXT_STRING, NULL, 0),
#endif
		OSSL_PARAM_END,
	};
	return params;
}

static int eddsa_set_ctx_params(void *vsctx,
				const OSSL_PARAM params[] __unused)
{
	struct sig_ctx *sctx = (struct sig_ctx *)vsctx;
	const OSSL_PARAM *p __unused;

	if (!sctx)
		return OSSL_RV_ERR;

#ifdef OSSL_SIGNATURE_PARAM_INSTANCE
	p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_INSTANCE);
	if (p) {
		const char *edi = NULL;

		if (OSSL_PARAM_get_utf8_string_ptr(p, &edi) != OSSL_RV_OK ||
		    OPENSSL_strcasecmp(sctx->ed_instance, edi) != 0)
			return OSSL_RV_ERR;
	}
#endif

#ifdef OSSL_SIGNATURE_PARAM_CONTEXT_STRING
	p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_CONTEXT_STRING);
	if (p) {
		const void *edc = NULL;
		size_t edcl;

		if (OSSL_PARAM_get_octet_string_ptr(p, &edc, &edcl) != OSSL_RV_OK ||
		    sctx->ed_ctxlen != edcl ||
		    memcmp(sctx->ed_ctx, edc, edcl) != 0)
			return OSSL_RV_ERR;
	}
#endif

	return OSSL_RV_OK;
}

#ifdef OSSL_FUNC_SIGNATURE_QUERY_KEY_TYPES
static const char **ecdsa_query_key_types(void)
{
	static const char *keytypes[] = { PROV_NAME_EC, NULL };
	return keytypes;
}

static const char **ed25519_query_key_types(void)
{
	static const char *keytypes[] = { PROV_NAME_ED25519, NULL };
	return keytypes;
}

static const char **ed448_query_key_types(void)
{
	static const char *keytypes[] = { PROV_NAME_ED448, NULL };
	return keytypes;
}
#endif

static const OSSL_DISPATCH ecdsa_functions[] = {
	DISPATCH_DEFN(SIGNATURE, NEWCTX,               ecdsa_newctx),
	DISPATCH_DEFN(SIGNATURE, FREECTX,              sig_freectx),
	DISPATCH_DEFN(SIGNATURE, DUPCTX,               sig_dupctx),

	DISPATCH_DEFN(SIGNATURE, SIGN_INIT,            sig_sign_init),
	DISPATCH_DEFN(SIGNATURE, SIGN,                 sig_sign),

	DISPATCH_DEFN(SIGNATURE, VERIFY_INIT,          sig_verify_init),
	DISPATCH_DEFN(SIGNATURE, VERIFY,               sig_verify),

	DISPATCH_DEFN(SIGNATURE, DIGEST_SIGN_INIT,     sig_digest_sign_init),
	DISPATCH_DEFN(SIGNATURE, DIGEST_SIGN_UPDATE,   sig_digest_update),
	DISPATCH_DEFN(SIGNATURE, DIGEST_SIGN_FINAL,    sig_digest_sign_final),

	DISPATCH_DEFN(SIGNATURE, DIGEST_VERIFY_INIT,   sig_digest_verify_init),
	DISPATCH_DEFN(SIGNATURE, DIGEST_VERIFY_UPDATE, sig_digest_update),
	DISPATCH_DEFN(SIGNATURE, DIGEST_VERIFY_FINAL,  sig_digest_verify_final),

	DISPATCH_DEFN(SIGNATURE, GETTABLE_CTX_PARAMS,  ecdsa_gettable_ctx_params),
	DISPATCH_DEFN(SIGNATURE, GET_CTX_PARAMS,       ecdsa_get_ctx_params),
	DISPATCH_DEFN(SIGNATURE, SETTABLE_CTX_PARAMS,  ecdsa_settable_ctx_params),
	DISPATCH_DEFN(SIGNATURE, SET_CTX_PARAMS,       ecdsa_set_ctx_params),
#ifdef OSSL_FUNC_SIGNATURE_QUERY_KEY_TYPES
	DISPATCH_DEFN(SIGNATURE, QUERY_KEY_TYPES,      ecdsa_query_key_types),
#endif

	DISPATCH_END,
};

static const OSSL_DISPATCH ed25519_functions[] = {
	DISPATCH_DEFN(SIGNATURE, NEWCTX,               ed25519_newctx),
	DISPATCH_DEFN(SIGNATURE, FREECTX,              sig_freectx),
	DISPATCH_DEFN(SIGNATURE, DUPCTX,               sig_dupctx),

	DISPATCH_DEFN(SIGNATURE, SIGN_INIT,            sig_sign_init),
	DISPATCH_DEFN(SIGNATURE, SIGN,                 sig_sign),

	DISPATCH_DEFN(SIGNATURE, VERIFY_INIT,          sig_verify_init),
	DISPATCH_DEFN(SIGNATURE, VERIFY,               sig_verify),

	DISPATCH_DEFN(SIGNATURE, DIGEST_SIGN_INIT,     ed_digest_sign_init),
	DISPATCH_DEFN(SIGNATURE, DIGEST_SIGN,          sig_sign),

	DISPATCH_DEFN(SIGNATURE, DIGEST_VERIFY_INIT,   ed_digest_verify_init),
	DISPATCH_DEFN(SIGNATURE, DIGEST_VERIFY,        sig_verify),

#ifdef OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT
	DISPATCH_DEFN(SIGNATURE, SIGN_MESSAGE_INIT,    sig_sign_init),
#endif
#ifdef OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_INIT
	DISPATCH_DEFN(SIGNATURE, VERIFY_MESSAGE_INIT,  sig_verify_init),
#endif

	DISPATCH_DEFN(SIGNATURE, GETTABLE_CTX_PARAMS,  eddsa_gettable_ctx_params),
	DISPATCH_DEFN(SIGNATURE, GET_CTX_PARAMS,       eddsa_get_ctx_params),
	DISPATCH_DEFN(SIGNATURE, SETTABLE_CTX_PARAMS,  eddsa_settable_ctx_params),
	DISPATCH_DEFN(SIGNATURE, SET_CTX_PARAMS,       eddsa_set_ctx_params),
#ifdef OSSL_FUNC_SIGNATURE_QUERY_KEY_TYPES
	DISPATCH_DEFN(SIGNATURE, QUERY_KEY_TYPES,      ed25519_query_key_types),
#endif

	DISPATCH_END,
};

static const OSSL_DISPATCH ed448_functions[] = {
	DISPATCH_DEFN(SIGNATURE, NEWCTX,               ed448_newctx),
	DISPATCH_DEFN(SIGNATURE, FREECTX,              sig_freectx),
	DISPATCH_DEFN(SIGNATURE, DUPCTX,               sig_dupctx),

	DISPATCH_DEFN(SIGNATURE, SIGN_INIT,            sig_sign_init),
	DISPATCH_DEFN(SIGNATURE, SIGN,                 sig_sign),

	DISPATCH_DEFN(SIGNATURE, VERIFY_INIT,          sig_verify_init),
	DISPATCH_DEFN(SIGNATURE, VERIFY,               sig_verify),

	DISPATCH_DEFN(SIGNATURE, DIGEST_SIGN_INIT,     ed_digest_sign_init),
	DISPATCH_DEFN(SIGNATURE, DIGEST_SIGN,          sig_sign),

	DISPATCH_DEFN(SIGNATURE, DIGEST_VERIFY_INIT,   ed_digest_verify_init),
	DISPATCH_DEFN(SIGNATURE, DIGEST_VERIFY,        sig_verify),

#ifdef OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT
	DISPATCH_DEFN(SIGNATURE, SIGN_MESSAGE_INIT,    sig_sign_init),
#endif
#ifdef OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_INIT
	DISPATCH_DEFN(SIGNATURE, VERIFY_MESSAGE_INIT,  sig_verify_init),
#endif

	DISPATCH_DEFN(SIGNATURE, GETTABLE_CTX_PARAMS,  eddsa_gettable_ctx_params),
	DISPATCH_DEFN(SIGNATURE, GET_CTX_PARAMS,       eddsa_get_ctx_params),
	DISPATCH_DEFN(SIGNATURE, SETTABLE_CTX_PARAMS,  eddsa_settable_ctx_params),
	DISPATCH_DEFN(SIGNATURE, SET_CTX_PARAMS,       eddsa_set_ctx_params),
#ifdef OSSL_FUNC_SIGNATURE_QUERY_KEY_TYPES
	DISPATCH_DEFN(SIGNATURE, QUERY_KEY_TYPES,      ed448_query_key_types),
#endif

	DISPATCH_END,
};

const OSSL_ALGORITHM signature_ops[] = {
	ALGORITHM_DEFN(PROV_NAMES_ECDSA, PROV_PROP, ecdsa_functions, PROV_DESC_ECDSA),
	ALGORITHM_DEFN(PROV_NAMES_ED25519, PROV_PROP, ed25519_functions, PROV_DESC_ED25519),
	ALGORITHM_DEFN(PROV_NAMES_ED448, PROV_PROP, ed448_functions, PROV_DESC_ED448),
	ALGORITHM_END,
};
