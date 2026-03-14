// SPDX-License-Identifier: MIT
// Copyright contributors to the libzpc project
#include <openssl/core.h>
#include <openssl/core_names.h>
#include <openssl/core_object.h>

#include "store_local.h"

#include "provider.h"
#include "decoder.h"
#include "ossl.h"
#include "asn1.h"
#include "uri.h"
#include "map.h"

#define DECODER_DER_STRUCTURE	"hbkzpc"
#define DECODER_PROP_PEM	PROV_PROP",input=pem"
#define DECODER_PROP_DER	PROV_PROP",input=der,structure="DECODER_DER_STRUCTURE

#define DECODER_CARRYON		OSSL_RV_TRUE
#define DECODER_STOP		OSSL_RV_FALSE

struct decoder_ctx {
	struct provider_ctx *pctx;
};

static void *dec_newctx(void *vpctx)
{
	struct provider_ctx *pctx = (struct provider_ctx *)vpctx;
	struct decoder_ctx *dctx;

	if (!pctx)
		return NULL;

	dctx = OPENSSL_zalloc(sizeof(struct decoder_ctx));
	if (!dctx)
		return NULL;

	dctx->pctx = pctx;
	return dctx;
}

static void dec_freectx(void *vdctx)
{
	OPENSSL_free(vdctx);
}

static int dec_pem_der_decode(void *vdctx, OSSL_CORE_BIO *in,
			      int selection __unused,
			      OSSL_CALLBACK *data_cb, void *data_cbarg,
			      OSSL_PASSPHRASE_CALLBACK *cb __unused,
			      void *cbarg __unused)
{
	char *label = NULL, *header = NULL;
	struct decoder_ctx *dctx = vdctx;
	unsigned char *data = NULL;
	int rc = DECODER_CARRYON;
	OSSL_PARAM params[3];
	long datalen;
	BIO *bin;

	bin = BIO_new_from_core_bio(dctx->pctx->libctx, in);
	if (!bin)
		goto out;

	if (PEM_read_bio(bin, &label, &header, &data, &datalen) != OSSL_RV_OK ||
	    OPENSSL_strcasecmp(label, HBKZPC_PEM_STRING) != 0)
		goto out;

	params[0] = OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_DATA,
						      data, datalen);
	params[1] = OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_STRUCTURE,
						     DECODER_DER_STRUCTURE, 0);
	params[2] = OSSL_PARAM_construct_end();
	rc = data_cb(params, data_cbarg);
out:
	OPENSSL_free(header);
	OPENSSL_free(label);
	OPENSSL_free(data);
	BIO_free(bin);

	return rc;
}

static int dec_der_decode(struct decoder_ctx *dctx, OSSL_CORE_BIO *in,
			  int selection, const char *data_type,
			  OSSL_CALLBACK *data_cb, void *data_cbarg,
			  OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
	struct parsed_uri *puri = NULL;
	const char *uri_data_type;
	bool public_only = false;
	int rv = DECODER_CARRYON;
	HBKZPC *hbk = NULL;
	BIO *bin;

	bin = BIO_new_from_core_bio(dctx->pctx->libctx, in);
	if (!bin)
		goto out;

	if (!d2i_HBKZPC_bio(bin, &hbk))
		goto out;

	puri = parsed_uri_new((const char *)ASN1_STRING_get0_data(hbk->uri));
	if (!puri)
		goto out;

	uri_data_type = alg2data_type(puri->origin_alg.value);

	if (OPENSSL_strcasecmp(data_type, uri_data_type) != 0)
		goto out;

	public_only = selection && !(selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY);

	rv = store_load_uri(dctx->pctx, puri, public_only,
			    data_cb, data_cbarg, cb, cbarg);
out:
	parsed_uri_free(puri);
	HBKZPC_free(hbk);
	BIO_free(bin);
	return rv;
}

static int dec_der_ec_decode(void *vdctx, OSSL_CORE_BIO *in,
			     int selection,
			     OSSL_CALLBACK *data_cb, void *data_cbarg,
			     OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
	return dec_der_decode(vdctx, in, selection, PROV_NAME_EC,
			      data_cb, data_cbarg, cb, cbarg);
}

static int dec_der_ed25519_decode(void *vdctx, OSSL_CORE_BIO *in,
			          int selection,
			          OSSL_CALLBACK *data_cb, void *data_cbarg,
			          OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
	return dec_der_decode(vdctx, in, selection, PROV_NAME_ED25519,
			      data_cb, data_cbarg, cb, cbarg);
}

static int dec_der_ed448_decode(void *vdctx, OSSL_CORE_BIO *in,
			          int selection,
			          OSSL_CALLBACK *data_cb, void *data_cbarg,
			          OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
	return dec_der_decode(vdctx, in, selection, PROV_NAME_ED448,
			      data_cb, data_cbarg, cb, cbarg);
}

static const OSSL_DISPATCH decoder_der_ec_functions[] = {
	DISPATCH_DEFN(DECODER, NEWCTX, dec_newctx),
	DISPATCH_DEFN(DECODER, FREECTX, dec_freectx),
	DISPATCH_DEFN(DECODER, DECODE, dec_der_ec_decode),
	DISPATCH_END,
};

static const OSSL_DISPATCH decoder_der_ed25519_functions[] = {
	DISPATCH_DEFN(DECODER, NEWCTX, dec_newctx),
	DISPATCH_DEFN(DECODER, FREECTX, dec_freectx),
	DISPATCH_DEFN(DECODER, DECODE, dec_der_ed25519_decode),
	DISPATCH_END,
};

static const OSSL_DISPATCH decoder_der_ed448_functions[] = {
	DISPATCH_DEFN(DECODER, NEWCTX, dec_newctx),
	DISPATCH_DEFN(DECODER, FREECTX, dec_freectx),
	DISPATCH_DEFN(DECODER, DECODE, dec_der_ed448_decode),
	DISPATCH_END,
};

static const OSSL_DISPATCH decoder_pem_der_functions[] = {
	DISPATCH_DEFN(DECODER, NEWCTX, dec_newctx),
	DISPATCH_DEFN(DECODER, FREECTX, dec_freectx),
	DISPATCH_DEFN(DECODER, DECODE, dec_pem_der_decode),
	DISPATCH_END,
};

const OSSL_ALGORITHM decoder_ops[] = {
	ALGORITHM_DEFN("DER", DECODER_PROP_PEM, decoder_pem_der_functions, NULL),
	ALGORITHM_DEFN(PROV_NAME_EC, DECODER_PROP_DER, decoder_der_ec_functions,  NULL),
	ALGORITHM_DEFN(PROV_NAME_ED25519, DECODER_PROP_DER, decoder_der_ed25519_functions,  NULL),
	ALGORITHM_DEFN(PROV_NAME_ED448, DECODER_PROP_DER, decoder_der_ed448_functions,  NULL),
	ALGORITHM_END,
};
