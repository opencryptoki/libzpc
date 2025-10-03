// SPDX-License-Identifier: MIT
// Copyright contributors to the libzpc project
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/rand.h>

#include "ossl.h"

#define PROP_PROVIDER		"provider=hbkzpc"

#define ZPC_PARAM_ORIGIN_TYPE	"origin-type"
#define ZPC_PARAM_ORIGIN_ALG	"origin-alg"
#define ZPC_PARAM_UVSECRET_ID	"uvsecret-id"

#define ORIGIN_ALG		"aes-128"
#define ORIGIN_TYPE		"uv"

enum rv {
	PASS = 0,
	SKIP = 77,
	FAIL = 99,
};

/* sha256("aes-key") */
static char secretid[] = {
	0x52, 0xfd, 0x15, 0xbc, 0x2e, 0xbb, 0xd8, 0x83,
	0x68, 0x41, 0x19, 0xb8, 0xde, 0x13, 0x12, 0xa8,
	0x39, 0x40, 0x38, 0x4a, 0x67, 0x24, 0x76, 0xd2,
	0xd1, 0xec, 0xd5, 0x51, 0xe0, 0x24, 0x71, 0x70,
};

static unsigned char text[32];
static unsigned char buf1[32];
static unsigned char buf2[32];

static unsigned char iv[16];

static const char *stringify(int rv)
{
	switch(rv) {
	case PASS:
		return "PASS";
	case FAIL:
		return "FAIL";
	case SKIP:
		return "SKIP";
	};
	return "n/a";
}

static EVP_SKEYMGMT *get_skeymgmt(void)
{
	return EVP_SKEYMGMT_fetch(NULL, "AES", PROP_PROVIDER);
}

static EVP_SKEY *get_skey(void)
{
	static const OSSL_PARAM params[] = {
		OSSL_PARAM_utf8_string(ZPC_PARAM_ORIGIN_ALG, ORIGIN_ALG, 0),
		OSSL_PARAM_utf8_string(ZPC_PARAM_ORIGIN_TYPE, ORIGIN_TYPE, 0),
		OSSL_PARAM_octet_string(ZPC_PARAM_UVSECRET_ID, secretid, sizeof(secretid)),
		OSSL_PARAM_END,
	};
	EVP_SKEYMGMT *skmgmt = get_skeymgmt();

	if (!skmgmt) {
		fprintf(stderr, "no skeymgmt\n");
		return NULL;
	}

	return EVP_SKEY_import(NULL, EVP_SKEYMGMT_get0_name(skmgmt),
			       PROP_PROVIDER, OSSL_SKEYMGMT_SELECT_ALL,
			       params);
}

static EVP_CIPHER *get_cipher(void)
{
	return EVP_CIPHER_fetch(NULL, "AES-128-CBC", PROP_PROVIDER);
}

static int test_provider(void)
{
	OSSL_LIB_CTX *libctx = NULL;
	OSSL_PROVIDER *provider = NULL;
	int rv = FAIL;

	provider = OSSL_PROVIDER_load(libctx, "hbkzpc");
	if (!provider) {
		fprintf(stderr, "no provider\n");
		goto out;
	}

	fprintf(stderr, "provider - name: %s\n",
		OSSL_PROVIDER_get0_name(provider));
	rv = PASS;
out:
	return rv;
}

static int test_skeymgmt(void)
{
	EVP_SKEYMGMT *skmgmt = get_skeymgmt();
	int rv = FAIL;

	if (!skmgmt) {
		fprintf(stderr, "no skeymgmt\n");
		goto out;
	}

	fprintf(stderr, "skeymgmt - name: %s, description: %s\n",
		EVP_SKEYMGMT_get0_name(skmgmt),
		EVP_SKEYMGMT_get0_description(skmgmt));
	rv = PASS;
out:
	return rv;
}

static int test_skey(void)
{
	EVP_SKEY *skey = get_skey();
	int rv = FAIL;

	if (!skey) {
		fprintf(stderr, "no evp_skey\n");
		goto out;
	}

	fprintf(stderr, "skey - id: %s\n",
		EVP_SKEY_get0_key_id(skey));
	rv = PASS;
out:
	return rv;
}

static int test_cipher(void)
{
	EVP_CIPHER *cipher = get_cipher();
	int rv = FAIL;

	if (!cipher) {
		fprintf(stderr, "no evp_cipher\n");
		goto out;
	}

	fprintf(stderr, "cipher - name: %s, description: %s\n",
		EVP_CIPHER_get0_name(cipher),
		EVP_CIPHER_get0_description(cipher));

	rv = PASS;
out:
	return rv;
}

static int test_cipher_encrypt(void)
{
	unsigned char *in = text, *out = buf1;
	int inl = 32, outl = sizeof(buf1);
	EVP_CIPHER *cipher = get_cipher();
	EVP_SKEY *skey = get_skey();
	EVP_CIPHER_CTX *ctx;
	int rv = FAIL;

	if (!cipher || !skey)
		return SKIP;

	ctx = EVP_CIPHER_CTX_new();
	if (!ctx) {
		fprintf(stderr, "no evp_cipher_ctx\n");
		goto out;
	}

	if (EVP_CipherInit_SKEY(ctx, cipher, skey, iv, sizeof(iv), 1, NULL) != OSSL_RV_OK) {
		fprintf(stderr, "evp_cipher_ctx init failed\n");
		goto out;
	}

	if (EVP_CipherUpdate(ctx, out, &outl, in, inl) != OSSL_RV_OK) {
		fprintf(stderr, "update failed\n");
		goto out;
	}

	if (EVP_CipherFinal_ex(ctx, out, &outl) != OSSL_RV_OK) {
		fprintf(stderr, "final failed\n");
		goto out;
	}

	rv = PASS;
out:
	return rv;
}

static int test_cipher_decrypt(void)
{
	unsigned char *in = buf1, *out = buf2;
	int inl = sizeof(buf1), outl = sizeof(buf2);
	EVP_CIPHER *cipher = get_cipher();
	EVP_SKEY *skey = get_skey();
	EVP_CIPHER_CTX *ctx;
	int rv = FAIL;

	if (!cipher || !skey)
		return SKIP;

	ctx = EVP_CIPHER_CTX_new();
	if (!ctx) {
		fprintf(stderr, "no evp_cipher_ctx\n");
		goto out;
	}

	if (EVP_CipherInit_SKEY(ctx, cipher, skey, iv, sizeof(iv), 0, NULL) != OSSL_RV_OK) {
		fprintf(stderr, "evp_cipher_ctx init failed\n");
		goto out;
	}

	if (EVP_CipherUpdate(ctx, out, &outl, in, inl) != OSSL_RV_OK) {
		fprintf(stderr, "update failed\n");
		goto out;
	}

	if (EVP_CipherFinal_ex(ctx, out, &outl) != OSSL_RV_OK) {
		fprintf(stderr, "final failed\n");
		goto out;
	}

	if (memcmp(text, buf2, 32) != 0) {
		fprintf(stderr, "compare failed\n");
		goto out;
	}

	rv = PASS;
out:
	return rv;
}

#define RUNTEST(t)	do { fprintf(stdout, "%s - %s\n", #t, stringify(t())); } while (0)

int main(void)
{
	RAND_bytes(text, sizeof(text));
	RAND_bytes(iv, sizeof(iv));

	RUNTEST(test_provider);
	RUNTEST(test_skeymgmt);
	RUNTEST(test_skey);
	RUNTEST(test_cipher);
	RUNTEST(test_cipher_encrypt);
	RUNTEST(test_cipher_decrypt);
}
