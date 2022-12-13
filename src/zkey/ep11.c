/*
 * zkey - Generate, re-encipher, and validate secure keys
 *
 * Copyright IBM Corp. 2019
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <dlfcn.h>
#include <err.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/types.h>
#include <unistd.h>

#include "lib/util_base.h"
#include "lib/util_libc.h"
#include "lib/util_panic.h"

#include "ep11.h"
#include "pkey.h"
#include "utils.h"

#include "debug.h"

#define pr_verbose(verbose, fmt...)	do {				\
						if (verbose)					\
							DEBUG(fmt);					\
					} while (0)

/*
 * Definitions for the EP11 library
 */
#define EP11_LIBRARY_NAME	"libep11.so"
#define EP11_LIBRARY_VERSION	3
#define EP11_WEB_PAGE		"http://www.ibm.com/security/cryptocards"

extern const size_t curve2publen[];
extern const uint16_t curve2bitlen[];
extern const size_t curve2puboffset[];
extern const size_t curve2macedspkilen[];

/*
 * Some SPKI related constants
 */
const unsigned char p256_spki_seq1[] = ZPC_P256_SPKI_SEQ1;
const unsigned char p384_spki_seq1[] = ZPC_P384_SPKI_SEQ1;
const unsigned char p521_spki_seq1[] = ZPC_P521_SPKI_SEQ1;
const unsigned char ed25519_spki_seq1[] = ZPC_ED25519_SPKI_SEQ1;
const unsigned char ed448_spki_seq1[] = ZPC_ED448_SPKI_SEQ1;

const unsigned char *curve2spki_seq1[] = {
	(unsigned char *)&p256_spki_seq1,
	(unsigned char *)&p384_spki_seq1,
	(unsigned char *)&p521_spki_seq1,
	(unsigned char *)&ed25519_spki_seq1,
	(unsigned char *)&ed448_spki_seq1,
};

const size_t curve2spki_seq1_len[] = {
	sizeof(p256_spki_seq1),
	sizeof(p384_spki_seq1),
	sizeof(p521_spki_seq1),
	sizeof(ed25519_spki_seq1),
	sizeof(ed448_spki_seq1),
};

const unsigned char ec_pubkey[] = ZPC_EC_PUBKEY;
const size_t ec_pubkey_len = sizeof(ec_pubkey);

const unsigned char p256_params[] = ZPC_P256_PARAMS;
const unsigned char p384_params[] = ZPC_P384_PARAMS;
const unsigned char p521_params[] = ZPC_P521_PARAMS;
const unsigned char ed25519_params[] = ZPC_ED25519_PARAMS;
const unsigned char ed448_params[] = ZPC_ED448_PARAMS;

const unsigned char *curve2spki_ec_params[] = {
	(unsigned char *)&p256_params,
	(unsigned char *)&p384_params,
	(unsigned char *)&p521_params,
	(unsigned char *)&ed25519_params,
	(unsigned char *)&ed448_params,
};

const size_t curve2spki_ec_params_len[] = {
	sizeof(p256_params),
	sizeof(p384_params),
	sizeof(p521_params),
	sizeof(ed25519_params),
	sizeof(ed448_params),
};

/**
 * Returns the major and minor version of the of the used EP11 host library.
 *
 * @param[in] ep11          the EP11 library structure
 * @param[in] verbose       if true, verbose messages are printed
 *
 * @returns 0 on success, a negative errno in case of an error
 */
static int get_ep11_version(struct ep11_lib *ep11, bool verbose)
{
	unsigned int host_version;
	CK_ULONG version_len = sizeof(host_version);
	CK_RV rc;

	if (ep11->lib_ep11 == NULL)
		return -ELIBACC;

	if (ep11->dll_m_get_xcp_info == NULL) {
		pr_verbose(verbose, "EP11 host lib function m_get_xcp_info not "
			"available but required for getting the EP11 library version.");
		return -ELIBACC;
	}

	rc = ep11->dll_m_get_xcp_info(&host_version, &version_len,
				      CK_IBM_XCPHQ_VERSION, 0, 0);
	if (rc != CKR_OK) {
		pr_verbose(verbose, "Failed to obtain the EP11 host library "
			   "version: m_get_xcp_info: 0x%lx", rc);
		return -EIO;
	}

	pr_verbose(verbose, "host_version: 0x%08x", host_version);

	ep11->version.major = (host_version & 0x00FF0000) >> 16;
	ep11->version.minor = (host_version & 0x0000FF00) >> 8;
	ep11->version.modification = host_version & 0x000000FF;
	/*
	 * EP11 host library < v2.0 returns an invalid version (i.e. 0x100).
	 * This can safely be treated as version 1.0
	 */
	if (ep11->version.major == 0) {
		ep11->version.major = 1;
		ep11->version.minor = 0;
	}

	pr_verbose(verbose, "EP11 library version: %u.%u.%u",
			ep11->version.major, ep11->version.minor,
			ep11->version.modification);

	return 0;
}

/**
 * Loads the EP11 library and provides the entry points of several functions.
 *
 * @param[out] ep11          on return this contains the address of the EP11
 *                           library and certain EP11 symbols. dlclose() should
 *                           be used to free the library when no longer needed.
 * @param verbose            if true, verbose messages are printed
 *
 * @returns 0 on success, -ELIBACC in case of library load errors
 */
int load_ep11_library(struct ep11_lib *ep11, bool verbose)
{
	char lib_name[256];
	int libver;
	int all_entry_points_loaded = 1, rc;

	util_assert(ep11 != NULL, "Internal error: ep11 is NULL");

	/* Load the EP11 library with highest available version'd SO name */
	for (libver = EP11_LIBRARY_VERSION; libver >= 0; libver--) {
		if (libver > 0)
			sprintf(lib_name, "%s.%d", EP11_LIBRARY_NAME, libver);
		else
			sprintf(lib_name, "%s", EP11_LIBRARY_NAME);

		ep11->lib_ep11 = dlopen(lib_name, RTLD_GLOBAL | RTLD_NOW);
		if (ep11->lib_ep11 != NULL)
			break;
	}
	if (ep11->lib_ep11 == NULL) {
		pr_verbose(verbose, "%s", dlerror());
		DEBUG("The command requires the IBM Z Enterprise PKCS #11 "
		      "(EP11) Support Program (EP11 host library).\n"
		      "For the supported environments and downloads, see:\n%s",
		      EP11_WEB_PAGE);
		return  -ELIBACC;
	}

	/* Get several EP11 host library functions */
	ep11->dll_m_init = (m_init_t)dlsym(ep11->lib_ep11, "m_init");
	ep11->dll_m_add_module = (m_add_module_t)dlsym(ep11->lib_ep11,
						       "m_add_module");
	ep11->dll_m_rm_module = (m_rm_module_t)dlsym(ep11->lib_ep11,
						     "m_rm_module");
	ep11->dll_m_get_xcp_info = (m_get_xcp_info_t)dlsym(ep11->lib_ep11,
							   "m_get_xcp_info");

	ep11->dll_m_admin = (m_admin_t)dlsym(ep11->lib_ep11, "m_admin");
	ep11->dll_xcpa_cmdblock = (xcpa_cmdblock_t)dlsym(ep11->lib_ep11,
							 "xcpa_cmdblock");
	if (ep11->dll_xcpa_cmdblock == NULL)
		ep11->dll_xcpa_cmdblock = (xcpa_cmdblock_t)dlsym(ep11->lib_ep11,
							"ep11a_cmdblock");
	ep11->dll_xcpa_internal_rv = (xcpa_internal_rv_t)dlsym(ep11->lib_ep11,
							"xcpa_internal_rv");
	if (ep11->dll_xcpa_internal_rv == NULL)
		ep11->dll_xcpa_internal_rv =
				(xcpa_internal_rv_t)dlsym(ep11->lib_ep11,
							  "ep11a_internal_rv");
	ep11->dll_m_UnwrapKey = (m_UnwrapKey_t)dlsym(ep11->lib_ep11, "m_UnwrapKey");
	ep11->dll_m_EncryptSingle = (m_EncryptSingle_t)dlsym(ep11->lib_ep11, "m_EncryptSingle");
	ep11->dll_m_GenerateKeyPair = (m_GenerateKeyPair_t)dlsym(ep11->lib_ep11, "m_GenerateKeyPair");
	ep11->dll_m_GenerateKey = (m_GenerateKey_t)dlsym(ep11->lib_ep11, "m_GenerateKey");
	ep11->dll_m_GetAttributeValue = (m_GetAttributeValue_t)dlsym(ep11->lib_ep11, "m_GetAttributeValue");

	/* dll_m_add_module and dll_m_rm_module may be NULL for V1 EP11 lib */
	if (ep11->dll_m_init == NULL ||
	    ep11->dll_m_get_xcp_info == NULL ||
	    ep11->dll_m_admin == NULL ||
	    ep11->dll_xcpa_cmdblock == NULL ||
	    ep11->dll_xcpa_internal_rv == NULL ||
	    ep11->dll_m_UnwrapKey == NULL ||
	    ep11->dll_m_EncryptSingle == NULL ||
	    ep11->dll_m_GenerateKeyPair == NULL ||
	    ep11->dll_m_GenerateKey == NULL ||
	    ep11->dll_m_GetAttributeValue == NULL) {
		pr_verbose(verbose, "%s", dlerror());
		DEBUG("The command requires the IBM Z Enterprise PKCS #11 "
		      "(EP11) Support Program (EP11 host library).\n"
		      "For the supported environments and downloads, see:\n%s",
		      EP11_WEB_PAGE);
		all_entry_points_loaded = 0;
	}

	if (ep11->dll_m_init == NULL) {
		dlclose(ep11->lib_ep11);
		ep11->lib_ep11 = NULL;
		return -ELIBACC;
	}

	/* Initialize the EP11 library */
	rc = ep11->dll_m_init();
	if (rc != 0) {
		pr_verbose(verbose, "Failed to initialize the EP11 host "
			   "library: m_init: 0x%x", rc);
		dlclose(ep11->lib_ep11);
		ep11->lib_ep11 = NULL;
		return -ELIBACC;
	}

	if (all_entry_points_loaded)
		pr_verbose(verbose, "EP11 library '%s' has been loaded successfully, "
				"all expected entry points available.",
			   lib_name);
	else
		pr_verbose(verbose, "EP11 library '%s' has been loaded successfully, "
				"but some entry points are missing.",
			   lib_name);

	return get_ep11_version(ep11, verbose);
}

/**
 * Get an EP11 target handle for a specific APQN (card and domain)
 *
 * @param[in] ep11          the EP11 library structure
 * @param[in] card          the card number
 * @param[in] domain        the domain number
 * @param[out] target       on return: the target handle for the APQN
 * @param verbose            if true, verbose messages are printed
 *
 * @returns 0 on success, a negative errno in case of errors
 */
int get_ep11_target_for_apqn(struct ep11_lib *ep11, unsigned int card,
		             unsigned int domain, target_t *target,
			     bool verbose)
{
	ep11_target_t *target_list;
	struct XCP_Module module;
	CK_RV rc;

	util_assert(ep11 != NULL, "Internal error: ep11 is NULL");
	util_assert(target != NULL, "Internal error: target is NULL");

	*target = XCP_TGT_INIT;

	if (ep11->dll_m_add_module != NULL) {
		memset(&module, 0, sizeof(module));
		module.version = ep11->version.major >= 3 ? XCP_MOD_VERSION_2
							  : XCP_MOD_VERSION_1;
		module.flags = XCP_MFL_MODULE;
		module.module_nr = card;
		XCPTGTMASK_SET_DOM(module.domainmask, domain);
		rc = ep11->dll_m_add_module(&module, target);
		if (rc != 0) {
			pr_verbose(verbose, "Failed to add APQN %02x.%04x: "
				   "m_add_module rc=0x%lx", card, domain, rc);
			return -EIO;
		}
	} else {
		/* Fall back to old target handling */
		target_list = (ep11_target_t *)calloc(1, sizeof(ep11_target_t));
		if (target_list == NULL)
			return -ENOMEM;
		target_list->length = 1;
		target_list->apqns[0] = card;
		target_list->apqns[1] = domain;
		*target = (target_t)target_list;
	}

	return 0;
}

/**
 * Free an EP11 target handle
 *
 * @param[in] ep11          the EP11 library structure
 * @param[in] target        the target handle to free
 *
 * @returns 0 on success, a negative errno in case of errors
 */
void free_ep11_target_for_apqn(struct ep11_lib *ep11, target_t target)
{
	util_assert(ep11 != NULL, "Internal error: ep11 is NULL");

	if (ep11->dll_m_rm_module != NULL) {
		ep11->dll_m_rm_module(NULL, target);
	} else {
		/*
		 * With the old target handling, target is a pointer to
		 * ep11_target_t
		 */
		free((ep11_target_t *)target);
	}
}

/**
 * Performs an EP11 administrative request to Re-encrypt a single EP11 secure
 * key with a new EP11 master key (wrapping key).
 *
 * @param[in] ep11      the EP11 library structure
 * @param[in] target    the target handle to use for the re-encipher operation
 * @param[in] card      the card that corresponds to the target handle
 * @param[in] domain    the domain that corresponds to the target handle
 * @param[in/out] ep11key the EP11 key token to reencipher. The re-enciphered
 *                      secure key will be returned in this buffer.
 * @param[in] ep11key_size the size of the secure key
 * @param[in] verbose   if true, verbose messages are printed
 *
 * @returns 0 on success, a negative errno in case of errors
 */
static int ep11_adm_reencrypt(struct ep11_lib *ep11, target_t target,
			      unsigned int card, unsigned int domain,
			      struct ep11keytoken *ep11key,
			      unsigned int ep11key_size, bool verbose)
{
	CK_BYTE resp[MAX_BLOBSIZE];
	CK_BYTE req[MAX_BLOBSIZE];
	struct XCPadmresp lrb;
	struct XCPadmresp rb;
	size_t resp_len;
	size_t blob_len;
	long req_len;
	CK_RV rv;
	int rc;

	if (ep11->dll_xcpa_cmdblock == NULL) {
		pr_verbose(verbose, "EP11 host lib function xcpa_cmdblock not "
			"available but required for EP11 adm reencrypt.");
		return -ELIBACC;
	}

	blob_len = ep11key_size;

	rb.domain = domain;
	lrb.domain = domain;

	resp_len = sizeof(resp);
	req_len = ep11->dll_xcpa_cmdblock(req, sizeof(req), XCP_ADM_REENCRYPT,
					  &rb, NULL, (unsigned char *)ep11key,
					  blob_len);
	if (req_len < 0) {
		pr_verbose(verbose, "Failed to build XCP command block");
		return -EIO;
	}

	rv = ep11->dll_m_admin(resp, &resp_len, NULL, NULL, req, req_len, NULL,
			       0, target);
	if (rv != CKR_OK || resp_len == 0) {
		pr_verbose(verbose, "Command XCP_ADM_REENCRYPT failed. "
			   "rc = 0x%lx, resp_len = %ld", rv, resp_len);
		return -EIO;
	}

	rc = ep11->dll_xcpa_internal_rv(resp, resp_len, &lrb, &rv);
	if (rc != 0) {
		pr_verbose(verbose, "Failed to parse response. rc = %d", rc);
		return -EIO;
	}

	if (rv != CKR_OK) {
		pr_verbose(verbose, "Failed to re-encrypt the EP11 secure key. "
			   "rc = 0x%lx", rv);
		switch (rv) {
		case CKR_IBM_WKID_MISMATCH:
			DEBUG("The EP11 secure key is currently encrypted "
			      "under a different master that does not match "
			      "the master key in the CURRENT master key "
			      "register of APQN %02X.%04X", card, domain);
			break;
		}
		return -EIO;
	}

	if (blob_len != lrb.pllen) {
		pr_verbose(verbose, "Re-encrypted EP11 secure key size has "
			   "changed: org-len: %lu, new-len: %lu", blob_len,
			   lrb.pllen);
		return -EIO;
	}

	memcpy(ep11key, lrb.payload, blob_len);

	return 0;
}

/**
 * Re-encipher an EP11 secure key with a new EP11 master key (wrapping key).
 *
 * @param[in] ep11      the EP11 library structure
 * @param[in] target    the target handle to use for the re-encipher operation
 * @param[in] card      the card that corresponds to the target handle
 * @param[in] domain    the domain that corresponds to the target handle
 * @param[in/out] secure_key the EP11 key token to reencipher. The re-enciphered
 *                      secure key will be returned in this buffer.
 * @param[in] secure_key_size the size of the secure key
 * @param[in] verbose   if true, verbose messages are printed
 *
 * @returns 0 on success, a negative errno in case of errors
 */
int reencipher_ep11_key(struct ep11_lib *ep11, target_t target,
			unsigned int card, unsigned int domain, u8 *secure_key,
			unsigned int secure_key_size, bool verbose)
{
	struct ep11keytoken *ep11key = (struct ep11keytoken *)secure_key;
	CK_IBM_DOMAIN_INFO dinf;
	CK_ULONG dinf_len = sizeof(dinf);
	CK_RV rv;
	int rc;

	util_assert(ep11 != NULL, "Internal error: ep11 is NULL");
	util_assert(secure_key != NULL, "Internal error: secure_key is NULL");

	if (ep11->dll_m_get_xcp_info == NULL) {
		pr_verbose(verbose, "EP11 host lib function m_get_xcp_info not "
			"available but required for EP11 EC key reencipher.");
		return -ELIBACC;
	}

	rv = ep11->dll_m_get_xcp_info(&dinf, &dinf_len, CK_IBM_XCPQ_DOMAIN, 0,
				      target);
	if (rv != CKR_OK) {
		pr_verbose(verbose, "Failed to query domain information for "
			   "%02X.%04X: m_get_xcp_info rc: 0x%lx", card, domain,
			   rv);
		return -EIO;
	}

	if ((dinf.flags & CK_IBM_DOM_COMMITTED_NWK) == 0) {
		DEBUG("The NEW master key register of APQN %02X.%04X is not "
		      "in COMMITTED state", card, domain);
		return -ENODEV;
	}

	rc = ep11_adm_reencrypt(ep11, target, card, domain, ep11key,
				secure_key_size, verbose);
	if (rc != 0)
		return rc;

	if (is_xts_key(secure_key, secure_key_size)) {
		secure_key += EP11_KEY_SIZE;
		secure_key_size -= EP11_KEY_SIZE;
		ep11key = (struct ep11keytoken *)secure_key;

		rc = ep11_adm_reencrypt(ep11, target, card, domain, ep11key,
					secure_key_size, verbose);
		if (rc != 0)
			return rc;
	}

	return 0;
}

/*
 * For importing keys we need to encrypt the keys. So build the blob by
 * m_UnwrapKey, use one wrap key for this purpose, can be any key,
 * we use an AES key
 */
CK_RV make_wrapblob(struct ep11_lib *ep11, target_t target)
{
	CK_MECHANISM mech = { CKM_AES_KEY_GEN, NULL, 0 };
	CK_BYTE csum[MAX_CSUMSIZE];
	size_t csum_len = sizeof(csum);
	CK_RV rv = 0;
	CK_BBOOL cktrue = CK_TRUE;
	CK_ULONG len = 32;
	CK_ATTRIBUTE wrap_tmpl[] = {
		{ CKA_VALUE_LEN, &len, sizeof(CK_ULONG) },
		{ CKA_WRAP, (void *) &cktrue, sizeof(cktrue) },
		{ CKA_UNWRAP, (void *) &cktrue, sizeof(cktrue) },
	};
	CK_ULONG wrap_tmpl_len = sizeof(wrap_tmpl) / sizeof(CK_ATTRIBUTE);

	if (ep11->dll_m_GenerateKey == NULL) {
		DEBUG("EP11 host lib function m_GenerateKey not available but "
			"required for creating the EP11 wrap blob.");
		return CKR_FUNCTION_NOT_SUPPORTED;
	}

	if (ep11->raw2key_wrap_blob_l != 0)
		return CKR_OK;

	ep11->raw2key_wrap_blob_l = sizeof(ep11->raw2key_wrap_blob);
	rv = ep11->dll_m_GenerateKey(&mech, wrap_tmpl, wrap_tmpl_len, NULL, 0,
			ep11->raw2key_wrap_blob, &ep11->raw2key_wrap_blob_l,
			csum, &csum_len, target);

	if (rv != CKR_OK) {
		ep11->raw2key_wrap_blob_l = 0;
		goto ret;
	}

	rv = CKR_OK;

ret:
	return rv;
}

/**
 * Translate key flags into ep11 key attributes and add the attributes to the
 * attrs in the array. *attrs_len specifies the number of already contained
 * attributes in the array.
 */
void ec_key_add_attrs_from_flags(unsigned int flags, CK_ATTRIBUTE attrs[],
						CK_ULONG *attrs_len, CK_BBOOL *cktrue)
{
	const size_t accepted_flags[] = {
		XCP_BLOB_MODIFIABLE, XCP_BLOB_RESTRICTABLE, XCP_BLOB_USE_AS_DATA,
		XCP_BLOB_WRAP, XCP_BLOB_TRUSTED, XCP_BLOB_WRAP_W_TRUSTED,
		XCP_BLOB_RETAINED
	};
	const CK_ULONG flag2attr[] = {
		CKA_MODIFIABLE, CKA_IBM_RESTRICTABLE, CKA_IBM_USE_AS_DATA,
		CKA_WRAP, CKA_TRUSTED, CKA_WRAP_WITH_TRUSTED,
		CKA_IBM_RETAINKEY
	};
	CK_ATTRIBUTE attr;
	size_t i, num_attrs = sizeof(flag2attr) / sizeof(CK_ULONG);

	if (flags == 0)
		return;

	attr.pValue = cktrue;
	attr.ulValueLen = sizeof(CK_BBOOL);

	for (i = 0; i < num_attrs; i++) {
		if (flags & accepted_flags[i]) {
			attr.type = flag2attr[i];
			memcpy(&attrs[*attrs_len], &attr, sizeof(CK_ATTRIBUTE));
			(*attrs_len)++;
		}
	}
}

/**
 * The ep11 host lib wants key material in ASN.1 form. We just need some
 * static ASN.1 encodings for EC public keys.
 */
void make_asn1_key_sequence(unsigned int curve,
					const unsigned char *pubkey, unsigned int publen,
					const unsigned char *privkey, unsigned int privlen,
					CK_BYTE *seq_buf, CK_ULONG *seq_len)
{
	asn1_p256_key_seq_t p256 = {
		.seq1 = ZPC_P256_KEY_SEQ1,
		.ec_pubkey = ZPC_EC_PUBKEY,
		.ec_params = ZPC_P256_PARAMS,
		.seq2 = ZPC_P256_KEY_SEQ2,
		.seq3 = ZPC_P256_KEY_SEQ3,
	};

	asn1_p384_key_seq_t p384 = {
		.seq1 = ZPC_P384_KEY_SEQ1,
		.ec_pubkey = ZPC_EC_PUBKEY,
		.ec_params = ZPC_P384_PARAMS,
		.seq2 = ZPC_P384_KEY_SEQ2,
		.seq3 = ZPC_P384_KEY_SEQ3,
	};

	asn1_p521_key_seq_t p521 = {
		.seq1 = ZPC_P521_KEY_SEQ1,
		.ec_pubkey = ZPC_EC_PUBKEY,
		.ec_params = ZPC_P521_PARAMS,
		.seq2 = ZPC_P521_KEY_SEQ2,
		.seq3 = ZPC_P521_KEY_SEQ3,
	};

	asn1_ed25519_key_seq_t ed25519 = {
		.seq1 = ZPC_ED25519_KEY_SEQ1,
		.ec_pubkey = ZPC_EC_PUBKEY,
		.ec_params = ZPC_ED25519_PARAMS,
		.seq2 = ZPC_ED25519_KEY_SEQ2,
		.seq3 = ZPC_ED25519_KEY_SEQ3,
	};

	asn1_ed448_key_seq_t ed448 = {
		.seq1 = ZPC_ED448_KEY_SEQ1,
		.ec_pubkey = ZPC_EC_PUBKEY,
		.ec_params = ZPC_ED448_PARAMS,
		.seq2 = ZPC_ED448_KEY_SEQ2,
		.seq3 = ZPC_ED448_KEY_SEQ3,
	};

	switch (curve) {
	case 0:
		memcpy(&p256.privkey, privkey, privlen);
		memcpy(&p256.pubkey, pubkey, publen);
		memcpy(seq_buf, &p256, sizeof(p256));
		*seq_len = sizeof(p256);
		break;
	case 1:
		memcpy(&p384.privkey, privkey, privlen);
		memcpy(&p384.pubkey, pubkey, publen);
		memcpy(seq_buf, &p384, sizeof(p384));
		*seq_len = sizeof(p384);
		break;
	case 2:
		memcpy(&p521.privkey, privkey, privlen);
		memcpy(&p521.pubkey, pubkey, publen);
		memcpy(seq_buf, &p521, sizeof(p521));
		*seq_len = sizeof(p521);
		break;
	case 3:
		memcpy(&ed25519.privkey, privkey, privlen);
		memcpy(&ed25519.pubkey, pubkey, publen);
		memcpy(seq_buf, &ed25519, sizeof(ed25519));
		*seq_len = sizeof(ed25519);
		break;
	case 4:
		memcpy(&ed448.privkey, privkey, privlen);
		memcpy(&ed448.pubkey, pubkey, publen);
		memcpy(seq_buf, &ed448, sizeof(ed448));
		*seq_len = sizeof(ed448);
		break;
	}
}

int ec_key_clr2sec_ep11(struct ep11_lib *ep11, unsigned int curve,
				unsigned int flags, unsigned char *secure_key, unsigned int *seclen,
				const unsigned char *pubkey, unsigned int publen,
				const unsigned char *privkey, unsigned int privlen,
				target_t target)
{
	CK_BYTE iv[PAES_BLOCK_SIZE], cipher[MAX_BLOBSIZE];
	CK_BYTE csum[MAX_BLOBSIZE], blob[MAX_BLOBSIZE];
	CK_MECHANISM mech_w = { CKM_AES_CBC_PAD, iv, PAES_BLOCK_SIZE };
	unsigned char *ep11_pin_blob = NULL;
	CK_ULONG ep11_pin_blob_len = 0, cipher_len = sizeof(cipher);
	CK_ULONG cslen = sizeof(csum), asn1_len;
	size_t blob_len = MAX_BLOBSIZE;
	CK_BYTE asn1_buf[1000];
	CK_RV rv;
	int rc, MAX_EP11_ATTRS = 10; /* below 3 defaults plus max 7 from flags */
	CK_ATTRIBUTE attrs[MAX_EP11_ATTRS];
	CK_ULONG attrs_len = 0;
	CK_ULONG keyType = CKK_EC;
	CK_BBOOL cktrue = CK_TRUE;
	CK_ATTRIBUTE default_attrs[] = {
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
		{ CKA_IBM_PROTKEY_EXTRACTABLE, &cktrue, sizeof(CK_BBOOL) },
		{ CKA_SIGN, &cktrue, sizeof(CK_BBOOL) },
	};
	struct ep11kblob_header *ep11hdr;

	if (ep11->dll_m_EncryptSingle == NULL || ep11->dll_m_UnwrapKey == NULL) {
		DEBUG("EP11 host lib function m_EncryptSingle and/or m_UnwrapKey "
			"not available but required for EP11 EC clear key import.");
		return -ELIBACC;
	}

	/* Create AES wrapping key */
	rv = make_wrapblob(ep11, target);
	if (rv != CKR_OK) {
		DEBUG("Could not create the wrap blob");
		goto ret;
	}

	/* Create ASN.1 key struct for m_EncryptSingle */
	make_asn1_key_sequence(curve, pubkey, publen, privkey, privlen,
						(CK_BYTE *)&asn1_buf, &asn1_len);

	/* Encrypt EC private key with AES wrapping key */
	rv = ep11->dll_m_EncryptSingle(ep11->raw2key_wrap_blob,
						ep11->raw2key_wrap_blob_l, &mech_w,
						(unsigned char *)asn1_buf, asn1_len,
						cipher, &cipher_len, target);
	if (rv != CKR_OK) {
		DEBUG("Error m_EncryptSingle, rv = 0x%lx", rv);
		goto ret;
	}

	/* Add default attributes */
	memcpy(attrs, &default_attrs, sizeof(default_attrs));
	attrs_len = sizeof(default_attrs) / sizeof(CK_ATTRIBUTE);

	/* Add user-defined flags, translated to attributes */
	ec_key_add_attrs_from_flags(flags, attrs, &attrs_len, &cktrue);

	/* Create the secure key blob */
	rv = ep11->dll_m_UnwrapKey(cipher, cipher_len, ep11->raw2key_wrap_blob,
			ep11->raw2key_wrap_blob_l, NULL, ~0, ep11_pin_blob,
			ep11_pin_blob_len, &mech_w, (CK_ATTRIBUTE *)&attrs, attrs_len,
			blob, &blob_len, csum, &cslen, target);
	if (rv != CKR_OK) {
		DEBUG("Error m_UnwrapKey, rv = 0x%lx", rv);
		goto ret;
	}

	/* Prepend an ep11kblob_header before the secure key blob as required by
	 * keytype PKEY_TYPE_EP11_ECC (= TOKVER_EP11_ECC_WITH_HEADER). */
	ep11hdr = (struct ep11kblob_header *)secure_key;
	ep11hdr->len = blob_len + sizeof(struct ep11kblob_header);
	ep11hdr->version = PKEY_TYPE_EP11_ECC;
	ep11hdr->bitlen = curve2bitlen[curve];

	/* Copy result */
	memcpy(secure_key + sizeof(struct ep11kblob_header), blob, blob_len);
	*seclen = blob_len + sizeof(struct ep11kblob_header);

	rv = CKR_OK;

ret:

	switch (rv) {
	case CKR_OK:
		rc = 0;
		break;
	default:
		rc = -EIO;
		break;
	}

	return rc;
}

/**
 * Extract the public key from given secure ECC key token. To obtain a public
 * key here, it must be contained in the token. The host lib does not
 * re-calculate a public key from given secure key.
 */
int ec_key_extract_public_ep11(struct ep11_lib *ep11, int curve,
				unsigned char *secure_key, unsigned int seclen,
				unsigned char *public_key, unsigned int *publen,
				unsigned char *spki, unsigned int *spkilen,
				target_t target)
{
	CK_RV rv;
	CK_BYTE temp[MAX_MACED_SPKI_SIZE] = { 0 };
	CK_ULONG temp_len = sizeof(temp);
	CK_ATTRIBUTE templ[] = {
		{ CKA_IBM_MACED_PUBLIC_KEY_INFO, &temp, temp_len },
	};
	int rc = -EIO;

	if (ep11->dll_m_GetAttributeValue == NULL) {
		DEBUG("EP11 host lib function m_GetAttributeValue not "
			"available but required for EP11 EC extract public key.");
		return -ELIBACC;
	}

	/* Note that the secure key is a TOKVER_EP11_ECC_WITH_HEADER and has a
	 * 16-byte ep11kblob_header prepended before the actual secure key blob.
	 * This header must not be passed to the ep11 library. */
	rv = ep11->dll_m_GetAttributeValue(secure_key + sizeof(struct ep11kblob_header),
								seclen - sizeof(struct ep11kblob_header),
								templ, 1, target);
	if (rv != CKR_OK) {
		DEBUG("Error m_GetAttributeValue, rv = 0x%lx", rv);
		goto ret;
	}

	if (templ[0].ulValueLen > MAX_MACED_SPKI_SIZE) {
		DEBUG("EP11 host lib function dll_m_GetAttributeValue returned an"
			"SPKI with %ld bytes. Cannot be handled.", templ[0].ulValueLen);
		goto ret;
	}

	memcpy(spki, temp, templ[0].ulValueLen);
	*spkilen = templ[0].ulValueLen;
	memcpy(public_key, temp + curve2puboffset[curve], curve2publen[curve]);
	*publen = curve2publen[curve];

	rc = 0;

ret:

	return rc;
}

int ec_key_generate_ep11(struct ep11_lib *ep11, int curve,
				unsigned int flags,
				unsigned char *secure_key, unsigned int *seclen,
				unsigned char *public_key, unsigned int *publen,
				unsigned char *spki, unsigned int *spkilen,
				target_t target)
{
	unsigned char *ep11_pin_blob = NULL;
	CK_ULONG ep11_pin_blob_len = 0;
	CK_MECHANISM mech = { CKM_EC_KEY_PAIR_GEN, NULL, 0 };
	CK_BYTE blob[MAX_BLOBSIZE];
	size_t blob_len = MAX_BLOBSIZE;
	unsigned char maced_spki[MAX_BLOBSIZE];
	unsigned long maced_spki_len = sizeof(maced_spki);
	int rc;
	CK_RV rv;
	CK_BYTE *q;
	size_t qlen;
	int MAX_EP11_ATTRS = 15;
	CK_ATTRIBUTE priv_attrs[MAX_EP11_ATTRS];
	CK_BBOOL cktrue = CK_TRUE;
	CK_ATTRIBUTE default_priv_attrs[] = {
		{CKA_IBM_PROTKEY_EXTRACTABLE, &cktrue, sizeof(cktrue)},
		{CKA_PRIVATE, &cktrue, sizeof(cktrue)},
		{CKA_SIGN, &cktrue, sizeof(cktrue)},
	};
	CK_ATTRIBUTE pub_attrs[] = {
		{ CKA_VERIFY, &cktrue, sizeof(cktrue) },
		{ CKA_EC_PARAMS, (unsigned char *)curve2spki_ec_params[curve],
				curve2spki_ec_params_len[curve] },
	};
	CK_ULONG pub_attrs_len = sizeof(pub_attrs) / sizeof(CK_ATTRIBUTE);
	CK_ULONG priv_attrs_len;
	struct ep11kblob_header *ep11hdr;

	if (ep11->dll_m_GenerateKeyPair == NULL) {
		DEBUG("EP11 host lib function m_GenerateKeyPair not "
			"available but required for EP11 EC key generate.");
		return -EIO;
	}

	/* Add default attributes */
	memcpy(&priv_attrs, &default_priv_attrs, sizeof(default_priv_attrs));
	priv_attrs_len = sizeof(default_priv_attrs) / sizeof(CK_ATTRIBUTE);

	/* Add user-defined flags, translated to attributes */
	ec_key_add_attrs_from_flags(flags, priv_attrs, &priv_attrs_len, &cktrue);

	/* Generate the secure key blob */
	rv = ep11->dll_m_GenerateKeyPair(&mech, pub_attrs, pub_attrs_len,
						priv_attrs, priv_attrs_len,
						ep11_pin_blob, ep11_pin_blob_len,
						blob, &blob_len,
						maced_spki, &maced_spki_len, target);
	if (rv != CKR_OK) {
		DEBUG("Error m_GenerateKeyPair, rv = 0x%lx", rv);
		rc = EIO;
		goto ret;
	}

	/* Get public key from spki */
	if (maced_spki_len > MAX_BLOBSIZE || blob_len > MAX_BLOBSIZE) {
		DEBUG("Invalid spki size from m_GenerateKeyPair: %ld bytes", maced_spki_len);
		rc = EIO;
		goto ret;
	}
	q = maced_spki + curve2puboffset[curve];
	qlen = curve2publen[curve];

	/* Copy public key and spki */
	memcpy(public_key, q, qlen);
	*publen = qlen;
	memcpy(spki, maced_spki, maced_spki_len);
	*spkilen = maced_spki_len;

	/* Copy secure key, which is of type TOKVER_EP11_ECC_WITH_HEADER. It has
	 * a 16-byte header prepended before the actual secure key blob. Refer
	 * to kernel zcrypt_ep11misc.h. Fill out this header in the key struct.
	 * This info is later needed for sec2prot. */
	memset(secure_key, 0, sizeof(struct ep11kblob_header));
	memcpy(secure_key + sizeof(struct ep11kblob_header), blob, blob_len);
	*seclen = blob_len + sizeof(struct ep11kblob_header);
	ep11hdr = (struct ep11kblob_header *)secure_key;
	ep11hdr->len = blob_len + sizeof(struct ep11kblob_header);
	ep11hdr->version = PKEY_TYPE_EP11_ECC;
	ep11hdr->bitlen = curve2bitlen[curve];

	rc = 0;

ret:
	return rc;
}

int ep11_get_raw_blob_length(const unsigned char *blob)
{
	struct ep11kblob_header *hdr = (struct ep11kblob_header *)blob;

	return hdr->len;
}

void ep11_make_spki(int curve, const unsigned char *pubkey, unsigned int publen,
			unsigned char *spki, unsigned int *spki_len)
{
	p256_maced_spki_t p256 = {
		.seq1 = ZPC_P256_SPKI_SEQ1,
		.ec_pubkey = ZPC_EC_PUBKEY,
		.ec_params = ZPC_P256_PARAMS,
		.seq2 = ZPC_P256_SPKI_SEQ2,
	};

	p384_maced_spki_t p384 = {
		.seq1 = ZPC_P384_SPKI_SEQ1,
		.ec_pubkey = ZPC_EC_PUBKEY,
		.ec_params = ZPC_P384_PARAMS,
		.seq2 = ZPC_P384_SPKI_SEQ2,
	};

	p521_maced_spki_t p521 = {
		.seq1 = ZPC_P521_SPKI_SEQ1,
		.ec_pubkey = ZPC_EC_PUBKEY,
		.ec_params = ZPC_P521_PARAMS,
		.seq2 = ZPC_P521_SPKI_SEQ2,
	};

	ed25519_maced_spki_t ed25519 = {
		.seq1 = ZPC_ED25519_SPKI_SEQ1,
		.ec_pubkey = ZPC_EC_PUBKEY,
		.ec_params = ZPC_ED25519_PARAMS,
		.seq2 = ZPC_ED25519_SPKI_SEQ2,
	};

	ed448_maced_spki_t ed448 = {
		.seq1 = ZPC_ED448_SPKI_SEQ1,
		.ec_pubkey = ZPC_EC_PUBKEY,
		.ec_params = ZPC_ED448_PARAMS,
		.seq2 = ZPC_ED448_SPKI_SEQ2,
	};

	switch (curve) {
	case 0:
		memcpy(&p256.pubkey, pubkey, publen);
		memcpy(spki, &p256, sizeof(p256));
		*spki_len = sizeof(p256) - EP11_SPKI_MACLEN;
		break;
	case 1:
		memcpy(&p384.pubkey, pubkey, publen);
		memcpy(spki, &p384, sizeof(p384));
		*spki_len = sizeof(p384) - EP11_SPKI_MACLEN;
		break;
	case 2:
		memcpy(&p521.pubkey, pubkey, publen);
		memcpy(spki, &p521, sizeof(p521));
		*spki_len = sizeof(p521) - EP11_SPKI_MACLEN;
		break;
	case 3:
		memcpy(&ed25519.pubkey, pubkey, publen);
		memcpy(spki, &ed25519, sizeof(ed25519));
		*spki_len = sizeof(ed25519) - EP11_SPKI_MACLEN;
		break;
	case 4:
		memcpy(&ed448.pubkey, pubkey, publen);
		memcpy(spki, &ed448, sizeof(ed448));
		*spki_len = sizeof(ed448) - EP11_SPKI_MACLEN;
		break;
	}
}

int ep11_make_maced_spki(struct ep11_lib *ep11,
					const CK_BYTE *spki, unsigned int spki_len,
					CK_BYTE *maced_spki, unsigned int *maced_spkilen,
					target_t target)
{
	CK_BYTE csum[MAX_BLOBSIZE];
	CK_MECHANISM mech = { CKM_IBM_TRANSPORTKEY, 0, 0 };
	unsigned char *ep11_pin_blob = NULL;
	CK_ULONG ep11_pin_blob_len = 0;
	CK_ULONG cslen = sizeof(csum);
	CK_OBJECT_CLASS class = CKO_PUBLIC_KEY;
	CK_ATTRIBUTE attrs[] = {
		{ CKA_CLASS, &class, sizeof(class) },
	};
	CK_ATTRIBUTE *p_attrs = (CK_ATTRIBUTE *)&attrs;
	CK_ULONG attrs_len = sizeof(attrs) / sizeof(CK_ATTRIBUTE);
	CK_ULONG ul_maced_spkilen = *maced_spkilen;
	CK_RV rv;
	int rc;

	if (spki == NULL || spki_len == 0)
		return 0;

	if (ep11->dll_m_UnwrapKey == NULL) {
		DEBUG("EP11 host lib function m_UnwrapKey not available but "
			"required for creating an EP11 MACed public key SPKI.");
		return -ELIBACC;
	}

	rv = ep11->dll_m_UnwrapKey(spki, spki_len, NULL, 0, NULL, 0,
							ep11_pin_blob, ep11_pin_blob_len, &mech,
							p_attrs, attrs_len, maced_spki,
							&ul_maced_spkilen, csum, &cslen, target);
	if (rv != CKR_OK) {
		DEBUG("Error m_UnwrapKey, rv = 0x%lx", rv);
		goto ret;
	}

	*maced_spkilen = ul_maced_spkilen;

	rv = CKR_OK;

ret:

	switch (rv) {
	case CKR_OK:
		rc = 0;
		break;
	default:
		rc = -EIO;
		break;
	}

	return rc;
}

/**
 * Check if the spki buffer contains an expected SPKI, which means it should
 * at least match with the curve of the key object.
 */
int ep11_spki_valid_for_curve(int curve, const unsigned char *spki, unsigned int len)
{
	/* This can be either a raw or a maced spki. */
	if (len < (curve2macedspkilen[curve] - EP11_SPKI_MACLEN) ||
		len > curve2macedspkilen[curve])
		return 0;

	/* Looks like length is ok, now check if static parts are as expected */
	if (memcmp(spki, curve2spki_seq1[curve], curve2spki_seq1_len[curve]) != 0 ||
		memcmp(spki + curve2spki_seq1_len[curve], ec_pubkey, ec_pubkey_len) != 0 ||
		memcmp(spki + curve2spki_seq1_len[curve] + ec_pubkey_len,
				curve2spki_ec_params[curve], curve2spki_ec_params_len[curve]) != 0)
		return 0;

	return 1;
}

int ep11_check_wk(struct ep11_lib *ep11, const unsigned char *wk_id,
				unsigned int wk_id_len, target_t target, bool verbose)
{
	CK_IBM_DOMAIN_INFO dinf;
	CK_ULONG dinf_len = sizeof(dinf);
	CK_RV rv;

	if (ep11->dll_m_get_xcp_info == NULL) {
		pr_verbose(verbose, "EP11 host lib function m_get_xcp_info not "
			"available but required for EP11 EC key reencipher.");
		return -ELIBACC;
	}

	rv = ep11->dll_m_get_xcp_info(&dinf, &dinf_len, CK_IBM_XCPQ_DOMAIN, 0,
								target);
	if (rv != CKR_OK) {
		pr_verbose(verbose, "Failed to query domain information "
			"m_get_xcp_info rc: 0x%lx", rv);
		return -EIO;
	}

	if (memcmp(wk_id, dinf.wk, wk_id_len) != 0)
		return -EIO;

	return 0;
}
