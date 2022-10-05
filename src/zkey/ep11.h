/*
 * zkey - Generate, re-encipher, and validate secure keys
 *
 * This header file defines the interface to the EP11 host library.
 *
 * Copyright IBM Corp. 2019
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef EP11_H
#define EP11_H

#include <stdint.h>
#include <stdbool.h>

#include "lib/zt_common.h"

/* EP11 definitions */

#define CKK_EC               0x00000003

#define MAX_CSUMSIZE         64
static const char wrap_key_name[] = "EP11_wrapkey";

#define CK_TRUE     1
#define CK_FALSE    0

typedef uint64_t		target_t;
typedef unsigned long int	CK_ULONG;
typedef CK_ULONG		CK_RV;
typedef unsigned char		CK_BYTE;
typedef CK_BYTE			CK_CHAR;
typedef CK_ULONG		*CK_ULONG_PTR;
typedef void			*CK_VOID_PTR;
typedef CK_BYTE			CK_BBOOL;

typedef CK_ULONG CK_ATTRIBUTE_TYPE;
typedef struct CK_ATTRIBUTE {
	CK_ATTRIBUTE_TYPE type;
	CK_VOID_PTR pValue;
	CK_ULONG ulValueLen; /* in bytes */
} CK_ATTRIBUTE;

#define CKA_TOKEN                              0x00000001
#define CKA_PRIVATE                            0x00000002
#define CKA_LABEL                              0x00000003
#define CKA_TRUSTED                            0x00000086
#define CKA_KEY_TYPE                           0x00000100
#define CKA_ENCRYPT                            0x00000104
#define CKA_DECRYPT                            0x00000105
#define CKA_WRAP                               0x00000106
#define CKA_UNWRAP                             0x00000107
#define CKA_SIGN                               0x00000108
#define CKA_VERIFY                             0x0000010A
#define CKA_VALUE_LEN                          0x00000161
#define CKA_EXTRACTABLE                        0x00000162
#define CKA_MODIFIABLE                         0x00000170
#define CKA_EC_PARAMS                          0x00000180
#define CKA_EC_POINT                           0x00000181
#define CKA_WRAP_WITH_TRUSTED                  0x00000210
#define CKA_VENDOR_DEFINED                     0x80000000
#define CKA_IBM_RESTRICTABLE                   (CKA_VENDOR_DEFINED +0x10001)
#define CKA_IBM_NEVER_MODIFIABLE               (CKA_VENDOR_DEFINED +0x10002)
#define CKA_IBM_RETAINKEY                      (CKA_VENDOR_DEFINED +0x10003)
#define CKA_IBM_ATTRBOUND                      (CKA_VENDOR_DEFINED +0x10004)
#define CKA_IBM_USE_AS_DATA                    (CKA_VENDOR_DEFINED +0x10008)
#define CKA_IBM_PROTKEY_EXTRACTABLE            (CKA_VENDOR_DEFINED +0x1000c)

/* Available with ep11 hostlib v4: */
#define CKA_IBM_MACED_PUBLIC_KEY_INFO          (CKA_VENDOR_DEFINED +0x20002)

typedef CK_ULONG CK_MECHANISM_TYPE;
typedef struct CK_MECHANISM {
	CK_MECHANISM_TYPE mechanism;
	CK_VOID_PTR pParameter;
	CK_ULONG ulParameterLen; /* in bytes */
} CK_MECHANISM;

#define CKM_EC_KEY_PAIR_GEN                    0x00001040
#define CKM_AES_CBC_PAD                        0x00001085
#define CKM_AES_KEY_GEN                        0x00001080
#define CKM_VENDOR_DEFINED                     0x80000000

typedef struct XCP_ModuleSocket {
	char		host[256 + 1];
	uint32_t	port;
} *XCP_ModuleSocket_t;

typedef struct XCP_DomainPerf {
	unsigned int	lastperf[256];
} *XCP_DomainPerf_t;

typedef struct XCP_Module {
	uint32_t	version;
	uint64_t	flags;
	uint32_t	domains;
	unsigned char	domainmask[256 / 8];
	struct XCP_ModuleSocket socket;
	uint32_t	module_nr;
	void		*mhandle;
	struct XCP_DomainPerf perf;
	/* -----  end of v1 fields  ----- */
	uint32_t	api;
	/* -----  end of v2 fields  ----- */
} *XCP_Module_t;

typedef enum {
	XCP_MFL_SOCKET       =    1,
	XCP_MFL_MODULE       =    2,
	XCP_MFL_MHANDLE      =    4,
	XCP_MFL_PERF         =    8,
	XCP_MFL_VIRTUAL      = 0x10,
	XCP_MFL_STRICT       = 0x20,
	XCP_MFL_PROBE        = 0x40,
	XCP_MFL_ALW_TGT_ADD  = 0x80,
	XCP_MFL_MAX          = 0xff
} XCP_Module_Flags;

#define XCP_MOD_VERSION_1	1
#define XCP_MOD_VERSION_2	2
#define XCP_TGT_INIT		~0UL

#define XCPTGTMASK_SET_DOM(mask, domain)      \
				mask[((domain)/8)] |=   (1 << (7-(domain)%8))

typedef enum {
	XCP_BLOB_EXTRACTABLE               = 1,
	XCP_BLOB_NEVER_EXTRACTABLE         = 2,
	XCP_BLOB_MODIFIABLE                = 4,
	XCP_BLOB_NEVER_MODIFIABLE          = 8,
	XCP_BLOB_RESTRICTABLE              = 0x10,
	XCP_BLOB_LOCAL                     = 0x20,
	XCP_BLOB_ATTRBOUND                 = 0x40,
	XCP_BLOB_USE_AS_DATA               = 0x80,
	XCP_BLOB_SIGN                      = 0x0100,
	XCP_BLOB_SIGN_RECOVER              = 0x0200,
	XCP_BLOB_DECRYPT                   = 0x0400,
	XCP_BLOB_ENCRYPT                   = 0x0800,
	XCP_BLOB_DERIVE                    = 0x1000,
	XCP_BLOB_UNWRAP                    = 0x2000,
	XCP_BLOB_WRAP                      = 0x4000,
	XCP_BLOB_VERIFY                    = 0x8000,
	XCP_BLOB_VERIFY_RECOVER            = 0x010000,
	XCP_BLOB_TRUSTED                   = 0x020000,
	XCP_BLOB_WRAP_W_TRUSTED            = 0x040000,
	XCP_BLOB_RETAINED                  = 0x080000,
	XCP_BLOB_ALWAYS_RETAINED           = 0x100000,
	XCP_BLOB_PROTKEY_EXTRACTABLE       = 0x200000,
	XCP_BLOB_PROTKEY_NEVER_EXTRACTABLE = 0x400000,
} XCP_Key_Flags;

#define XCP_SERIALNR_CHARS	8
#define XCP_ADMCTR_BYTES	((size_t) (128/8))
#define XCP_KEYCSUM_BYTES	(256/8)

#define XCP_ADM_REENCRYPT	25 /* transform blobs to next WK */

#define MAX_BLOBSIZE		8192

#define CKR_VENDOR_DEFINED	0x80000000
#define CKR_IBM_WKID_MISMATCH	CKR_VENDOR_DEFINED + 0x10001

typedef struct XCPadmresp {
	uint32_t	fn;
	uint32_t	domain;
	uint32_t	domainInst;

	/* module ID || module instance */
	unsigned char	module[XCP_SERIALNR_CHARS + XCP_SERIALNR_CHARS];
	unsigned char	modNr[XCP_SERIALNR_CHARS];
	unsigned char	modInst[XCP_SERIALNR_CHARS];

	unsigned char	tctr[XCP_ADMCTR_BYTES];  /* transaction counter */

	CK_RV		rv;
	uint32_t	reason;

	const unsigned char *payload;
	size_t		pllen;
} *XCPadmresp_t;

typedef struct CK_IBM_DOMAIN_INFO {
	CK_ULONG domain;
	CK_BYTE wk[XCP_KEYCSUM_BYTES];
	CK_BYTE nextwk[XCP_KEYCSUM_BYTES];
	CK_ULONG flags;
	CK_BYTE mode[8];
} CK_IBM_DOMAIN_INFO;

#define CK_IBM_DOM_COMMITTED_NWK	8

#define CK_IBM_XCPHQ_VERSION	0xff000001
#define CK_IBM_XCPQ_DOMAIN	3

#define MAX_APQN 256

typedef struct {
	short	format;
	short	length;
	short	apqns[2 * MAX_APQN];
} __packed ep11_target_t;

#define CKR_OK                               0x00000000
#define CKR_FUNCTION_NOT_SUPPORTED           0x00000054

typedef int (*m_init_t) (void);
typedef int (*m_add_module_t) (XCP_Module_t module, target_t *target);
typedef int (*m_rm_module_t) (XCP_Module_t module, target_t target);
typedef CK_RV (*m_get_xcp_info_t)(CK_VOID_PTR pinfo, CK_ULONG_PTR infbytes,
				  unsigned int query, unsigned int subquery,
				  target_t target);
typedef unsigned long int (*m_admin_t)(unsigned char *resp1, size_t *r1len,
				       unsigned char *resp2, size_t *r2len,
				       const unsigned char *cmd, size_t clen,
				       const unsigned char *sigs, size_t slen,
				       target_t target);
typedef long (*xcpa_cmdblock_t)(unsigned char *blk, size_t blen,
				unsigned int fn, const struct XCPadmresp *minf,
				const unsigned char *tctr,
				const unsigned char *payload, size_t plen);
typedef long (*xcpa_internal_rv_t)(const unsigned char *rsp, size_t rlen,
				   struct XCPadmresp *rspblk, CK_RV *rv);
typedef unsigned long int (*m_UnwrapKey_t)(const unsigned char *wrapped,
		CK_ULONG wlen, const unsigned char *kek, size_t keklen,
		const unsigned char *mackey, size_t mklen, const unsigned char *pin,
		size_t pinlen, const CK_MECHANISM *uwmech, const CK_ATTRIBUTE *ptempl,
		CK_ULONG pcount, unsigned char *unwrapped, size_t * uwlen,
		unsigned char *csum, CK_ULONG * cslen, target_t target);
typedef unsigned long int (*m_EncryptSingle_t)(const unsigned char *key,
		size_t klen, CK_MECHANISM *mech, unsigned char *plain, CK_ULONG plen,
		unsigned char *cipher, CK_ULONG_PTR clen, target_t target);
typedef unsigned long int (*m_GenerateKeyPair_t)(CK_MECHANISM *pmech,
		CK_ATTRIBUTE *ppublic, unsigned long pubattrs, CK_ATTRIBUTE *pprivate,
		unsigned long prvattrs, const unsigned char *pin, size_t pinlen,
		unsigned char *key, size_t * klen, unsigned char *pubkey,
		size_t * pklen, target_t target);
typedef unsigned long int (*m_GenerateKey_t)(CK_MECHANISM *pmech,
		CK_ATTRIBUTE *templ, CK_ULONG templcount, const unsigned char *pin,
		size_t pinlen, unsigned char *key, size_t * klen, unsigned char *csum,
		size_t * clen, target_t target);
typedef unsigned long int (*m_GetAttributeValue_t) (const unsigned char *blob,
		size_t bloblen, CK_ATTRIBUTE *templ, CK_ULONG templcount,
		target_t target);

struct ep11_version {
	unsigned int	minor;
	unsigned int	major;
};

struct ep11_lib {
	void *lib_ep11;
	m_init_t dll_m_init;
	m_add_module_t dll_m_add_module;
	m_rm_module_t dll_m_rm_module;
	m_get_xcp_info_t dll_m_get_xcp_info;
	m_admin_t dll_m_admin;
	xcpa_cmdblock_t dll_xcpa_cmdblock;
	xcpa_internal_rv_t dll_xcpa_internal_rv;
	m_UnwrapKey_t dll_m_UnwrapKey;
	m_EncryptSingle_t dll_m_EncryptSingle;
	m_GenerateKeyPair_t dll_m_GenerateKeyPair;
	m_GenerateKey_t dll_m_GenerateKey;
	m_GetAttributeValue_t dll_m_GetAttributeValue;
	struct ep11_version version;
	CK_BYTE raw2key_wrap_blob[MAX_BLOBSIZE];
	size_t raw2key_wrap_blob_l;
};

/*
 * ASN.1 sequence constants
 */
#define ZPC_P256_PARAMS         {0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07}
#define ZPC_P384_PARAMS         {0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22}
#define ZPC_P521_PARAMS         {0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x23}
#define ZPC_ED25519_PARAMS      {0x06, 0x03, 0x2B, 0x65, 0x70}
#define ZPC_ED448_PARAMS        {0x06, 0x03, 0x2B, 0x65, 0x71}

#define ZPC_EC_PUBKEY           {0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01}

#define ZPC_P256_KEY_SEQ1       {0x30, 0x81, 0x87, 0x02, 0x01, 0x00, 0x30, 0x13}
#define ZPC_P384_KEY_SEQ1       {0x30, 0x81, 0xB6, 0x02, 0x01, 0x00, 0x30, 0x10}
#define ZPC_P521_KEY_SEQ1       {0x30, 0x81, 0xEE, 0x02, 0x01, 0x00, 0x30, 0x10}
#define ZPC_ED25519_KEY_SEQ1    {0x30, 0x61, 0x02, 0x01, 0x00, 0x30, 0x0E}
#define ZPC_ED448_KEY_SEQ1      {0x30, 0x81, 0x93, 0x02, 0x01, 0x00, 0x30, 0x0E}

#define ZPC_P256_KEY_SEQ2       {0x04, 0x6D, 0x30, 0x6B, 0x02, 0x01, 0x01, 0x04, 0x20}
#define ZPC_P384_KEY_SEQ2       {0x04, 0x81, 0x9E, 0x30, 0x81, 0x9B, 0x02, 0x01, 0x01, 0x04, 0x30}
#define ZPC_P521_KEY_SEQ2       {0x04, 0x81, 0xD6, 0x30, 0x81, 0xD3, 0x02, 0x01, 0x01, 0x04, 0x42}
#define ZPC_ED25519_KEY_SEQ2    {0x04, 0x4C, 0x30, 0x4A, 0x02, 0x01, 0x01, 0x04, 0x20}
#define ZPC_ED448_KEY_SEQ2      {0x04, 0x7E, 0x30, 0x7C, 0x02, 0x01, 0x01, 0x04, 0x39}

#define ZPC_P256_KEY_SEQ3       {0xA1, 0x44, 0x03, 0x42, 0x00, 0x04}
#define ZPC_P384_KEY_SEQ3       {0xA1, 0x64, 0x03, 0x62, 0x00, 0x04}
#define ZPC_P521_KEY_SEQ3       {0xA1, 0x81, 0x89, 0x03, 0x81, 0x86, 0x00, 0x04}
#define ZPC_ED25519_KEY_SEQ3    {0xA1, 0x23, 0x03, 0x21, 0x00}
#define ZPC_ED448_KEY_SEQ3      {0xA1, 0x3C, 0x03, 0x3A, 0x00}

/**
 * SEQUENCE (2 elem)
 *   SEQUENCE (2 elem)
 *     OBJECT IDENTIFIER 1.2.840.10045.2.1 ecPublicKey (ANSI X9.62 public key type)
 *     OBJECT IDENTIFIER 1.2.840.10045.3.1.7 prime256v1 (ANSI X9.62 named elliptic curve)
 *   BIT STRING (520 bit) ...
 */
typedef struct {
	CK_BYTE seq1[8];
	CK_BYTE ec_pubkey[9];
	CK_BYTE ec_params[10];
	CK_BYTE seq2[9];
	CK_BYTE privkey[32];
	CK_BYTE seq3[6];
	CK_BYTE pubkey[64];
} __attribute__((packed)) asn1_p256_key_seq_t;

/**
 * SEQUENCE (2 elem)
 *   SEQUENCE (2 elem)
 *     OBJECT IDENTIFIER 1.2.840.10045.2.1 ecPublicKey (ANSI X9.62 public key type)
 *     OBJECT IDENTIFIER 1.3.132.0.34 secp384r1 (SECG (Certicom) named elliptic curve)
 *   BIT STRING (776 bit) ...
 */
typedef struct {
	CK_BYTE seq1[8];
	CK_BYTE ec_pubkey[9];
	CK_BYTE ec_params[7];
	CK_BYTE seq2[11];
	CK_BYTE privkey[48];
	CK_BYTE seq3[6];
	CK_BYTE pubkey[96];
} __attribute__((packed)) asn1_p384_key_seq_t;

/**
 * SEQUENCE (2 elem)
 *   SEQUENCE (2 elem)
 *     OBJECT IDENTIFIER 1.2.840.10045.2.1 ecPublicKey (ANSI X9.62 public key type)
 *     OBJECT IDENTIFIER 1.3.132.0.35 secp521r1 (SECG (Certicom) named elliptic curve)
 *   BIT STRING (1064 bit) ...
 */
typedef struct {
	CK_BYTE seq1[8];
	CK_BYTE ec_pubkey[9];
	CK_BYTE ec_params[7];
	CK_BYTE seq2[11];
	CK_BYTE privkey[66];
	CK_BYTE seq3[8];
	CK_BYTE pubkey[132];
} __attribute__((packed)) asn1_p521_key_seq_t;

/**
 * SEQUENCE (2 elem)
 *   SEQUENCE (2 elem)
 *     OBJECT IDENTIFIER 1.2.840.10045.2.1 ecPublicKey (ANSI X9.62 public key type)
 *     OBJECT IDENTIFIER 1.3.101.112 curveEd25519 (EdDSA 25519 signature algorithm)
 *   BIT STRING (256 bit) ...
 */
typedef struct {
	CK_BYTE seq1[7];
	CK_BYTE ec_pubkey[9];
	CK_BYTE ec_params[5];
	CK_BYTE seq2[9];
	CK_BYTE privkey[32];
	CK_BYTE seq3[5];
	CK_BYTE pubkey[32];
} __attribute__((packed)) asn1_ed25519_key_seq_t;

/**
 * SEQUENCE (2 elem)
 *   SEQUENCE (2 elem)
 *     OBJECT IDENTIFIER 1.2.840.10045.2.1 ecPublicKey (ANSI X9.62 public key type)
 *     OBJECT IDENTIFIER 1.3.101.113 curveEd448 (EdDSA 448 signature algorithm)
 *   BIT STRING (456 bit) ...
 */
typedef struct {
	CK_BYTE seq1[8];
	CK_BYTE ec_pubkey[9];
	CK_BYTE ec_params[5];
	CK_BYTE seq2[9];
	CK_BYTE privkey[57];
	CK_BYTE seq3[5];
	CK_BYTE pubkey[57];
} __attribute__((packed)) asn1_ed448_key_seq_t;

int load_ep11_library(struct ep11_lib *ep11, bool verbose);

int get_ep11_target_for_apqn(struct ep11_lib *ep11, unsigned int card,
			     unsigned int domain, target_t *target,
			     bool verbose);

void free_ep11_target_for_apqn(struct ep11_lib *ep11, target_t target);

int reencipher_ep11_key(struct ep11_lib *ep11, target_t target,
			unsigned int card, unsigned int domain, u8 *secure_key,
			unsigned int secure_key_size, bool verbose);

int ec_key_clr2sec_ep11(struct ep11_lib *ep11, unsigned int curve,
			unsigned int flags, unsigned char *sec, unsigned int *seclen,
			const unsigned char *pubkey, unsigned int publen,
			const unsigned char *privkey, unsigned int privlen,
			target_t target);

int ec_key_extract_public_ep11(struct ep11_lib *ep11, int curve,
			unsigned char *ecc_token, unsigned int ecc_token_len,
			unsigned char *ecc_pub_token, unsigned int *p_ecc_pub_token_len,
			target_t target);

int ec_key_generate_ep11(struct ep11_lib *ep11, int curve, unsigned int flags,
			unsigned char *secure_key, unsigned int *seclen,
			unsigned char *public_key, unsigned int *publen,
			target_t target);
#endif
