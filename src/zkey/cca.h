/*
 * zkey - Generate, re-encipher, and validate secure keys
 *
 * This header file defines the interface to the CCA host library.
 *
 * Copyright IBM Corp. 2019
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef CCA_H
#define CCA_H

#include <stdbool.h>

#include "lib/zt_common.h"

/* CCA library constants */
#define CCA_PRIVATE_KEY_NAME_SIZE       64
#define CCA_KEY_TOKEN_SIZE              3500
#define CCA_TRANSPORT_KEY_SIZE          1024
#define CCA_EC_KEY_VALUE_STRUCT_SIZE    207
#define CCA_KEYWORD_SIZE                8
#define CCA_RULE_ARRAY_SIZE             256
#define CCA_KEY_ID_SIZE                 64
#define CCA_EC_HEADER_SIZE              8

#define CCA_EC_CURVE_TYPE_PRIME         0
#define CCA_EC_CURVE_TYPE_EDWARDS       2

#define METHOD_OLD_TO_CURRENT	"RTCMK   "
#define METHOD_CURRENT_TO_NEW	"RTNMK   "

/*
 * ECC private key section (X'20'), Key-usage and translation control flag.
 */
typedef enum {
	CCA_XPRTCPAC                  = 0x01,
} ECC_Key_Flags;

typedef void (*t_CSNBKTC)(long *return_code,
			  long *reason_code,
			  long *exit_data_length,
			  unsigned char *exit_data,
			  long *rule_array_count,
			  unsigned char *rule_array,
			  unsigned char *key_identifier);

typedef void (*t_CSNBKTC2)(long *return_code,
			  long *reason_code,
			  long *exit_data_length,
			  unsigned char *exit_data,
			  long *rule_array_count,
			  unsigned char *rule_array,
			  long *key_identifier_length,
			  unsigned char *key_identifier);

typedef void (*t_CSUACFV)(long *return_code,
			  long *reason_code,
			  long *exit_data_length,
			  unsigned char *exit_data,
			  long *version_data_length,
			  unsigned char *version_data);

typedef void (*t_CSUACFQ)(long *return_code,
			  long *reason_code,
			  long *exit_data_length,
			  unsigned char *exit_data,
			  long *rule_array_count,
			  unsigned char *rule_array,
			  long *verb_data_length,
			  unsigned char *verb_data);

typedef void (*t_CSUACRA)(long *return_code,
			  long *reason_code,
			  long *exit_data_length,
			  unsigned char *exit_data,
			  long *rule_array_count,
			  unsigned char *rule_array,
			  long *ressource_name_length,
			  unsigned char *ressource_name);

typedef void (*t_CSUACRD)(long *return_code,
			  long *reason_code,
			  long *exit_data_length,
			  unsigned char *exit_data,
			  long *rule_array_count,
			  unsigned char *rule_array,
			  long *ressource_name_length,
			  unsigned char *ressource_name);

typedef void (*t_CSNBKTB2)(long *return_code,
			   long *reason_code,
			   long *exit_data_length,
			   unsigned char *exit_data,
			   long *rule_array_count,
			   unsigned char *rule_array,
			   long *clear_key_bit_length,
			   unsigned char *clear_key_value,
			   long *key_name_length,
			   unsigned char *key_name,
			   long *user_associated_data_length,
			   unsigned char *user_associated_data,
			   long *token_data_length,
			   unsigned char *token_data,
			   long *verb_data_length,
			   unsigned char *verb_data,
			   long *target_key_token_length,
			   unsigned char *target_key_token);

typedef void (*t_CSNBKTR2)(long *return_code,
			   long *reason_code,
			   long *exit_data_length,
			   unsigned char *exit_data,
			   long *rule_array_count,
			   unsigned char *rule_array,
			   long *input_key_token_length,
			   unsigned char *input_key_token,
			   long *input_KEK_key_identifier_length,
			   unsigned char *input_KEK_key_identifier,
			   long *output_KEK_key_identifier_length,
			   unsigned char *output_KEK_key_identifier,
			   long *output_key_token_length,
			   unsigned char *output_key_token);

typedef void (*t_CSNBRKA)(long *return_code,
			  long *reason_code,
			  long *exit_data_length,
			  unsigned char *exit_data,
			  long *rule_array_count,
			  unsigned char *rule_array,
			  long *key_identifier_length,
			  unsigned char *key_identifier,
			  long *ey_encrypting_key_identifier_length,
			  unsigned char *ey_encrypting_key_identifier,
			  long *opt_parameter1_length,
			  unsigned char *opt_parameter1,
			  long *opt_parameter2_length,
			  unsigned char *opt_parameter2);

typedef void (*t_CSNDPKB) (long *return_code,
		long *reason_code,
		long *exit_data_length,
		unsigned char *exit_data,
		long *rule_array_count,
		unsigned char *rule_array,
		long *kvs_len,
		unsigned char *kvs,
		long *key_name_len,
		unsigned char *key_name,
		long *rlen1,
		unsigned char *r1,
		long *rlen2,
		unsigned char *r2,
		long *rlen3,
		unsigned char *r3,
		long *rlen4,
		unsigned char *r4,
		long *rlen5,
		unsigned char *r5,
		long *skel_token_len,
		unsigned char *skel_token);

typedef void (*t_CSNDPKG) (long *return_code,
		long *reason_code,
		long *exit_data_length,
		unsigned char *exit_data,
		long *rule_array_count,
		unsigned char *rule_array,
		long *regen_data_len,
		unsigned char *regen_data,
		long *skel_token_len,
		unsigned char *kel_token,
		unsigned char *trans_key,
		long *ecc_token_len,
		unsigned char *sec_key);

typedef void (*t_CSNDPKX) (long *return_code,
		long *reason_code,
		long *exit_data_length,
		unsigned char *exit_data,
		long *rule_array_count,
		unsigned char *rule_array,
		long *ecc_token_len,
		unsigned char *ecc_token,
		long *ecc_pub_token_len,
		unsigned char *ecc_pub_token);

typedef void (*t_CSNDPKI) (long *return_code,
		long *reason_code,
		long *exit_data_length,
		unsigned char *exit_data,
		long *rule_array_count,
		unsigned char *rule_array,
		long *key_token_length,
		unsigned char *key_token,
		unsigned char *transport_key_identifier,
		long *target_key_token_length,
		unsigned char *target_key_token);

typedef void (*t_CSNDKTC) (long *return_code,
		long *reason_code,
		long *exit_data_length,
		unsigned char *exit_data,
		long *rule_array_count,
		unsigned char *rule_array,
		long *key_identifier_length,
		unsigned char *key_identifier);

struct cca_version {
	unsigned int ver;
	unsigned int rel;
	unsigned int mod;
};

struct cca_lib {
	void *lib_csulcca;
	t_CSNBKTC dll_CSNBKTC;
	t_CSNBKTC2 dll_CSNBKTC2;
	t_CSUACFV dll_CSUACFV;
	t_CSUACFQ dll_CSUACFQ;
	t_CSUACRA dll_CSUACRA;
	t_CSUACRD dll_CSUACRD;
	t_CSNBKTB2 dll_CSNBKTB2;
	t_CSNBKTR2 dll_CSNBKTR2;
	t_CSNBRKA dll_CSNBRKA;
	t_CSNDPKB dll_CSNDPKB;
	t_CSNDPKG dll_CSNDPKG;
	t_CSNDPKX dll_CSNDPKX;
	t_CSNDPKI dll_CSNDPKI;
	t_CSNDKTC dll_CSNDKTC;
	struct cca_version version;
};

/*
 * Refer to CCA Programmer's Guide, PKA Key Token Build
 * Key value structure elements, ECC keys
 */
typedef struct {
	u8 curve_type; /* 00 = prime, 02 = edwards */
	u8 reserved;
	u16 p_bitlen;
	u16 d_length;
	u16 q_length;
	// followed by d || q
}__attribute__((packed)) ECC_PAIR;

int load_cca_library(struct cca_lib *cca, bool verbose);

int key_token_change(struct cca_lib *cca,
		     u8 *secure_key, unsigned int secure_key_size,
		     char *method, bool verbose);

int select_cca_adapter(struct cca_lib *cca, unsigned int card,
		       unsigned int domain, bool verbose);

#define FLAG_SEL_CCA_MATCH_CUR_MKVP	0x01
#define FLAG_SEL_CCA_MATCH_OLD_MKVP	0x02
#define FLAG_SEL_CCA_NEW_MUST_BE_SET	0x80

int select_cca_adapter_by_mkvp(struct cca_lib *cca, u8 *mkvp, const char *apqns,
			       unsigned int flags, bool verbose);

void print_msg_for_cca_envvars(const char *key_name);

int convert_aes_data_to_cipher_key(struct cca_lib *cca,
				   u8 *input_key, unsigned int input_key_size,
				   u8 *output_key,
				   unsigned int *output_key_size,
				   bool verbose);

int restrict_key_export(struct cca_lib *cca, u8 *secure_key,
			unsigned int secure_key_size, bool verbose);

int ec_key_generate_cca(struct cca_lib *cca, int curve, unsigned int flags,
			unsigned char *secure_key, unsigned int *seclen,
			unsigned char *public_key, unsigned int *publen,
			bool verbose);

int ec_key_extract_public_cca(struct cca_lib *cca, unsigned char *ecc_token,
			unsigned int ecc_token_len, unsigned char *ecc_pub_token,
			unsigned int *p_ecc_pub_token_len, bool verbose);

int ec_key_clr2sec_cca(struct cca_lib *cca, int curve, unsigned int flags,
			unsigned char *secure_key, unsigned int *seclen,
			const unsigned char *pubkey, unsigned int publen,
			const unsigned char *privkey, unsigned int privlen,
			bool verbose);

#endif
