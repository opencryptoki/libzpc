/*
 * zkey - Generate, re-encipher, and validate secure keys
 *
 * This header file defines the interface to the pkey kernel module.
 * It defines a set of IOCTL commands with its associated structures.
 *
 * Copyright IBM Corp. 2017, 2018
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef PKEY_H
#define PKEY_H

#include <stdbool.h>

#include "lib/zt_common.h"

#include "cca.h"
#include "ep11.h"

#define SYSFS_DEVICES_AP            "/sys/devices/ap/"

/*
 * Definitions for the /dev/pkey kernel module interface
 */

struct tokenheader {
	u8  type;
	u8  res0[3];
	u8  version;
	u8  res1[3];
} __packed;

#define TOKEN_TYPE_NON_CCA		0x00
#define TOKEN_TYPE_CCA_INTERNAL		0x01

/* CCA-Internal token versions */
#define TOKEN_VERSION_AESDATA		0x04
#define TOKEN_VERSION_AESCIPHER		0x05

/* Non-CCA token versions */
#define TOKEN_VERSION_PROTECTED_KEY	0x01
#define TOKEN_VERSION_CLEAR_KEY		0x02
#define TOKEN_VERSION_EP11_AES		0x03

/* Some ECC related constants */
#define EC_PUBLEN_P256                   64
#define EC_PUBLEN_P384                   96
#define EC_PUBLEN_P521                  132
#define EC_PUBLEN_ED25519                32
#define EC_PUBLEN_ED448                  57

#define EC_PRIVLEN_P256                  32
#define EC_PRIVLEN_P384                  48
#define EC_PRIVLEN_P521                  66
#define EC_PRIVLEN_ED25519               32
#define EC_PRIVLEN_ED448                 57

#define EC_BITLEN_P256                  256
#define EC_BITLEN_P384                  384
#define EC_BITLEN_P521                  521
#define EC_BITLEN_ED25519               255
#define EC_BITLEN_ED448                 448

#define EC_SIGLEN_P256                   64
#define EC_SIGLEN_P384                   96
#define EC_SIGLEN_P521                  132
#define EC_SIGLEN_ED25519                64
#define EC_SIGLEN_ED448                 114

#define MKVP_LEN_EP11                    16
#define MKVP_LEN_CCA                      8

struct aesdatakeytoken {
	u8  type;     /* TOKEN_TYPE_INTERNAL (0x01) for internal key token */
	u8  res0[3];
	u8  version;  /* should be TOKEN_VERSION_AESDATA (0x04) */
	u8  res1[1];
	u8  flag;     /* key flags */
	u8  res2[1];
	u64 mkvp;     /* master key verification pattern */
	u8  key[32];  /* key value (encrypted) */
	u8  cv[8];    /* control vector */
	u16 bitsize;  /* key bit size */
	u16 keysize;  /* key byte size */
	u8  tvv[4];   /* token validation value */
} __packed;

struct aescipherkeytoken {
	u8  type;     /* TOKEN_TYPE_INTERNAL (0x01) for internal key token */
	u8  res0;
	u16 length;   /* length of token */
	u8  version;  /* should be TOKEN_VERSION_CIPHER (0x05) */
	u8  res1[3];
	u8  kms;      /* key material state, should be 0x03 */
	u8  kvptype;  /* key verification pattern type */
	u8  kvp[16];  /* key verification pattern */
	u8  kwm;      /* key wrapping method, should be 0x02 */
	u8  kwh;      /* key wrapping hash algorithm */
	u8  pfv;      /* payload format version, should be 0x00*/
	u8  res2;
	u8  adv;      /* associated data section version */
	u8  res3;
	u16 adl;      /* associated data length */
	u8  kll;      /* length of optional key label */
	u8  eadl;     /* extended associated data length */
	u8  uadl;     /* user associated data length */
	u8  res4;
	u16 pl;       /* payload bit length */
	u8  res5;
	u8  at;       /* algorithm type, should be 0x02 (AES) */
	u16 kt;       /* key type, should be 0x0001 (CIPHER) */
	u8  kufc;     /* key usage field count */
	u16 kuf1;     /* key usage field 1 */
	u16 kuf2;     /* key usage field 2 */
	u8  kmfc;     /* key management field count */
	u16 kmf1;     /* key management field 1 */
	u16 kmf2;     /* key management field 2 */
	u16 kmf3;     /* key management field 3 */
	u8  varpart[80]; /* variable part */
} __packed;

struct ccakeytoken {
	u8  type; /* TOKEN_TYPE_INTERNAL (0x1F) for internal key token */
	u8  version;
	u16 length;
	u32 reserved1;
	u8  privtok; /* CCA private key token: 0x20 */
	u8  priv_tok_version;
	u16 priv_tok_len;
	u8  aeskw; /* secure key: AESKW */
	u8  data_sec_hash; /* data section hash */
	u16 reserved2;
	u8  keyusage;
	u8  curve_type;
	u8  key_format; /* 0x08 = encrypted internal EC key */
	u8  section_version;
	u16 p_len;
	u16 associated_data_len1;
	u8  mkvp[MKVP_LEN_CCA];
	u8  opk[48]; /* Object Protection Key (OPK) */
	u16 associated_data_len2;
	u16 formatted_section_len;
	u8  associated_data_version;
	u8  key_label_len;
	u16 associated_data_len3;
	u16 ext_associated_data_len;
	u8  user_definable_data_len;
	u8 curve_type2;
	u16 p_len2;
	u8 key_usage_flag;
	u8 key_format_flag;
	u8 ad_section_version;
	u8 reserved3[3];
	u8 encr_d[0];
	/* followed by encrypted (D) */
} __packed;

struct eccpubtoken {
	u8 id; /* 0x21 = public section */
	u8 version;
	u16 length;
	u32 reserved1;
	u8 curve_type;
	u8 reserved2;
	u16 p_bitlen;
	u16 q_len;
	u8 q[0];
	/* followed by variable length q, max 133 bytes */
} __packed;

#define EP11_STRUCT_MAGIC        0x1234

/*
 * Internal used values for the version field of the key header.
 * Should match to the enum pkey_key_type in pkey.h.
 */
#define TOKVER_EP11_AES                 0x03 /* EP11 AES key blob (old style) */
#define TOKVER_EP11_AES_WITH_HEADER     0x06 /* EP11 AES key blob with hdr */
#define TOKVER_EP11_ECC_WITH_HEADER     0x07 /* EP11 ECC key blob with hdr */
/* 0x08 is reserved for internal use */
#define TOKVER_UV_SECRET                0x09 /* UV retrievable secret */

struct ep11keytoken {
	union {
		u8 session[32];
		struct {
			u8  type;      /* TOKEN_TYPE_NON_CCA (0x00) */
			u8  res0;      /* unused */
			u16 length;    /* length of token */
			u8  version;   /* TOKEN_VERSION_EP11_AES (0x03) */
			u8  res1;      /* unused */
			u16 keybitlen; /* clear key bit len, 0 for unknown */
		} head;
	};
	u8  wkvp[MKVP_LEN_EP11]; /* wrapping key verification pattern */
	u64 attr;     /* boolean key attributes */
	u64 mode;     /* mode bits */
	u16 version;  /* 0x1234, ep11 blob struct version */
	u8  iv[14];
	u8  encrypted_key_data[144];
	u8  mac[32];
	u8  padding[64];
} __packed;

#define AESDATA_KEY_SIZE	sizeof(struct aesdatakeytoken)
#define AESCIPHER_KEY_SIZE	sizeof(struct aescipherkeytoken)
#define EP11_KEY_SIZE		sizeof(struct ep11keytoken)

#define UV_SECRET_ID_LEN            32

/* Inside view of an UV retrievable secret key token */
struct uvrsecrettoken {
	u8 type; /* 0x00 - Non-CCA key token */
	u8 res0[3];
	u8 version; /* 0x09 - UV retrievable secret */
	u8 res1[3];
	u16 secret_type; /* the secret type as the UV told us */
	u16 secret_len; /* length in bytes of the secret */
	u8 secret_id[UV_SECRET_ID_LEN]; /* the secret id for this secret */
} __packed;

/*
 * CCA Application Programmer's Guide, AES CIPHER variable-length symmetric
 * key token:
 *   - Encrypted V0 payload: 120 bytes
 *   - Encrypted V1 payload: 136 bytes
 */
#define AESCIPHER_KEY_SIZE_ENCR_V0		AESCIPHER_KEY_SIZE - 16
#define AESCIPHER_KEY_SIZE_ENCR_V1		AESCIPHER_KEY_SIZE

/* MAX/MIN from zt_common.h produces warnings for variable length arrays */
#define _MIN(a, b)  ((a) < (b) ? (a) : (b))
#define _MAX(a, b)  ((a) > (b) ? (a) : (b))

#define MIN_EC_BLOB_SIZE		_MIN(sizeof(struct ccakeytoken), \
									sizeof(struct ep11keytoken))
#define MAX_EC_BLOB_SIZE		2048

#define MAX_SECURE_KEY_SIZE	_MAX(EP11_KEY_SIZE, \
			_MAX(AESDATA_KEY_SIZE, _MAX(AESCIPHER_KEY_SIZE, UV_SECRET_ID_LEN)))

#define MIN_SECURE_KEY_SIZE	_MIN(EP11_KEY_SIZE, \
			_MIN(AESDATA_KEY_SIZE, _MAX(AESCIPHER_KEY_SIZE, UV_SECRET_ID_LEN)))

#define MAXPROTKEYSIZE	64	/* a protected key blob may be up to 64 bytes */

/* Struct to hold protected AES key and length info */
struct pkey_protkey {
	u32 type;	 /* key type, one of the PKEY_KEYTYPE_AES values */
	u32 len;		/* bytes actually stored in protkey[]	 */
	u8  protkey[MAXPROTKEYSIZE];	       /* the protected key blob */
};

#define MAXECPROTKEYSIZE	112	/* max 80 + 32 bytes for p521 */

struct pkey_ecprotkey {
	u8  protkey[MAXECPROTKEYSIZE]; /* the EC protected key blob */
};

#define MAX_MACED_SPKI_SIZE	sizeof(p521_maced_spki_t)

struct pkey_ecpubkey {
	u32 publen;
	u8  pubkey[132]; /* max (66,66) for p521 public key (X,Y) value */
	u32 spkilen;
	u8  spki[MAX_MACED_SPKI_SIZE];
};

struct pkey_seckey {
	u8  seckey[AESDATA_KEY_SIZE];  /* the secure key blob */
};

struct pkey_clrkey {
	u8  clrkey[32]; /* 16, 24, or 32 byte clear key value */
};

#define MAXHMACPROTKEYSIZE        160

struct hmac_protkey {
	u32 type; /* key type, one of the PKEY_KEYTYPE_HMAC values */
	u32 len; /* bytes actually stored in protkey[] */
	u8  protkey[MAXHMACPROTKEYSIZE]; /* the protected key blob */
};

struct hmac_genprotk {
	u32 keytype; /* in: key type to generate */
	struct hmac_protkey protkey; /* out: the generated protkey */
};

#define PKEY_IOCTL_MAGIC	'p'
#define AUTOSELECT		0xFFFF
#define PKEYDEVICE		"/dev/pkey"
#define PKEY_KEYTYPE_AES_128	1
#define PKEY_KEYTYPE_AES_192	2
#define PKEY_KEYTYPE_AES_256	3
#define PKEY_KEYTYPE_ECC		4
#define PKEY_KEYTYPE_ECC_P256         5
#define PKEY_KEYTYPE_ECC_P384         6
#define PKEY_KEYTYPE_ECC_P521         7
#define PKEY_KEYTYPE_ECC_ED25519      8
#define PKEY_KEYTYPE_ECC_ED448        9
#define PKEY_KEYTYPE_HMAC_512         12
#define PKEY_KEYTYPE_HMAC_1024        13

/* inside view of a clear key token (type 0x00 version 0x02) */
struct clearkeytoken {
	u8 type; /* 0x00 for PAES specific key tokens */
	u8 res0[3];
	u8 version; /* 0x02 for clear key token */
	u8 res1[3];
	u32 keytype; /* key type, one of the PKEY_KEYTYPE_* values */
	u32 len; /* bytes actually stored in clearkey[] */
	u8 clearkey[]; /* clear key value */
} __packed;

struct pkey_genseck {
	u16 cardnr;			/* in: card to use or FFFF for any */
	u16 domain;			/* in: domain or FFFF for any */
	u32 keytype;			/* in: key type to generate */
	struct pkey_seckey seckey;	/* out: the secure key blob */
};

#define PKEY_GENSECK _IOWR(PKEY_IOCTL_MAGIC, 0x01, struct pkey_genseck)

struct pkey_clr2seck {
	u16 cardnr;			/* in: card to use or FFFF for any */
	u16 domain;			/* in: domain or FFFF for any*/
	u32 keytype;			/* in: key type to generate */
	struct pkey_clrkey clrkey;	/* in: the clear key value */
	struct pkey_seckey seckey;	/* out: the secure key blob */
};

#define PKEY_CLR2SECK _IOWR(PKEY_IOCTL_MAGIC, 0x02, struct pkey_clr2seck)

struct pkey_verifykey {
	struct pkey_seckey seckey;	/* in: the secure key blob */
	u16  cardnr;			/* out: card number */
	u16  domain;			/* out: domain number */
	u16  keysize;			/* out: key size in bits */
	u32  attributes;		/* out: attribute bits */
};

#define PKEY_VERIFY_ATTR_AES       0x0001 /* key is an AES key */
#define PKEY_VERIFY_ATTR_OLD_MKVP  0x0100 /* key has old MKVP value */

#define PKEY_VERIFYKEY _IOWR(PKEY_IOCTL_MAGIC, 0x07, struct pkey_verifykey)

enum pkey_key_type {
	PKEY_TYPE_CCA_DATA   = (u32) 1,
	PKEY_TYPE_CCA_CIPHER = (u32) 2,
	PKEY_TYPE_EP11       = (u32) 3,
	PKEY_TYPE_CCA_ECC    = (u32) 0x1f,
	PKEY_TYPE_EP11_ECC   = (u32) 7,
};

enum pkey_key_size {
	PKEY_SIZE_AES_128 = (u32) 128,
	PKEY_SIZE_AES_192 = (u32) 192,
	PKEY_SIZE_AES_256 = (u32) 256,
	PKEY_SIZE_UNKNOWN = (u32) 0xFFFFFFFF,
};

#define PKEY_FLAGS_MATCH_CUR_MKVP  0x00000002
#define PKEY_FLAGS_MATCH_ALT_MKVP  0x00000004

#define PKEY_KEYGEN_XPRT_SYM	0x00008000
#define PKEY_KEYGEN_XPRT_UASY	0x00004000
#define PKEY_KEYGEN_XPRT_AASY	0x00002000
#define PKEY_KEYGEN_XPRT_RAW	0x00001000
#define PKEY_KEYGEN_XPRT_CPAC	0x00000800
#define PKEY_KEYGEN_XPRT_DES	0x00000080
#define PKEY_KEYGEN_XPRT_AES	0x00000040
#define PKEY_KEYGEN_XPRT_RSA	0x00000008

struct pkey_apqn {
	u16 card;
	u16 domain;
};

struct pkey_genseck2 {
	struct pkey_apqn *apqns;	/* in: ptr to list of apqn targets */
	u32 apqn_entries;		/* in: # of apqn target list entries */
	enum pkey_key_type type;	/* in: key type to generate */
	enum pkey_key_size size;	/* in: key size to generate */
	u32 keygenflags;		/* in: key generation flags */
	u8 *key;			/* in: pointer to key blob buffer */
	u32 keylen;			/* in: available key blob buffer size */
					/* out: actual key blob size */
};

#define PKEY_GENSECK2 _IOWR(PKEY_IOCTL_MAGIC, 0x11, struct pkey_genseck2)

struct pkey_clr2seck2 {
	struct pkey_apqn *apqns;	/* in: ptr to list of apqn targets */
	u32 apqn_entries;		/* in: # of apqn target list entries */
	enum pkey_key_type type;	/* in: key type to generate */
	enum pkey_key_size size;	/* in: key size to generate */
	u32 keygenflags;		/* in: key generation flags */
	struct pkey_clrkey clrkey;	/* in: the clear key value */
	u8 *key;			/* in: pointer to key blob buffer */
	u32 keylen;			/* in: available key blob buffer size */
					/* out: actual key blob size */
};

#define PKEY_CLR2SECK2 _IOWR(PKEY_IOCTL_MAGIC, 0x12, struct pkey_clr2seck2)

struct pkey_verifykey2 {
	u8 *key;			/* in: pointer to key blob */
	u32 keylen;			/* in: key blob size */
	u16 cardnr;			/* in/out: card number */
	u16 domain;			/* in/out: domain number */
	enum pkey_key_type type;	/* out: the key type */
	enum pkey_key_size size;	/* out: the key size */
	u32 flags;			/* out: additional key info flags */
};

#define PKEY_VERIFYKEY2 _IOWR(PKEY_IOCTL_MAGIC, 0x17, struct pkey_verifykey2)

struct pkey_apqns4key {
	u8 *key;			/* in: pointer to key blob */
	u32 keylen;			/* in: key blob size */
	u32 flags;			/* in: match controlling flags */
	struct pkey_apqn *apqns;	/* in/out: ptr to list of apqn targets*/
	u32 apqn_entries;		/* in: max # of apqn entries in list */
					/* out: # apqns stored into the list */
};

#define PKEY_APQNS4K _IOWR(PKEY_IOCTL_MAGIC, 0x1B, struct pkey_apqns4key)

struct pkey_apqns4keytype {
	enum pkey_key_type type;	/* in: key type */
	u8  cur_mkvp[32];		/* in: current mkvp */
	u8  alt_mkvp[32];		/* in: alternate mkvp */
	u32 flags;			/* in: match controlling flags */
	struct pkey_apqn *apqns;	/* in/out: ptr to list of apqn targets*/
	u32 apqn_entries;		/* in: max # of apqn entries in list */
					/* out: # apqns stored into the list */
};

#define PKEY_APQNS4KT _IOWR(PKEY_IOCTL_MAGIC, 0x1C, struct pkey_apqns4keytype)

struct pkey_sec2protk {
	u16 cardnr;		     /* in: card to use or FFFF for any   */
	u16 domain;		     /* in: domain or FFFF for any	  */
	struct pkey_seckey seckey;   /* in: the secure key blob		  */
	struct pkey_protkey protkey; /* out: the protected key		  */
};
#define PKEY_SEC2PROTK _IOWR(PKEY_IOCTL_MAGIC, 0x03, struct pkey_sec2protk)

struct pkey_genprotk {
	u32 keytype;			       /* in: key type to generate */
	struct pkey_protkey protkey;	       /* out: the protected key   */
};
#define PKEY_GENPROTK _IOWR(PKEY_IOCTL_MAGIC, 0x08, struct pkey_genprotk)

struct pkey_kblob2pkey2 {
	u8  *key;	     /* in: pointer to key blob		   */
	u32 keylen;		     /* in: key blob size		   */
	struct pkey_apqn *apqns; /* in: ptr to list of apqn targets */
	u32 apqn_entries;	     /* in: # of apqn target list entries  */
	struct pkey_protkey protkey; /* out: the protected key		   */
};
#define PKEY_KBLOB2PROTK2 _IOWR(PKEY_IOCTL_MAGIC, 0x1A, struct pkey_kblob2pkey2)

/*
 * EP11 key blobs of type PKEY_TYPE_EP11_AES and PKEY_TYPE_EP11_ECC
 * are ep11 blobs prepended by this header:
 */
struct ep11kblob_header {
	u8  type;	/* always 0x00 */
	u8  hver;	/* header version,  currently needs to be 0x00 */
	u16 len;	/* total length in bytes (including this header) */
	u8  version;	/* PKEY_TYPE_EP11_AES or PKEY_TYPE_EP11_ECC */
	u8  res0;	/* unused */
	u16 bitlen;	/* clear key bit len, 0 for unknown */
	u8  res1[8];	/* unused */
} __packed;

/*
 * Transform a key blob into a protected key, version 3.
 * The difference to version 2 of this ioctl is that the protected key
 * buffer is now explicitly and not within a struct pkey_protkey any more.
 * So this ioctl is also able to handle EP11 and CCA ECC secure keys and
 * provide ECC protected keys.
 */
struct pkey_kblob2pkey3 {
	u8  *key; /* in: pointer to key blob */
	u32 keylen; /* in: key blob size */
	struct pkey_apqn *apqns; /* in: ptr to list of apqn targets */
	u32 apqn_entries; /* in: # of apqn target list entries  */
	u32 pkeytype; /* out: prot key type (enum pkey_key_type) */
	u32 pkeylen; /* in/out: size of pkey buffer/actual len of pkey */
	u8  *pkey; /* in: pkey blob buffer space ptr */
};
#define PKEY_KBLOB2PROTK3 _IOWR(PKEY_IOCTL_MAGIC, 0x1D, struct pkey_kblob2pkey3)

#define KEY_TYPE_CCA_AESDATA        "CCA-AESDATA"
#define KEY_TYPE_CCA_AESCIPHER      "CCA-AESCIPHER"
#define KEY_TYPE_EP11_AES           "EP11-AES"

#define DEFAULT_KEYBITS             256
#define PAES_BLOCK_SIZE             16
#define ENC_ZERO_LEN                (2 * PAES_BLOCK_SIZE)
#define VERIFICATION_PATTERN_LEN    (2 * ENC_ZERO_LEN + 1)

#define MKVP_LENGTH		16

static const u8 zero_mkvp[MKVP_LENGTH] = { 0x00 };

#define MKVP_EQ(mkvp1, mkvp2)	(memcmp(mkvp1, mkvp2, MKVP_LENGTH) == 0)
#define MKVP_ZERO(mkvp)		(mkvp == NULL || MKVP_EQ(mkvp, zero_mkvp))

enum card_type {
	CARD_TYPE_ANY	= -1,
	CARD_TYPE_CCA   = 1,
	CARD_TYPE_EP11  = 2,
};

struct ext_lib {
	struct cca_lib *cca;
	struct ep11_lib *ep11;
};

bool is_cca_aes_data_key(const u8 *key, size_t key_size);
bool is_cca_aes_cipher_key(const u8 *key, size_t key_size);
bool is_session_bound(const u8 *key, size_t key_size);
bool is_ep11_aes_key(const u8 *key, size_t key_size);
bool is_ep11_aes_key_with_header(const u8 *key, size_t key_size);
bool is_xts_key(const u8 *key, size_t key_size);
bool is_cca_ec_key(const u8 *key, size_t key_size);
bool is_ep11_ec_key_with_header(const u8 *key, size_t key_size);
int alloc_apqns_from_mkvp(int pkeyfd, struct pkey_apqn **apqns, size_t *napqns,
							const unsigned char mkvp[], int type);
#endif
