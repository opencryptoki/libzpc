/*
 * Copyright IBM Corp. 2021
 *
 * libzpc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef CPACF_H
# define CPACF_H

# include "misc.h"

# define CPACF_M                      0x80      /* Modifier bit */

/* KM */

/* Function codes */
# define CPACF_KM_QUERY			         0
# define CPACF_KM_ENCRYPTED_AES_128	    26
# define CPACF_KM_ENCRYPTED_AES_192	    27
# define CPACF_KM_ENCRYPTED_AES_256	    28
# define CPACF_KM_XTS_ENCRYPTED_AES_128	58
# define CPACF_KM_XTS_ENCRYPTED_AES_256	60

struct cpacf_km_aes_param {
	u8 protkey[64]; /* WKa(K)|WKaVP */
};

struct cpacf_km_xts_aes_128_param {
	u8 protkey[48]; /* WKa(K)|WKaVP */
	u8 xtsparam[16];
};

struct cpacf_km_xts_aes_256_param {
	u8 protkey[64]; /* WKa(K)|WKaVP */
	u8 xtsparam[16];
};

static inline int
cpacf_km(unsigned long fc, void *param, u8 * out, const u8 * in,
    unsigned long inlen)
{
        /* *INDENT-OFF* */
	register unsigned long r0 __asm__("0") = (unsigned long) fc;
	register unsigned long r1 __asm__("1") = (unsigned long) param;
	register unsigned long r2 __asm__("2") = (unsigned long) in;
	register unsigned long r3 __asm__("3") = (unsigned long) inlen;
	register unsigned long r4 __asm__("4") = (unsigned long) out;
	u8 cc;

	__asm__ volatile(
		"0:	.insn	rre,%[opc] << 16,%[out],%[in]\n"
		"	brc	1,0b\n" /* handle partial completion */
                "       ipm     %[cc]\n"
                "       srl     %[cc],28\n"
		: [in] "+a" (r2), [inlen] "+d" (r3), [out] "+a" (r4),
          [cc] "=d" (cc)
		: [fc] "d" (r0), [param] "a" (r1), [opc] "i" (0xb92e)
		: "cc", "memory"
	);
        /* *INDENT-ON* */

	return cc;
}

/* KMC */

/* Function codes */
# define CPACF_KMC_QUERY		0
# define CPACF_KMC_ENCRYPTED_AES_128	26
# define CPACF_KMC_ENCRYPTED_AES_192	27
# define CPACF_KMC_ENCRYPTED_AES_256	28

struct cpacf_kmc_aes_param {
	u8 cv[16];
	u8 protkey[64]; /* WKa(K)|WKaVP */
};

static inline int
cpacf_kmc(unsigned long fc, void *param, u8 * out, const u8 * in, long inlen)
{
        /* *INDENT-OFF* */
	register unsigned long r0 __asm__("0") = (unsigned long) fc;
	register unsigned long r1 __asm__("1") = (unsigned long) param;
	register unsigned long r2 __asm__("2") = (unsigned long) in;
	register unsigned long r3 __asm__("3") = (unsigned long) inlen;
	register unsigned long r4 __asm__("4") = (unsigned long) out;
	u8 cc;

	__asm__ volatile(
		"0:	.insn	rre,%[opc] << 16,%[out],%[in]\n"
		"	brc	1,0b\n" /* handle partial completion */
                "       ipm     %[cc]\n"
                "       srl     %[cc],28\n"
		: [in] "+a" (r2), [inlen] "+d" (r3), [out] "+a" (r4),
          [cc] "=d" (cc)
		: [fc] "d" (r0), [param] "a" (r1), [opc] "i" (0xb92f)
		: "cc", "memory"
	);
        /* *INDENT-ON* */

	return cc;
}

/* KMAC */

/* Function codes */
# define CPACF_KMAC_QUERY                 0
# define CPACF_KMAC_ENCRYPTED_AES_128    26
# define CPACF_KMAC_ENCRYPTED_AES_192    27
# define CPACF_KMAC_ENCRYPTED_AES_256    28
# define CPACF_KMAC_ENCRYPTED_SHA_224    120
# define CPACF_KMAC_ENCRYPTED_SHA_256    121
# define CPACF_KMAC_ENCRYPTED_SHA_384    122
# define CPACF_KMAC_ENCRYPTED_SHA_512    123

/* Flags */
# define CPACF_KMAC_IKP         0x8000
# define CPACF_KMAC_IIMP        0x4000
# define CPACF_KMAC_CCUP        0x2000

struct cpacf_kmac_aes_param {
	u8 icv[16];
	u8 protkey[64]; /* WKa(K)|WKaVP */
};

struct cpacf_kmac_hmac_param {
	union {
		struct {
			u32 h[8];
			u64 imbl;
			unsigned char protkey[96]; /* WKa(K)|WKaVP */
		} hmac_224_256;
		struct {
			u64 h[8];
			u128 imbl;
			unsigned char protkey[160]; /* WKa(K)|WKaVP */
		} hmac_384_512;
	};
};

static inline int
cpacf_kmac(unsigned long fc, void *param, const u8 * in, unsigned long inlen)
{
        /* *INDENT-OFF* */
	register unsigned long r0 __asm__("0") = (unsigned long)fc;
	register unsigned long r1 __asm__("1") = (unsigned long)param;
	register unsigned long r2 __asm__("2") = (unsigned long)in;
	register unsigned long r3 __asm__("3") = (unsigned long)inlen;
	u8 cc;

	__asm__ volatile(
		"0:	.insn	rre,%[opc] << 16,0,%[in]\n"
		"	brc	1,0b\n" /* handle partial completion */
        "   ipm     %[cc]\n"
        "   srl     %[cc],28\n"
		: [in] "+a" (r2), [inlen] "+d" (r3), [cc] "=d" (cc)
		: [fc] "d" (r0), [param] "a" (r1), [opc] "i" (0xb91e)
		: "cc", "memory"
	);
        /* *INDENT-ON* */

	return cc;
}

/* PCC */

/* Function codes */
# define CPACF_PCC_QUERY                     0
# define CPACF_PCC_CMAC_ENCRYPTED_AES_128    26
# define CPACF_PCC_CMAC_ENCRYPTED_AES_192    27
# define CPACF_PCC_CMAC_ENCRYPTED_AES_256    28
# define CPACF_PCC_XTS_ENCRYPTED_AES_128	58
# define CPACF_PCC_XTS_ENCRYPTED_AES_256	60

struct cpacf_pcc_xts_aes_128_param {
	u8 protkey[48]; /* WKa(K)|WKaVP */
	u8 i[16];
	u8 j[16];
	u8 t[16];
	u8 xtsparams[16];
};

struct cpacf_pcc_xts_aes_256_param {
	u8 protkey[64]; /* WKa(K)|WKaVP */
	u8 i[16];
	u8 j[16];
	u8 t[16];
	u8 xtsparams[16];
};

struct cpacf_pcc_cmac_aes_param {
	u8 ml;
	u8 reserved[7];
	u8 message[16];
	u8 icv[16];
	u8 protkey[64]; /* WKa(K)|WKaVP */
};

/* PCC (perform cryptographuc computation) */
static inline int
cpacf_pcc(unsigned long fc, void *param)
{
	register unsigned long r0 __asm__("0") = (unsigned long)fc;
	register unsigned long r1 __asm__("1") = (unsigned long)param;
	u8 cc;

	/* *INDENT-OFF* */
	__asm__ volatile(
		"0:     .insn   rre,%[opc] << 16,0,0\n" /* PCC opcode */
		"       brc     1,0b\n" /* handle partial completion */
    	"       ipm     %[cc]\n"
        "       srl     %[cc],28\n"
        : [cc] "=d" (cc)
        : [fc] "d" (r0), [param] "a" (r1), [opc] "i" (0xb92c)
        : "cc", "memory"
	);
	/* *INDENT-ON* */

	return cc;
}

/* KMA */

/* Function codes */
# define CPACF_KMA_QUERY                     0
# define CPACF_KMA_GCM_ENCRYPTED_AES_128    26
# define CPACF_KMA_GCM_ENCRYPTED_AES_192    27
# define CPACF_KMA_GCM_ENCRYPTED_AES_256    28

/* Function code flags */
# define CPACF_KMA_LPC             0x100/* Last-Plaintext/Ciphertext */
# define CPACF_KMA_LAAD            0x200/* Last-AAD */
# define CPACF_KMA_HS              0x400/* Hash-subkey Supplied */

struct cpacf_kma_gcm_aes_param {
	u8 reserved[12];
	u32 cv;
	u8 t[16];
	u8 h[16];
	u64 taadl;
	u64 tpcl;
	u8 j0[16];
	u8 protkey[64]; /* WKa(K)|WKaVP */
};

/*  KMA (cipher message with authentication) */
static inline int
cpacf_kma(unsigned long fc, void *param, u8 * out, const u8 * aad,
    unsigned long aadlen, const u8 * in, unsigned long inlen)
{
        /* *INDENT-OFF* */
        register unsigned long r0 __asm__("0") = (unsigned long)fc;
	register unsigned long r1 __asm__("1") = (unsigned long)param;
	register unsigned long r2 __asm__("2") = (unsigned long)in;
	register unsigned long r3 __asm__("3") = (unsigned long)inlen;
	register unsigned long r4 __asm__("4") = (unsigned long)aad;
	register unsigned long r5 __asm__("5") = (unsigned long)aadlen;
	register unsigned long r6 __asm__("6") = (unsigned long)out;
	u8 cc;

        __asm__ volatile(
                "0:     .insn   rrf,%[opc]<<16,%[out],%[in],%[aad],0\n"
                "       brc     1,0b\n"     /* partial completion */
                "       ipm     %[cc]\n"
                "       srl     %[cc],28\n"
                : [out] "+a" (r6), [cc] "=d" (cc),
                    [in] "+a" (r2), [inlen] "+d" (r3),
                    [aad] "+a" (r4), [aadlen] "+d" (r5)
                : [fc] "d" (r0), [param] "a" (r1), [opc] "i" (0xb929)
                : "cc", "memory"
        );
        /* *INDENT-ON* */

	return cc;
}

/* KDSA */

/* Function codes */
#define CPACF_KDSA_QUERY                              0
#define CPACF_KDSA_ECDSA_VERIFY_ECP256                1
#define CPACF_KDSA_ECDSA_VERIFY_ECP384                2
#define CPACF_KDSA_ECDSA_VERIFY_ECP521                3
#define CPACF_KDSA_EDDSA_VERIFY_ED25519              32
#define CPACF_KDSA_EDDSA_VERIFY_ED448                36
#define CPACF_KDSA_ENCRYPTED_ECDSA_SIGN_P256         17
#define CPACF_KDSA_ENCRYPTED_ECDSA_SIGN_P384         18
#define CPACF_KDSA_ENCRYPTED_ECDSA_SIGN_P521         19
#define CPACF_KDSA_ENCRYPTED_EDDSA_SIGN_ED25519      48
#define CPACF_KDSA_ENCRYPTED_EDDSA_SIGN_ED448        52

/* Parameter blocks */
typedef struct cpacf_ecp256_sign_param {
	unsigned char sig_r[32];
	unsigned char sig_s[32];
	unsigned char hash[32];
	unsigned char prot[32];
	unsigned char rand[32];
	unsigned char wkvp[32];
	unsigned short c;
} cpacf_ecp256_sign_param_t;

typedef struct cpacf_ecp256_verify_param {
	unsigned char sig_r[32];
	unsigned char sig_s[32];
	unsigned char hash[32];
	unsigned char pub_x[32];
	unsigned char pub_y[32];
} cpacf_ecp256_verify_param_t;

typedef struct cpacf_ecp384_sign_param {
	unsigned char sig_r[48];
	unsigned char sig_s[48];
	unsigned char hash[48];
	unsigned char prot[48];
	unsigned char rand[48];
	unsigned char wkvp[32];
	unsigned short c;
} cpacf_ecp384_sign_param_t;

typedef struct cpacf_ecp384_verify_param {
	unsigned char sig_r[48];
	unsigned char sig_s[48];
	unsigned char hash[48];
	unsigned char pub_x[48];
	unsigned char pub_y[48];
} cpacf_ecp384_verify_param_t;

typedef struct cpacf_ecp521_sign_param {
	unsigned char sig_r[80];
	unsigned char sig_s[80];
	unsigned char hash[80];
	unsigned char prot[80];
	unsigned char rand[80];
	unsigned char wkvp[32];
	unsigned short c;
} cpacf_ecp521_sign_param_t;

typedef struct cpacf_ecp521_verify_param {
	unsigned char sig_r[80];
	unsigned char sig_s[80];
	unsigned char hash[80];
	unsigned char pub_x[80];
	unsigned char pub_y[80];
} cpacf_ecp521_verify_param_t;

typedef struct cpacf_ed25519_sign_param {
	unsigned char sig_r[32];
	unsigned char sig_s[32];
	unsigned char prot[32];
	unsigned char wkvp[32];
	unsigned char res[16];
	unsigned short c;
} cpacf_ed25519_sign_param_t;

typedef struct cpacf_ed25519_verify_param {
	unsigned char sig_r[32];
	unsigned char sig_s[32];
	unsigned char pub[32];
} cpacf_ed25519_verify_param_t;

typedef struct cpacf_ed448_sign_param {
	unsigned char sig_r[64];
	unsigned char sig_s[64];
	unsigned char prot[64];
	unsigned char wkvp[32];
	unsigned char res[16];
	unsigned short c;
} cpacf_ed448_sign_param_t;

typedef struct cpacf_ed448_verify_param {
	unsigned char sig_r[64];
	unsigned char sig_s[64];
	unsigned char pub[64];
} cpacf_ed448_verify_param_t;

/**
 * cpacf_kdsa:
 * @func: the function code passed to KDSA; see s390_kdsa_functions
 * @param: address of parameter block; see POP for details on each func
 * @src: address of source memory area
 * @srclen: length of src operand in bytes
 *
 * Executes the KDSA (COMPUTE DIGITAL SIGNATURE AUTHENTICATION) operation of
 * the CPU.
 *
 * Returns 0 on success. Fails in case of sign if the random number was not
 * invertible. Fails in case of verify if the signature is invalid or the
 * public key is not on the curve.
 */
static inline int
cpacf_kdsa(unsigned long func, void *param,
			const unsigned char *src, unsigned long srclen)
{
    register unsigned long r0 __asm__("0") = (unsigned long)func;
    register unsigned long r1 __asm__("1") = (unsigned long)param;
    register unsigned long r2 __asm__("2") = (unsigned long)src;
    register unsigned long r3 __asm__("3") = (unsigned long)srclen;
    unsigned long rc = 1;

    __asm__ volatile(
        "0: .insn   rre,%[__opc] << 16,0,%[__src]\n"
        "   brc 1,0b\n" /* handle partial completion */
        "   brc 7,1f\n"
        "   lghi    %[__rc],0\n"
        "1:\n"
        : [__src] "+a" (r2), [__srclen] "+d" (r3), [__rc] "+d" (rc)
        : [__fc] "d" (r0), [__param] "a" (r1), [__opc] "i" (0xb93a)
        : "cc", "memory");

    return (int)rc;
}

/* KLMD */

/* Function codes */
#define CPACF_KLMD_QUERY                              0
#define CPACF_KLMD_SHA_256                            2
#define CPACF_KLMD_SHA_512                            3

/* Parameter blocks */
struct cpacf_klmd_param {
	union {
		struct {
			u8 h[32];
			u64 mbl;
		} klmd_224_256;
		struct {
			u8 h[64];
			u128 mbl;
		} klmd_384_512;
	};
};

static inline int cpacf_klmd(unsigned long func, void *param,
		const unsigned char *src, long src_len)
{
	register long __func __asm__("0") = func;
	register void *__param __asm__("1") = param;
	register const unsigned char *__src __asm__("2") = src;
	register long __src_len __asm__("3") = src_len;

	__asm__ volatile (
		"0:	.insn	rre,0xb93f0000,%0,%0 \n" /* KLMD opcode */
		"	brc	1,0b \n"	/* handle partial completion */
		: "+a"(__src), "+d"(__src_len)
		: "d"(__func), "a"(__param)
		: "cc", "memory");

	return func ? src_len - __src_len : __src_len;
}

static inline void s390_flip_endian_32(void *dest, const void *src)
{
	__asm__ volatile(
		"	lrvg    %%r0,0(%[__src])\n"
		"	lrvg    %%r1,8(%[__src])\n"
		"	lrvg    %%r4,16(%[__src])\n"
		"	lrvg    %%r5,24(%[__src])\n"
		"	stg %%r0,24(%[__dest])\n"
		"	stg %%r1,16(%[__dest])\n"
		"	stg %%r4,8(%[__dest])\n"
		"	stg %%r5,0(%[__dest])\n"
		:
		: [__dest] "a" (dest), [__src] "a" (src)
		: "memory", "%r0", "%r1", "%r4", "%r5");
}

static inline void s390_flip_endian_64(void *dest, const void *src)
{
	__asm__ volatile(
		"	lrvg    %%r0,0(%[__src])\n"
		"	lrvg    %%r1,8(%[__src])\n"
		"	lrvg    %%r4,16(%[__src])\n"
		"	lrvg    %%r5,24(%[__src])\n"
		"	lrvg    %%r6,32(%[__src])\n"
		"	lrvg    %%r7,40(%[__src])\n"
		"	lrvg    %%r8,48(%[__src])\n"
		"	lrvg    %%r9,56(%[__src])\n"
		"	stg %%r0,56(%[__dest])\n"
		"	stg %%r1,48(%[__dest])\n"
		"	stg %%r4,40(%[__dest])\n"
		"	stg %%r5,32(%[__dest])\n"
		"	stg %%r6,24(%[__dest])\n"
		"	stg %%r7,16(%[__dest])\n"
		"	stg %%r8,8(%[__dest])\n"
		"	stg %%r9,0(%[__dest])\n"
		:
		: [__dest] "a" (dest), [__src] "a" (src)
		: "memory", "%r0", "%r1", "%r4", "%r5",
			"%r6", "%r7", "%r8", "%r9");
}
#endif
