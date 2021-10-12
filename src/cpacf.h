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
	register unsigned long r0 asm("0") = (unsigned long) fc;
	register unsigned long r1 asm("1") = (unsigned long) param;
	register unsigned long r2 asm("2") = (unsigned long) in;
	register unsigned long r3 asm("3") = (unsigned long) inlen;
	register unsigned long r4 asm("4") = (unsigned long) out;
	u8 cc;

	asm volatile(
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
	register unsigned long r0 asm("0") = (unsigned long) fc;
	register unsigned long r1 asm("1") = (unsigned long) param;
	register unsigned long r2 asm("2") = (unsigned long) in;
	register unsigned long r3 asm("3") = (unsigned long) inlen;
	register unsigned long r4 asm("4") = (unsigned long) out;
	u8 cc;

	asm volatile(
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

struct cpacf_kmac_aes_param {
	u8 icv[16];
	u8 protkey[64]; /* WKa(K)|WKaVP */
};

static inline int
cpacf_kmac(unsigned long fc, void *param, const u8 * in, unsigned long inlen)
{
        /* *INDENT-OFF* */
	register unsigned long r0 asm("0") = (unsigned long)fc;
	register unsigned long r1 asm("1") = (unsigned long)param;
	register unsigned long r2 asm("2") = (unsigned long)in;
	register unsigned long r3 asm("3") = (unsigned long)inlen;
	u8 cc;

	asm volatile(
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
	asm volatile(
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

#endif
