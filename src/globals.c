/*
 * Copyright IBM Corp. 2021
 *
 * libzpc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "aes_key_local.h"
#include "cpacf.h"
#include "globals.h"
#include "misc.h"
#include "debug.h"

#include <assert.h>
#include <dlfcn.h>
#include <stdint.h>
#include <stdlib.h>
#include <fcntl.h>
#include <limits.h>
#include <unistd.h>
#include <sys/auxv.h>
#include <sys/types.h>
#include <sys/stat.h>

#define ENV_DEBUG	"ZPC_DEBUG"

/*
 * IBM z/Architecture Principles of Operation (POP) counts bits
 * from most-significant/leftmost to least-significant/rightmost,
 * starting at 0.
 * If the bits returned by STFLE (facility list) or the bits
 * returned by a CPACF instruction's query function (status word)
 * are stored in an u64 array, the macros below can be used to
 * check a specific bit using its number from POP.
 * For example, checking facility bit 146:
 *   u64 *flist;
 *   [...] // store facility list at flist
 *   if (flist[OFF64(146)] & MASK64(146)) [...];
 */

/* Map a facility bit number or function code to its bit mask. */
#define MASK64(n)  (1ULL << (63 - (n) % 64))

/* Map a facility bit number or function code to its offset. */
#define OFF64(n) (n / 64)

/* Facility bit numbers */
#define MSA    17       /* message-security-assist */
#define MSA3   76       /* message-security-assist extension 3 */
#define MSA4   77       /* message-security-assist extension 4 */
#define MSA5   57       /* message-security-assist extension 5 */
#define MSA8  146       /* message-security-assist extension 8 (implies MSA3) */
#define MSA9  155       /* message-security-assist extension 9 (implies MSA3
                         * and MSA4) */

/* STFLE (store facility list extended) */
static inline unsigned long
stfle(u64 flist[], u8 nmemb)
{
        /* *INDENT-OFF* */
        register unsigned long r0 __asm__("0") = (unsigned long)nmemb - 1;

        __asm__ volatile(
                ".insn s,%[opc]<<16,0(%[flist])"
                : "+d" (r0)
                : [flist] "a" (flist), [opc] "i" (0xb2b0)
                : "memory", "cc"
        );
        /* *INDENT-ON* */

	return r0 + 1;
}

/*
 * libzpc is initialized iff pkeyfd >= 0.
 *
 * Make sure this global (or another one from this compilation unit)
 * is referenced from all other compilation units that require the
 * constructor to run (that is probably all units except for the
 * error unit).
 * In case libzpc was compiled to a static library/archive, this makes sure
 * that the object file corresponding to this compilation unit is included
 * when the archive is linked with another binary.
 * This is because this file's constructor and destructor are required
 * for libzpc to work properly but are never referenced otherwise,
 * so the linker will generally not pick this object from the archive
 * unless the --whole-archive option was specified.
 */
int pkeyfd = -1;

struct hwcaps hwcaps;
struct swcaps swcaps;

int debug;
pthread_mutex_t debuglock;

struct cca_lib cca;
pthread_mutex_t ccalock;

struct ep11_lib ep11;
pthread_mutex_t ep11lock;

#if !defined(__linux__) && !defined(__s390x__)
static const int init = 0;
#else
static const int init = 1;
#endif

__attribute__((constructor))
static void zpc_init(void)
{
	unsigned long hwcap, facility_list_nmemb;
	u64 status_word[2], *facility_list = NULL, tmp;
	int rc, err = -1;
	int aes_ecb_km = 0;
	int aes_cbc_kmc = 0;
	int aes_gcm_kma = 0;
	int aes_cmac_kmac = 0, aes_cmac_pcc = 0, hmac_kmac = 0;
	int aes_ccm_kmac = 0, aes_ccm_kma = 0;
	int aes_xts_km = 0, aes_xts_pcc = 0, aes_xts_full_km = 0;
	int ecc_kdsa = 0;
	int aes_cca = 0, aes_ep11 = 0, ecdsa_cca = 0, ecdsa_ep11 = 0;
	int uv_pvsecrets = 0;
	char *env;

	if (init != 1)
		return;

	/* Init debuggind. */
	rc = pthread_mutex_init(&debuglock, NULL);
	if (rc)
		goto ret;
	env = getenv(ENV_DEBUG);
	if (env != NULL && env[0] != '\0') {
	char *endptr;
	long debuglong = strtol(env, &endptr, 0);

		if (*endptr == '\0' && debuglong > INT_MIN
		    && debuglong < INT_MAX)
			debug = (int)debuglong;
	}

	/* Init CCA library structure. */
	rc = pthread_mutex_init(&ccalock, NULL);
	if (rc)
		goto ret;
	rc = pthread_mutex_lock(&ccalock);
	assert(rc == 0);
	if (load_cca_library(&cca, true) != 0) {
		DEBUG("loading CCA library failed");
	} else {
		DEBUG("loaded CCA library: ver %u, rel %u, mod %u",
	            cca.version.ver, cca.version.rel, cca.version.mod);
		aes_cca = 1;
		if (cca.version.ver >= 7)
			ecdsa_cca = 1;
	}
	rc = pthread_mutex_unlock(&ccalock);
	assert(rc == 0);

	/* Init EP11 library structure. */
	rc = pthread_mutex_init(&ep11lock, NULL);
	if (rc)
		goto ret;
	rc = pthread_mutex_lock(&ep11lock);
	assert(rc == 0);
	if (load_ep11_library(&ep11, true) != 0) {
		DEBUG("loading EP11 library failed");
	} else {
		DEBUG("loaded EP11 library: %u.%u", ep11.version.major,
	            ep11.version.minor);
		aes_ep11 = 1;
		if (ep11.version.major >= 3)
			ecdsa_ep11 = 1;
	}
	rc = pthread_mutex_unlock(&ep11lock);
	assert(rc == 0);

	/*
	 * Check if we are running in a Secure Execution guest with retrievable
	 * secret support
	 */
	if (running_in_se_guest() && max_secrets() > 0)
		uv_pvsecrets = 1;

	/* Open pkey device */
	pkeyfd = open("/dev/pkey", O_RDWR);
	if (pkeyfd < 0) {
		DEBUG("opening /dev/pkey failed");
		goto ret;
	}
	DEBUG("opened /dev/pkey: file descriptor %d", pkeyfd);

	/* Check for STFLE. */
	hwcap = getauxval(AT_HWCAP);
	if (!(hwcap & HWCAP_S390_STFLE))
		goto ret;

	/* Query number of u64s returned by stfle. */
	facility_list_nmemb = stfle(&tmp, 1);
	if (facility_list_nmemb > UINT8_MAX)
		goto ret;

	/* Expected facility list size is 64 * facility_list_nmemb bits. */
	facility_list = calloc(facility_list_nmemb, sizeof(u64));
	if (facility_list == NULL)
		goto ret;

	/* Query facility list. */
	stfle(facility_list, facility_list_nmemb);

	/* Check MSA. */
	if (facility_list_nmemb >= OFF64(MSA) + 1
	    && (facility_list[OFF64(MSA)] & MASK64(MSA))) {
		DEBUG("detected message-security-assist");

		memset(status_word, 0, sizeof(status_word));
		cpacf_km(CPACF_KM_QUERY, &status_word, NULL, NULL, 0, NULL);
		DEBUG("status word km: 0x%016llx:0x%016llx", status_word[0],
		    status_word[1]);

		if ((status_word[OFF64(CPACF_KM_ENCRYPTED_AES_128)]
		    & MASK64(CPACF_KM_ENCRYPTED_AES_128))
		    && (status_word[OFF64(CPACF_KM_ENCRYPTED_AES_192)]
		    & MASK64(CPACF_KM_ENCRYPTED_AES_192))
		    && (status_word[OFF64(CPACF_KM_ENCRYPTED_AES_256)]
		    & MASK64(CPACF_KM_ENCRYPTED_AES_256))) {
			aes_ecb_km = 1;
		}
		if ((status_word[OFF64(CPACF_KM_XTS_ENCRYPTED_AES_128)]
		    & MASK64(CPACF_KM_XTS_ENCRYPTED_AES_128))
		    && (status_word[OFF64(CPACF_KM_XTS_ENCRYPTED_AES_256)]
		    & MASK64(CPACF_KM_XTS_ENCRYPTED_AES_256))) {
			aes_xts_km = 1;
		}
		if ((status_word[OFF64(CPACF_KM_FXTS_ENCRYPTED_AES_128)]
			& MASK64(CPACF_KM_FXTS_ENCRYPTED_AES_128))
			&& (status_word[OFF64(CPACF_KM_FXTS_ENCRYPTED_AES_256)]
			& MASK64(CPACF_KM_FXTS_ENCRYPTED_AES_256))) {
			aes_xts_full_km = 1;
		}

		memset(status_word, 0, sizeof(status_word));
		cpacf_kmc(CPACF_KMC_QUERY, &status_word, NULL, NULL, 0, NULL);
		DEBUG("status word kmc: 0x%016llx:0x%016llx", status_word[0],
		    status_word[1]);

		if ((status_word[OFF64(CPACF_KMC_ENCRYPTED_AES_128)]
		    & MASK64(CPACF_KMC_ENCRYPTED_AES_128))
		    && (status_word[OFF64(CPACF_KMC_ENCRYPTED_AES_192)]
		    & MASK64(CPACF_KMC_ENCRYPTED_AES_192))
		    && (status_word[OFF64(CPACF_KMC_ENCRYPTED_AES_256)]
		    & MASK64(CPACF_KMC_ENCRYPTED_AES_256))) {
			aes_cbc_kmc = 1;
		}

		memset(status_word, 0, sizeof(status_word));
		cpacf_kmac(CPACF_KMAC_QUERY, &status_word, NULL, 0);
		DEBUG("status word kmac: 0x%016llx:0x%016llx", status_word[0],
		    status_word[1]);

		if ((status_word[OFF64(CPACF_KMAC_ENCRYPTED_AES_128)]
		    & MASK64(CPACF_KMAC_ENCRYPTED_AES_128))
		    && (status_word[OFF64(CPACF_KMAC_ENCRYPTED_AES_192)]
		    & MASK64(CPACF_KMAC_ENCRYPTED_AES_192))
		    && (status_word[OFF64(CPACF_KMAC_ENCRYPTED_AES_256)]
		    & MASK64(CPACF_KMAC_ENCRYPTED_AES_256))) {
			aes_cmac_kmac = 1;
			aes_ccm_kmac = 1;
		}
		if ((status_word[OFF64(CPACF_KMAC_ENCRYPTED_SHA_224)]
		    & MASK64(CPACF_KMAC_ENCRYPTED_SHA_224))
		    && (status_word[OFF64(CPACF_KMAC_ENCRYPTED_SHA_256)]
		    & MASK64(CPACF_KMAC_ENCRYPTED_SHA_256))
		    && (status_word[OFF64(CPACF_KMAC_ENCRYPTED_SHA_384)]
		    & MASK64(CPACF_KMAC_ENCRYPTED_SHA_384))
		    && (status_word[OFF64(CPACF_KMAC_ENCRYPTED_SHA_512)]
		    & MASK64(CPACF_KMAC_ENCRYPTED_SHA_512))) {
			hmac_kmac = 1;
		}
	}

	/* Check MSA3. */
	if (facility_list_nmemb >= OFF64(MSA3) + 1
	    && (facility_list[OFF64(MSA3)] & MASK64(MSA3))) {
		DEBUG("detected message-security-assist extension 3");

		memset(status_word, 0, sizeof(status_word));
		cpacf_pcc(CPACF_PCC_QUERY, &status_word);
		DEBUG("status word pcc: 0x%016llx:0x%016llx", status_word[0],
		    status_word[1]);

		if ((status_word[OFF64(CPACF_PCC_CMAC_ENCRYPTED_AES_128)]
		    & MASK64(CPACF_PCC_CMAC_ENCRYPTED_AES_128))
		    && (status_word[OFF64(CPACF_PCC_CMAC_ENCRYPTED_AES_192)]
		    & MASK64(CPACF_PCC_CMAC_ENCRYPTED_AES_192))
		    && (status_word[OFF64(CPACF_PCC_CMAC_ENCRYPTED_AES_256)]
		    & MASK64(CPACF_PCC_CMAC_ENCRYPTED_AES_256))) {
			aes_cmac_pcc = 1;
		}

		if ((status_word[OFF64(CPACF_PCC_XTS_ENCRYPTED_AES_128)]
		    & MASK64(CPACF_PCC_XTS_ENCRYPTED_AES_128))
		    && (status_word[OFF64(CPACF_PCC_XTS_ENCRYPTED_AES_256)]
		    & MASK64(CPACF_PCC_XTS_ENCRYPTED_AES_256))) {
			aes_xts_pcc = 1;
		}
	}

	/* Check MSA8. */
	if (facility_list_nmemb >= OFF64(MSA8) + 1
	    && (facility_list[OFF64(MSA8)] & MASK64(MSA8))) {
		DEBUG("detected message-security-assist extension 8");

		memset(status_word, 0, sizeof(status_word));
		cpacf_kma(CPACF_KMA_QUERY, &status_word, NULL, NULL, 0, NULL,
		    0, NULL);
		DEBUG("status word kma: 0x%016llx:0x%016llx", status_word[0],
		    status_word[1]);

		if ((status_word[OFF64(CPACF_KMA_GCM_ENCRYPTED_AES_128)]
		    & MASK64(CPACF_KMA_GCM_ENCRYPTED_AES_128))
		    && (status_word[OFF64(CPACF_KMA_GCM_ENCRYPTED_AES_192)]
		    & MASK64(CPACF_KMA_GCM_ENCRYPTED_AES_192))
		    && (status_word[OFF64(CPACF_KMA_GCM_ENCRYPTED_AES_256)]
		    & MASK64(CPACF_KMA_GCM_ENCRYPTED_AES_256))) {
			aes_ccm_kma = 1;
			aes_gcm_kma = 1;
		}
	}

	/* Check MSA9. */
	if (facility_list_nmemb >= OFF64(MSA9) + 1
	    && (facility_list[OFF64(MSA9)] & MASK64(MSA9))) {
		DEBUG("detected message-security-assist extension 9");

		memset(status_word, 0, sizeof(status_word));
		cpacf_kdsa(CPACF_KDSA_QUERY, &status_word, NULL, 0);
		DEBUG("status word kdsa: 0x%016llx:0x%016llx", status_word[0],
		    status_word[1]);

		if ((status_word[OFF64(CPACF_KDSA_ENCRYPTED_ECDSA_SIGN_P256)]
		    & MASK64(CPACF_KDSA_ENCRYPTED_ECDSA_SIGN_P256))
		    && (status_word[OFF64(CPACF_KDSA_ENCRYPTED_ECDSA_SIGN_P384)]
		    & MASK64(CPACF_KDSA_ENCRYPTED_ECDSA_SIGN_P384))
		    && (status_word[OFF64(CPACF_KDSA_ENCRYPTED_ECDSA_SIGN_P521)]
		    & MASK64(CPACF_KDSA_ENCRYPTED_ECDSA_SIGN_P521))
		    && (status_word[OFF64(CPACF_KDSA_ENCRYPTED_EDDSA_SIGN_ED25519)]
		    & MASK64(CPACF_KDSA_ENCRYPTED_EDDSA_SIGN_ED25519))
		    && (status_word[OFF64(CPACF_KDSA_ENCRYPTED_EDDSA_SIGN_ED448)]
		    & MASK64(CPACF_KDSA_ENCRYPTED_EDDSA_SIGN_ED448))) {
			ecc_kdsa = 1;
		}
	}

	if (aes_xts_full_km == 1) {
		DEBUG("detected message-security-assist extension 10");
	}
	if (hmac_kmac == 1) {
		DEBUG("detected message-security-assist extension 11");
	}

	/* Hardware capabilities via CPACF */
	if (aes_ecb_km == 1) {
		hwcaps.aes_ecb = 1;
		DEBUG("detected aes-ecb instruction set extensions");
	}
	if (aes_cbc_kmc == 1) {
		hwcaps.aes_cbc = 1;
		DEBUG("detected aes-cbc instruction set extensions");
	}
	if (aes_xts_km == 1 && aes_xts_pcc) {
		hwcaps.aes_xts = 1;
		DEBUG("detected aes-xts instruction set extensions");
	}
	if (aes_xts_full_km == 1) {
		hwcaps.aes_xts_full = 1;
		DEBUG("detected aes-xts-full instruction set extensions");
	}
	if (aes_cmac_kmac == 1 && aes_cmac_pcc == 1) {
		hwcaps.aes_cmac = 1;
		DEBUG("detected aes-cmac instruction set extensions");
	}
	if (hmac_kmac == 1) {
		hwcaps.hmac_kmac = 1;
		DEBUG("detected hmac instruction set extensions");
	}
	if (aes_ccm_kma == 1 && aes_ccm_kmac == 1) {
		hwcaps.aes_ccm = 1;
		DEBUG("detected aes-ccm instruction set extensions");
	}
	if (aes_gcm_kma == 1) {
		hwcaps.aes_gcm = 1;
		DEBUG("detected aes-gcm instruction set extensions");
	}
	if (ecc_kdsa == 1) {
		hwcaps.ecc_kdsa = 1;
		DEBUG("detected ecc-kdsa instruction set extensions");
	}

	/* Software capabilities via host libs */
	if (aes_cca == 1) {
		swcaps.aes_cca = 1;
		DEBUG("detected aes via cca host lib software capability");
	}
	if (aes_ep11 == 1) {
		swcaps.aes_ep11 = 1;
		DEBUG("detected aes via ep11 host lib software capability");
	}
	if (uv_pvsecrets == 1) {
		swcaps.uv_pvsecrets = 1;
		DEBUG("detected UV retrievable secrets capability");
	} else {
		DEBUG("UV retrievable secrets capability not available");
	}
	if (ecdsa_cca == 1) {
		swcaps.ecdsa_cca = 1;
		DEBUG("detected ecdsa via cca host lib software capability");
	} else {
		DEBUG("ecdsa via cca host lib software capability not available");
	}
	if (ecdsa_ep11 == 1) {
		swcaps.ecdsa_ep11 = 1;
		DEBUG("detected ecdsa via ep11 host lib software capability");
	} else {
		DEBUG("ecdsa via ep11 host lib software capability not available");
	}

	err = 0;
ret:
	if (err) {
		if (pkeyfd >= 0) {
			close(pkeyfd);
			pkeyfd = -1;
		}
	}
	free(facility_list);
	DEBUG("return");
	return;
}

__attribute__((destructor))
static void zpc_fini(void)
{
	int rc;

	UNUSED(rc);

	if (init != 1)
		return;

	if (pkeyfd >= 0) {
		close(pkeyfd);
		pkeyfd = -1;
	}

	/* Unload EP11 library. */
	rc = pthread_mutex_lock(&ep11lock);
	assert(rc == 0);
	if (ep11.lib_ep11 != NULL)
		dlclose(ep11.lib_ep11);
	rc = pthread_mutex_unlock(&ep11lock);
	assert(rc == 0);
	rc = pthread_mutex_destroy(&ep11lock);
	assert(rc == 0);

	/* Unload CCA library. */
	rc = pthread_mutex_lock(&ccalock);
	assert(rc == 0);
	if (cca.lib_csulcca != NULL)
		dlclose(cca.lib_csulcca);
	rc = pthread_mutex_unlock(&ccalock);
	assert(rc == 0);
	rc = pthread_mutex_destroy(&ccalock);
	assert(rc == 0);

	DEBUG("return");

	rc = pthread_mutex_destroy(&debuglock);
	assert(rc == 0);
}
