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

#include "cca.h"
#include "pkey.h"
#include "utils.h"

#include "debug.h"

#define pr_verbose(verbose, fmt...)	do {				\
						if (verbose)					\
							DEBUG(fmt);					\
					} while (0)

/*
 * Definitions for the CCA library
 */
#define CCA_LIBRARY_NAME	"libcsulcca.so"
#define CCA_WEB_PAGE		"http://www.ibm.com/security/cryptocards"
#define CCA_DOMAIN_ENVAR	"CSU_DEFAULT_DOMAIN"
#define CCA_ADAPTER_ENVAR	"CSU_DEFAULT_ADAPTER"

extern const uint16_t curve2bitlen[];

#define CCA_CURVE_TYPE_PRIME              0
#define CCA_CURVE_TYPE_EDWARDS            2

const uint8_t curve2ccatype[] = {
	CCA_CURVE_TYPE_PRIME,
	CCA_CURVE_TYPE_PRIME,
	CCA_CURVE_TYPE_PRIME,
	CCA_CURVE_TYPE_EDWARDS,
	CCA_CURVE_TYPE_EDWARDS
};

/**
 * Prints CCA return and reason code information for certain known CCA
 * error situations.
 *
 * @param return_code  the CCA return code
 * @param reason_code  the CCA reason code
 */
static void print_CCA_error(int return_code, int reason_code)
{
	switch (return_code) {
	case 8:
		switch (reason_code) {
		case 48:
			DEBUG("The secure key has a CCA master key "
			      "verification pattern that is not valid");
			break;
		case 90:
			DEBUG("The operation has been rejected due to access "
			      "control checking");
			break;
		case 2143:
			DEBUG("The operation has been rejected due to key "
			      "export restrictions of the secure key");
			break;
		}
		break;
	case 12:
		switch (reason_code) {
		case 764:
			DEBUG("The CCA master key is not loaded and "
			      "therefore a secure key cannot be enciphered");
			break;
		}
		break;
	}
}

/**
 * Returns the version, release and modification number of the used CCA library.
 *
 * @param[in] cca           the CCA library structure
 * @param[in] verbose       if true, verbose messages are printed
 *
 * @returns 0 on success, a negative errno in case of an error
 */
static int get_cca_version(struct cca_lib *cca, bool verbose)
{
	unsigned char exit_data[4] = { 0, };
	unsigned char version_data[20];
	long return_code, reason_code;
	long version_data_length;
	long exit_data_len = 0;
	char date[20];

	util_assert(cca != NULL, "Internal error: cca is NULL");

	if (cca->lib_csulcca == NULL) {
		pr_verbose(verbose, "CCA host library not available.");
		return -ELIBACC;
	}

	if (cca->dll_CSUACFV == NULL) {
		pr_verbose(verbose, "CCA host lib function CSUACFV not "
				"available but required for getting the CCA library version.");
		return -ELIBACC;
	}

	memset(version_data, 0, sizeof(version_data));
	version_data_length = sizeof(version_data);
	cca->dll_CSUACFV(&return_code, &reason_code,
			 &exit_data_len, exit_data,
			 &version_data_length, version_data);
	pr_verbose(verbose, "CSUACFV (Cryptographic Facility Version) "
		   "returned: return_code: %ld, reason_code: %ld", return_code,
		   reason_code);
	if (return_code != 0) {
		print_CCA_error(return_code, reason_code);
		return -EIO;
	}

	version_data[sizeof(version_data) - 1] = '\0';
	pr_verbose(verbose, "CCA Version string: %s", version_data);

	if (sscanf((char *)version_data, "%u.%u.%uz%s", &cca->version.ver,
		   &cca->version.rel, &cca->version.mod, date) != 4) {
		DEBUG("CCA library version is invalid: %s", version_data);
		return -EINVAL;
	}

	return 0;
}

/**
 * Loads the CCA library and provides the entry point of the CSNBKTC function.
 *
 * @param[out] cca           on return this contains the address of the CCA
 *                           library and certain CCA symbols. dlclose() should
 *                           be used to free the library when no longer needed.
 * @param verbose            if true, verbose messages are printed
 *
 * @returns 0 on success, -ELIBACC in case of library load errors
 */
int load_cca_library(struct cca_lib *cca, bool verbose)
{
	util_assert(cca != NULL, "Internal error: cca is NULL");

	/* Load the CCA library */
	cca->lib_csulcca = dlopen(CCA_LIBRARY_NAME, RTLD_GLOBAL | RTLD_NOW);
	if (cca->lib_csulcca == NULL) {
		pr_verbose(verbose, "%s", dlerror());
		DEBUG("The command requires the IBM CCA Host Libraries and "
		      "Tools.\nFor the supported environments and downloads, "
		      "see:\n%s", CCA_WEB_PAGE);
		return  -ELIBACC;
	}

	/* Get the Cryptographic Facility Version function */
	cca->dll_CSUACFV = (t_CSUACFV)dlsym(cca->lib_csulcca, "CSUACFV");

	/* Get the Key Token Change function */
	cca->dll_CSNBKTC = (t_CSNBKTC)dlsym(cca->lib_csulcca, "CSNBKTC");

	/* Get the Key Token Change 2 function */
	cca->dll_CSNBKTC2 = (t_CSNBKTC2)dlsym(cca->lib_csulcca, "CSNBKTC2");

	/* Get the Cryptographic Facility Query function */
	cca->dll_CSUACFQ = (t_CSUACFQ)dlsym(cca->lib_csulcca, "CSUACFQ");

	/* Get the Cryptographic Resource Allocate function */
	cca->dll_CSUACRA = (t_CSUACRA)dlsym(cca->lib_csulcca, "CSUACRA");

	/* Cryptographic Resource Deallocate function */
	cca->dll_CSUACRD = (t_CSUACRD)dlsym(cca->lib_csulcca, "CSUACRD");

	/* Get the Key Token Build 2 function */
	cca->dll_CSNBKTB2 = (t_CSNBKTB2)dlsym(cca->lib_csulcca, "CSNBKTB2");

	/* Get the Key Translate 2 function */
	cca->dll_CSNBKTR2 = (t_CSNBKTR2)dlsym(cca->lib_csulcca, "CSNBKTR2");

	/* Get the Restrict Key Attribute function */
	cca->dll_CSNBRKA = (t_CSNBRKA)dlsym(cca->lib_csulcca, "CSNBRKA");

	/* Get the PKA Key Token Build function */
	cca->dll_CSNDPKB = (t_CSNDPKB)dlsym(cca->lib_csulcca, "CSNDPKB");

	/* Get the PKA Key Generate function */
	cca->dll_CSNDPKG = (t_CSNDPKG)dlsym(cca->lib_csulcca, "CSNDPKG");

	/* Get the PKA Public Key Extract function */
	cca->dll_CSNDPKX = (t_CSNDPKX)dlsym(cca->lib_csulcca, "CSNDPKX");

	/* Get the PKA Key Import function */
	cca->dll_CSNDPKI = (t_CSNDPKI)dlsym(cca->lib_csulcca, "CSNDPKI");

	/* Get the PKA Key Token Change function (for ECC keys) */
	cca->dll_CSNDKTC = (t_CSNDKTC)dlsym(cca->lib_csulcca, "CSNDKTC");

	if (cca->dll_CSUACFV == NULL ||
	    cca->dll_CSNBKTC == NULL ||
	    cca->dll_CSNBKTC2 == NULL ||
	    cca->dll_CSUACFQ == NULL ||
	    cca->dll_CSUACRA == NULL ||
	    cca->dll_CSUACRD == NULL ||
	    cca->dll_CSNBKTB2 == NULL ||
	    cca->dll_CSNBKTR2 == NULL ||
	    cca->dll_CSNBRKA == NULL ||
	    cca->dll_CSNDPKB == NULL ||
	    cca->dll_CSNDPKG == NULL ||
	    cca->dll_CSNDPKX == NULL ||
	    cca->dll_CSNDPKI == NULL ||
	    cca->dll_CSNDKTC == NULL) {
		pr_verbose(verbose, "%s", dlerror());
		DEBUG("The command requires the IBM CCA Host Libraries and "
		      "Tools.\nFor the supported environments and downloads, "
		      "see:\n%s", CCA_WEB_PAGE);
		return -ELIBACC;
	}

	pr_verbose(verbose, "CCA library '%s' has been loaded successfully",
		   CCA_LIBRARY_NAME);

	return get_cca_version(cca, verbose);
}

/**
 * Re-enciphers a secure key.
 *
 * @param[in] cca              the CCA libraray structure
 * @param[in] secure_key       a buffer containing the secure key
 * @param[in] secure_key_size  the size of the secure key
 * @param[in] method           the re-enciphering method. METHOD_OLD_TO_CURRENT
 *                             or METHOD_CURRENT_TO_NEW.
 * @param[in] verbose          if true, verbose messages are printed
 *
 * @returns 0 on success, -EIO in case of an error
 */
int key_token_change(struct cca_lib *cca,
		     u8 *secure_key, unsigned int secure_key_size,
		     char *method, bool verbose)
{
	struct aescipherkeytoken *cipherkey =
				(struct aescipherkeytoken *)secure_key;
	long exit_data_len = 0, rule_array_count;
	unsigned char rule_array[2 * 8] = { 0, };
	unsigned char exit_data[4] = { 0, };
	long return_code, reason_code;
	long key_token_length;

	util_assert(cca != NULL, "Internal error: cca is NULL");
	util_assert(secure_key != NULL, "Internal error: secure_key is NULL");
	util_assert(secure_key_size > 0,
		    "Internal error: secure_key_size is 0");
	util_assert(method != NULL, "Internal error: method is NULL");

	memcpy(rule_array, method, 8);
	rule_array_count = 1;

	if (is_cca_aes_data_key(secure_key, secure_key_size)) {

		if (cca->dll_CSNBKTC == NULL) {
			pr_verbose(verbose, "CCA host lib function CSNBKTC not "
					"available but required for AES data key token change.");
			return -ELIBACC;
		}

		memcpy(rule_array + 8, "AES     ", 8);
		rule_array_count++;
		cca->dll_CSNBKTC(&return_code, &reason_code,
				 &exit_data_len, exit_data,
				 &rule_array_count, rule_array,
				 secure_key);

		pr_verbose(verbose, "CSNBKTC (Key Token Change) with '%s' "
			   "returned: return_code: %ld, reason_code: %ld",
			   method, return_code, reason_code);

	} else if (is_cca_aes_cipher_key(secure_key, secure_key_size)) {

		if (cca->dll_CSNBKTC2 == NULL) {
			pr_verbose(verbose, "CCA host lib function CSNBKTC2 not "
					"available but required for AES cipher key token change.");
			return -ELIBACC;
		}

		memcpy(rule_array + 8, "AES     ", 8);
		rule_array_count++;
		key_token_length = cipherkey->length;
		cca->dll_CSNBKTC2(&return_code, &reason_code,
				  &exit_data_len, exit_data,
				  &rule_array_count, rule_array,
				  &key_token_length,
				  (unsigned char *)cipherkey);

		pr_verbose(verbose, "CSNBKTC2 (Key Token Change2) with '%s' "
			   "returned: return_code: %ld, reason_code: %ld",
			   method, return_code, reason_code);

		pr_verbose(verbose, "key_token_length: %lu", key_token_length);

	} else if (is_cca_ec_key(secure_key, secure_key_size)) {

		if (cca->dll_CSNDKTC == NULL) {
			pr_verbose(verbose, "CCA host lib function CSNDKTC not "
					"available but required for ECC key token change.");
			return -ELIBACC;
		}

		memcpy(rule_array + 8, "ECC     ", 8);
		rule_array_count++;
		key_token_length = secure_key_size;
		cca->dll_CSNDKTC(&return_code, &reason_code,
				&exit_data_len, exit_data,
				&rule_array_count, rule_array,
				&key_token_length,
				secure_key);

		pr_verbose(verbose, "CSNDKTC (PKA Key Token Change) with '%s' "
			"returned: return_code: %ld, reason_code: %ld",
			method, return_code, reason_code);

		pr_verbose(verbose, "key_token_length: %lu", key_token_length);
	} else {
		DEBUG("Invalid key type specified");
		return -EINVAL;
	}

	if (return_code != 0) {
		print_CCA_error(return_code, reason_code);
		return -EIO;
	}

	if (is_xts_key(secure_key, secure_key_size)) {
		if (is_cca_aes_data_key(secure_key, secure_key_size)) {
			cca->dll_CSNBKTC(&return_code, &reason_code,
					 &exit_data_len, exit_data,
					 &rule_array_count, rule_array,
					 secure_key + AESDATA_KEY_SIZE);

			pr_verbose(verbose, "CSNBKTC (Key Token Change) with "
				   "'%s' returned: return_code: %ld, "
				   "reason_code: %ld", method, return_code,
				   reason_code);
		} else if (is_cca_aes_cipher_key(secure_key, secure_key_size)) {
			cipherkey = (struct aescipherkeytoken *)(secure_key +
							AESCIPHER_KEY_SIZE);
			key_token_length = cipherkey->length;
			cca->dll_CSNBKTC2(&return_code, &reason_code,
					 &exit_data_len, exit_data,
					 &rule_array_count, rule_array,
					 &key_token_length,
					 (unsigned char *)cipherkey);

			pr_verbose(verbose, "CSNBKTC2 (Key Token Change2) with "
				  "'%s' returned: return_code: %ld, "
				  "reason_code: %ld", method, return_code,
				  reason_code);

			pr_verbose(verbose, "key_token_length: %lu",
				   key_token_length);
		} else {
			DEBUG("Invalid key type specified");
			return -EINVAL;
		}

		if (return_code != 0) {
			print_CCA_error(return_code, reason_code);
			return -EIO;
		}
	}

	return 0;
}

/**
 * Queries the number of adapters known by the CCA host library
 *
 * @param[in] cca              the CCA library structure
 * @param[out] adapters        the number of adapters
 * @param[in] verbose          if true, verbose messages are printed
 *
 * @returns 0 on success, a negative errno in case of an error.
 */
static int get_number_of_cca_adapters(struct cca_lib *cca,
				      unsigned int *adapters, bool verbose)
{
	long exit_data_len = 0, rule_array_count, verb_data_length = 0;
	unsigned char rule_array[16 * 8] = { 0, };
	unsigned char exit_data[4] = { 0, };
	long return_code, reason_code;

	util_assert(cca != NULL, "Internal error: cca is NULL");
	util_assert(adapters != NULL, "Internal error: adapters is NULL");

	if (cca->dll_CSUACFQ == NULL) {
		pr_verbose(verbose, "CCA host lib function CSUACFQ not "
				"available but required for getting number of CCA adapters.");
		return -ELIBACC;
	}

	memset(rule_array, 0, sizeof(rule_array));
	memcpy(rule_array, "STATCRD2", 8);
	rule_array_count = 1;

	cca->dll_CSUACFQ(&return_code, &reason_code,
			 &exit_data_len, exit_data,
			 &rule_array_count, rule_array,
			 &verb_data_length, NULL);

	pr_verbose(verbose, "CSUACFQ (Cryptographic Facility Query) returned: "
		   "return_code: %ld, reason_code: %ld", return_code,
		   reason_code);
	if (return_code != 0) {
		print_CCA_error(return_code, reason_code);
		return -EIO;
	}

	rule_array[8] = '\0';
	if (sscanf((char *)rule_array, "%u", adapters) != 1) {
		pr_verbose(verbose, "Unparsable output: %s", rule_array);
		return -EIO;
	}

	pr_verbose(verbose, "Number of CCA adapters: %u", *adapters);
	return 0;
}

/**
 * Allocate a specific CCA adapter.
 *
 * @param[in] cca              the CCA library structure
 * @param[in] adapter          the adapter number, starting at 1. If 0 is
 *                             specified, then the AUTOSELECT option is
 *                             enabled.
 * @param[in] verbose          if true, verbose messages are printed
 *
 * @returns 0 on success, a negative errno in case of an error. -ENODEV is
 *          returned if the adapter is not available.
 */
static int allocate_cca_adapter(struct cca_lib *cca, unsigned int adapter,
				bool verbose)
{
	long exit_data_len = 0, rule_array_count;
	unsigned char rule_array[8] = { 0, };
	unsigned char exit_data[4] = { 0, };
	long return_code, reason_code;
	char res_name[9];
	long res_name_len;

	util_assert(cca != NULL, "Internal error: cca is NULL");

	if (cca->dll_CSUACRA == NULL) {
		pr_verbose(verbose, "CCA host lib function CSUACRA not "
				"available but required for allocate CCA adapter.");
		return -ELIBACC;
	}

	if (adapter > 0)
		memcpy(rule_array, "DEVICE  ", 8);
	else
		memcpy(rule_array, "DEV-ANY ", 8);
	rule_array_count = 1;

	sprintf(res_name, "CRP%02d", adapter);
	res_name_len = strlen(res_name);

	cca->dll_CSUACRA(&return_code, &reason_code,
			 &exit_data_len, exit_data,
			 &rule_array_count, rule_array,
			 &res_name_len, (unsigned char *)res_name);

	pr_verbose(verbose, "CSUACRA (Cryptographic Resource Allocate) "
		   "returned: return_code: %ld, reason_code: %ld", return_code,
		   reason_code);
	if (return_code != 0) {
		print_CCA_error(return_code, reason_code);
		return -ENODEV;
	}

	pr_verbose(verbose, "Adapter %u (%s) allocated", adapter, res_name);
	return 0;
}

/**
 * Deallocate a specific CCA adapter.
 *
 * @param[in] cca              the CCA library structure
 * @param[in] adapter          the adapter number, starting at 1. If 0 is
 *                             specified, then the AUTOSELECT option is
 *                             disabled.
 * @param[in] verbose          if true, verbose messages are printed
 *
 * @returns 0 on success, a negative errno in case of an error. -ENODEV is
 *          returned if the adapter is not available.
 */
static int deallocate_cca_adapter(struct cca_lib *cca, unsigned int adapter,
				  bool verbose)
{
	long exit_data_len = 0, rule_array_count;
	unsigned char rule_array[8] = { 0, };
	unsigned char exit_data[4] = { 0, };
	long return_code, reason_code;
	char res_name[9];
	long res_name_len;

	util_assert(cca != NULL, "Internal error: cca is NULL");

	if (cca->dll_CSUACRD == NULL) {
		pr_verbose(verbose, "CCA host lib function CSUACRD not "
				"available but required for deallocate CCA adapter.");
		return -ELIBACC;
	}

	if (adapter > 0)
		memcpy(rule_array, "DEVICE  ", 8);
	else
		memcpy(rule_array, "DEV-ANY ", 8);
	rule_array_count = 1;

	sprintf(res_name, "CRP%02d", adapter);
	res_name_len = strlen(res_name);

	cca->dll_CSUACRD(&return_code, &reason_code,
			 &exit_data_len, exit_data,
			 &rule_array_count, rule_array,
			 &res_name_len, (unsigned char *)res_name);

	pr_verbose(verbose, "CSUACRD (Cryptographic Resource Deallocate) "
		   "returned: return_code: %ld, reason_code: %ld", return_code,
		   reason_code);
	if (return_code != 0) {
		print_CCA_error(return_code, reason_code);
		return -ENODEV;
	}

	pr_verbose(verbose, "Adapter %u (%s) deallocated", adapter, res_name);
	return 0;
}

/**
 * Queries the serial number of the current CCA adapter
 *
 * @param[in] cca              the CCA library structure
 * @param[out] serialnr        the buffer where the serial number is returned
 * @param[in] verbose          if true, verbose messages are printed
 *
 * @returns 0 on success, a negative errno in case of an error.
 */
static int get_cca_adapter_serialnr(struct cca_lib *cca, char serialnr[9],
				    bool verbose)
{
	long exit_data_len = 0, rule_array_count, verb_data_length = 0;
	unsigned char rule_array[16 * 8] = { 0, };
	unsigned char exit_data[4] = { 0, };
	long return_code, reason_code;

	util_assert(cca != NULL, "Internal error: cca is NULL");

	if (cca->dll_CSUACFQ == NULL) {
		pr_verbose(verbose, "CCA host lib function CSUACFQ not "
				"available but required for get adapter serialnr.");
		return -ELIBACC;
	}

	memset(rule_array, 0, sizeof(rule_array));
	memcpy(rule_array, "STATCRD2", 8);
	rule_array_count = 1;

	cca->dll_CSUACFQ(&return_code, &reason_code,
			 &exit_data_len, exit_data,
			 &rule_array_count, rule_array,
			 &verb_data_length, NULL);

	pr_verbose(verbose, "CSUACFQ (Cryptographic Facility Query) returned: "
		   "return_code: %ld, reason_code: %ld", return_code,
		   reason_code);
	if (return_code != 0) {
		print_CCA_error(return_code, reason_code);
		return -EIO;
	}

	memcpy(serialnr, rule_array+14*8, 8);
	serialnr[8] = '\0';

	pr_verbose(verbose, "Serial number of CCA adapter: %s", serialnr);
	return 0;
}

/**
 * Selects the specified APQN to be used for the CCA host library.
 *
 * @param[in] cca              the CCA library structure
 * @param[in] card             the card number
 * @param[in] domain           the domain number
 * @param[in] verbose          if true, verbose messages are printed
 *
 * @returns 0 on success, a negative errno in case of an error. -ENOTSUP is
 *          returned when the serialnr sysfs attribute is not available,
 *          because the zcrypt kernel module is on an older level. -ENODEV is
 *          returned if the APQN is not available.
 */
int select_cca_adapter(struct cca_lib *cca, unsigned int card,
		       unsigned int domain, bool verbose)
{
	unsigned int adapters, adapter;
	char adapter_serialnr[9];
	char apqn_serialnr[SERIALNR_LENGTH];
	char temp[10];
	int rc, found = 0;

	util_assert(cca != NULL, "Internal error: cca is NULL");

	pr_verbose(verbose, "Select %02x.%04x for the CCA host library", card,
		   domain);

	rc = sysfs_get_serialnr(card, apqn_serialnr, verbose);
	if (rc != 0) {
		pr_verbose(verbose, "Failed to get the serial number: %s",
			   strerror(-rc));
		return rc;
	}

	sprintf(temp, "%u", domain);
	if (setenv(CCA_DOMAIN_ENVAR, temp, 1) != 0) {
		rc = -errno;
		pr_verbose(verbose, "Failed to set the %s environment variable:"
			   " %s", CCA_DOMAIN_ENVAR, strerror(-rc));
		return rc;
	}
	unsetenv(CCA_ADAPTER_ENVAR);

	/*
	 * Unload and reload the CCA host library so that it recognizes the
	 * changed CSU_DEFAULT_DOMAIN environment variable value.
	 */
	if (cca->lib_csulcca != NULL)
		dlclose(cca->lib_csulcca);
	memset(cca, 0, sizeof(struct cca_lib));

	rc = load_cca_library(cca, verbose);
	if (rc != 0)
		return rc;

	rc = get_number_of_cca_adapters(cca, &adapters, verbose);
	if (rc != 0)
		return rc;

	/* Deallocate any adapter first, in case one is already allocated */
	for (adapter = 1; adapter <= adapters; adapter++)
		deallocate_cca_adapter(cca, adapter, false);

	/* Disable the AUTOSELECT option */
	rc = deallocate_cca_adapter(cca, 0, verbose);
	if (rc != 0)
		return rc;

	for (adapter = 1; adapter <= adapters; adapter++) {
		rc = allocate_cca_adapter(cca, adapter, verbose);
		if (rc != 0)
			return rc;

		rc = get_cca_adapter_serialnr(cca, adapter_serialnr, verbose);
		if (rc == 0) {
			if (memcmp(apqn_serialnr, adapter_serialnr, 8) == 0) {
				found = 1;
				break;
			}
		}

		rc = deallocate_cca_adapter(cca, adapter, verbose);
		if (rc != 0)
			return rc;
	}

	if (!found)
		return -ENODEV;

	pr_verbose(verbose, "Selected adapter %u (CRP%02d)", adapter, adapter);
	return 0;
}

/**
 * Setup rule array for key token build:
 *   defaults:
 *     - XPRTCPAC : make the secure key CPACF exportable
 *     - KEY-MGMT : digital signature generate (prime curves)
 *     - SIG-ONLY : digital signature generate (edwards curves)
 *   via flags:
 *     - AES1ECOK : allow export using an AES key of similar strength
 */
void setup_rule_array(int curve, unsigned int flags, uint8_t *rule_array_buf,
					long *rule_array_count)
{
	memcpy(rule_array_buf, "ECC-PAIR", CCA_KEYWORD_SIZE);
	*rule_array_count = 1;
	memcpy(rule_array_buf + *rule_array_count * CCA_KEYWORD_SIZE, "XPRTCPAC", CCA_KEYWORD_SIZE);
	(*rule_array_count)++;

	switch (curve2ccatype[curve]) {
	case CCA_EC_CURVE_TYPE_PRIME:
		memcpy(rule_array_buf + *rule_array_count * CCA_KEYWORD_SIZE, "KEY-MGMT", CCA_KEYWORD_SIZE);
		break;
	case CCA_EC_CURVE_TYPE_EDWARDS:
		memcpy(rule_array_buf + *rule_array_count * CCA_KEYWORD_SIZE, "SIG-ONLY", CCA_KEYWORD_SIZE);
		break;
	}
	(*rule_array_count)++;

	/* Add user-defined flags: the only flag that is currently recognized here,
	 * is PKEY_KEYGEN_XPRT_AES : Allow export using an AES key. */
	if ((flags & PKEY_KEYGEN_XPRT_AES) == PKEY_KEYGEN_XPRT_AES) {
		memcpy(rule_array_buf + *rule_array_count * CCA_KEYWORD_SIZE, "AES1ECOK", CCA_KEYWORD_SIZE);
		(*rule_array_count)++;
	}
}

/**
 * Setup key value structure for key token build.
 */
void setup_key_value_struct(uint8_t *kvs_buf, long *kvs_len, int curve,
						const unsigned char *pubkey, unsigned int publen,
						const unsigned char *privkey, unsigned int privlen)
{
	ECC_PAIR ecc_pair;

	ecc_pair.curve_type = curve2ccatype[curve];
	ecc_pair.reserved = 0x00;
	ecc_pair.p_bitlen = curve2bitlen[curve];
	ecc_pair.d_length = privlen;
	ecc_pair.q_length = publen;

	memcpy(kvs_buf, &ecc_pair, sizeof(ECC_PAIR));

	if (privlen > 0)
		memcpy(kvs_buf + sizeof(ECC_PAIR), privkey, privlen);

	*kvs_len = sizeof(ECC_PAIR) + privlen;

	if (publen > 0) {
		if (curve2ccatype[curve] == CCA_EC_CURVE_TYPE_PRIME) {
			memset(kvs_buf + sizeof(ECC_PAIR) + privlen, 0x04, 1);
			memcpy(kvs_buf + sizeof(ECC_PAIR) + privlen + 1, pubkey, publen);
			ecc_pair.q_length = publen + 1;
			*kvs_len = *kvs_len + 1 + publen;
		} else {
			/* Edwards curves do not have a compression indication in the kvs struct */
			memcpy(kvs_buf + sizeof(ECC_PAIR) + privlen, pubkey, publen);
			*kvs_len = *kvs_len + publen;
		}
	}
}

int ec_key_generate_cca(struct cca_lib *cca, int curve, unsigned int flags,
				unsigned char *secure_key, unsigned int *seclen,
				unsigned char *public_key, unsigned int *publen,
				bool verbose)
{
	unsigned char kvs_buf[CCA_EC_KEY_VALUE_STRUCT_SIZE] = { 0 };
	unsigned char rule_array[CCA_RULE_ARRAY_SIZE] = { 0 };
	unsigned char skel_token[CCA_KEY_TOKEN_SIZE] = { 0 };
	unsigned char trans_key[CCA_TRANSPORT_KEY_SIZE] = { 0 };
	unsigned char ecc_token[CCA_KEY_TOKEN_SIZE] = { 0 };
	unsigned char exit_data[4] = { 0 };
	unsigned char buf[132] = { 0 };
	long skel_token_len = sizeof(skel_token);
	long ecc_token_len = sizeof(ecc_token);
	long regen_data_len = 0, kvs_len = 0, exit_data_len = 0;
	long return_code = 0, reason_code = 0, key_name_len = 0;
	long rlen1 = 0, rlen2 = 0, rlen3 = 0, rlen4 = 0, rlen5 = 0;
	long rule_array_count = 0;
	unsigned int buflen = sizeof(buf);
	int rc;

	if (cca->dll_CSNDPKB == NULL || cca->dll_CSNDPKG == NULL) {
		pr_verbose(verbose, "CCA host lib function CSNDPKB and/or CSNDPKG not "
				"available but required for EC key generate.");
		return -ELIBACC;
	}

	*seclen = 0;
	*publen = 0;

	/* Create skeleton token */
	setup_rule_array(curve, flags, rule_array, &rule_array_count);
	setup_key_value_struct(kvs_buf, &kvs_len, curve, NULL, 0, NULL, 0);

	cca->dll_CSNDPKB(&return_code, &reason_code, &exit_data_len, exit_data,
			&rule_array_count, rule_array, &kvs_len, kvs_buf,
			&key_name_len, NULL, &rlen1, NULL, &rlen2, NULL, &rlen3, NULL,
			&rlen4, NULL, &rlen5, NULL, &skel_token_len, skel_token);

	pr_verbose(verbose, "CSNDPKB (PKA Key Token Build) "
			"returned: return_code: %ld, reason_code: %ld", return_code,
			reason_code);

	if (return_code != 0) {
		print_CCA_error(return_code, reason_code);
		return -EIO;
	}

	/* Generate secure key token */
	memcpy(rule_array, "MASTER  ", CCA_KEYWORD_SIZE);
	rule_array_count = 1;
	cca->dll_CSNDPKG(&return_code, &reason_code, &exit_data_len, exit_data,
			&rule_array_count, rule_array, &regen_data_len, NULL,
			&skel_token_len, skel_token, trans_key, &ecc_token_len,
			(unsigned char *)&ecc_token);

	pr_verbose(verbose, "CSNDPKG (PKA Key Generate) "
			"returned: return_code: %ld, reason_code: %ld", return_code,
			reason_code);

	if (return_code != 0) {
		print_CCA_error(return_code, reason_code);
		return -EIO;
	}

	memcpy(secure_key, ecc_token, ecc_token_len);
	*seclen = ecc_token_len;

	/* Extract public key from secure key token */
	rc = ec_key_extract_public_cca(cca, ecc_token, ecc_token_len,
				(unsigned char *)&buf, &buflen, verbose);
	if (rc == 0 && buflen > 0) {
		memcpy(public_key, buf, buflen);
		*publen = buflen;
	}

	return 0;
}

/**
 * Extract the public key out if the given secure key blob. A public key can
 * only be obtained, if it is already contained in the token. The host lib
 * does not re-calculate the public key from the given private key.
 */
int ec_key_extract_public_cca(struct cca_lib *cca, unsigned char *ecc_token,
				unsigned int ecc_token_len, unsigned char *ecc_pub_token,
				unsigned int *p_ecc_pub_token_len, bool verbose)
{
	unsigned char rule_array_buf[CCA_RULE_ARRAY_SIZE] = { 0 };
	unsigned char buf[CCA_EC_KEY_VALUE_STRUCT_SIZE] = { 0 };
	unsigned char exit_data[4];
	long return_code = 0, reason_code = 0, exit_data_len = 0;
	long rule_array_count = 0;
	long buflen = sizeof(buf);
	struct eccpubtoken *pubtok;

	if (cca->dll_CSNDPKX == NULL) {
		pr_verbose(verbose, "CCA host lib function CSNDPKX not "
				"available but required for public key extract.");
		return -ELIBACC;
	}

	/* Extract the public key from secure key token */
	cca->dll_CSNDPKX(&return_code, &reason_code, &exit_data_len, exit_data,
			&rule_array_count, rule_array_buf, (long *)&ecc_token_len, ecc_token,
			&buflen, (unsigned char *)&buf);

	pr_verbose(verbose, "CSNDPKX (PKA Public Key Extract) "
			"returned: return_code: %ld, reason_code: %ld", return_code,
			reason_code);

	if (return_code != 0) {
		print_CCA_error(return_code, reason_code);
		return -EIO;
	}

	/* Copy result: public token comes after the CCA header */
	pubtok = (struct eccpubtoken *)&buf[CCA_EC_HEADER_SIZE];
	if (pubtok->curve_type == CCA_EC_CURVE_TYPE_PRIME) {
		/* Remove indication for uncompressed key 0x04 */
		memcpy(ecc_pub_token, pubtok->q + 1, pubtok->q_len - 1);
		*p_ecc_pub_token_len = pubtok->q_len - 1;
	} else {
		memcpy(ecc_pub_token, pubtok->q, pubtok->q_len);
		*p_ecc_pub_token_len = pubtok->q_len;
	}

	return 0;
}

int ec_key_clr2sec_cca(struct cca_lib *cca, int curve, unsigned int flags,
				unsigned char *secure_key, unsigned int *seclen,
				const unsigned char *pubkey, unsigned int publen,
				const unsigned char *privkey, unsigned int privlen,
				bool verbose)
{
	unsigned char private_key_name[CCA_PRIVATE_KEY_NAME_SIZE] = { 0, };
	unsigned char rule_array[CCA_RULE_ARRAY_SIZE] = { 0, };
	unsigned char transport_key_identifier[CCA_KEY_ID_SIZE] = { 0, };
	unsigned char target_key_token[CCA_KEY_TOKEN_SIZE] = { 0, };
	unsigned char kvs_buf[CCA_EC_KEY_VALUE_STRUCT_SIZE] = { 0, };
	unsigned char key_token[CCA_KEY_TOKEN_SIZE] = { 0, };
	unsigned char *exit_data = NULL, *param2 = NULL;
	long return_code = 0, reason_code = 0, rule_array_count = 0;
	long exit_data_len = 0, kvs_len = 0, private_key_name_length = 0;
	long key_token_length = CCA_KEY_TOKEN_SIZE;
	long param1 = 0, target_key_token_length = 0;

	if (cca->dll_CSNDPKB == NULL || cca->dll_CSNDPKI == NULL) {
		pr_verbose(verbose, "CCA host lib function CSNDPKB and/or CSNDPKI not "
				"available but required for clear key import.");
		return -ELIBACC;
	}

	setup_key_value_struct(kvs_buf, &kvs_len, curve, pubkey, publen, privkey, privlen);
	setup_rule_array(curve, flags, rule_array, &rule_array_count);

	cca->dll_CSNDPKB(&return_code, &reason_code, &exit_data_len, exit_data,
			&rule_array_count, rule_array, &kvs_len, kvs_buf,
			&private_key_name_length, private_key_name,
			&param1, param2, &param1, param2, &param1, param2, &param1, param2,
			&param1, param2, &key_token_length, key_token);

	pr_verbose(verbose, "CSNDPKB (PKA Key Token Build) "
			"returned: return_code: %ld, reason_code: %ld", return_code,
			reason_code);

	if (return_code != 0) {
		print_CCA_error(return_code, reason_code);
		return -EIO;
	}

	/* Now import the PKA key token */
	memcpy(rule_array, "ECC     ", CCA_KEYWORD_SIZE);
	rule_array_count = 1;

	key_token_length = CCA_KEY_TOKEN_SIZE;
	target_key_token_length = CCA_KEY_TOKEN_SIZE;

	cca->dll_CSNDPKI(&return_code, &reason_code, NULL, NULL, &rule_array_count,
			rule_array, &key_token_length, key_token, transport_key_identifier,
			&target_key_token_length, target_key_token);

	pr_verbose(verbose, "CSNDPKI (PKA Key Import) "
			"returned: return_code: %ld, reason_code: %ld", return_code,
			reason_code);

	if (return_code != 0) {
		print_CCA_error(return_code, reason_code);
		return -EIO;
	}

	memcpy(secure_key, target_key_token, target_key_token_length);
	*seclen = target_key_token_length;

	return 0;
}
