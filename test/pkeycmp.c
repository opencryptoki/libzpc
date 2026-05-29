// SPDX-License-Identifier: MIT
// Copyright contributors to the libzpc project
#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <openssl/err.h>
#include <openssl/pem.h>

static const char *comm = NULL;

static EVP_PKEY *pkey_read(const char *path)
{
	BIO *bin = BIO_new_file(path, "r");
	EVP_PKEY *pkey = NULL;

	if (!bin)
		goto out;

	pkey = PEM_read_bio_PrivateKey(bin, &pkey, NULL, NULL);
	if (pkey)
		goto out;

	if (BIO_reset(bin) > 0)
		goto out;
	pkey = PEM_read_bio_PUBKEY(bin, &pkey, NULL, NULL);
out:
	BIO_free(bin);
	return pkey;
}

static void usage(const char *msg, const char *arg)
{
	if (msg)
		fprintf(stdout, "%s%s\n", msg, arg ?: "");
	fprintf(stderr, "Usage:\n");
	fprintf(stderr, "  %s --in1|-1 --in2|-2 [--help|-h]\n", comm);
	fprintf(stderr, "  -1, --in1 <FILE>              First input file\n");
	fprintf(stderr, "  -2, --in2 <FILE>              Second input file\n");
	fprintf(stderr, "  -h, --help                    Show short help\n");
}

int main(int argc, char *argv[])
{
	static const struct option long_options[] = {
		{ "in1",   required_argument, NULL, '1' },
		{ "in2",   required_argument, NULL, '2' },
		{ "quiet", no_argument,       NULL, 'q' },
		{ "help",  no_argument,       NULL, 'h' },
		{ NULL,    0,                 NULL,  0  }
	};
	static const char options[] = "1:2:qh";
	EVP_PKEY *pkey1 = NULL, *pkey2 = NULL;
	const char *in1 = NULL, *in2 = NULL;
	bool quiet = false;
	int opt, rc = 1;

	comm = argv[0];

	while ((opt = getopt_long(argc, argv, options, long_options, NULL)) != -1) {
		switch (opt) {
		case '1':
			in1 = optarg;
			break;
		case '2':
			in2 = optarg;
			break;
		case 'q':
			quiet = true;
			break;
		case 'h':
			usage(NULL, NULL);
			goto out;
		default:
			usage("Unknown argument", optarg);
			goto out;
		}
	}

	if (optind < argc) {
		usage("Wrong arguments", NULL);
		goto out;
	}

	if (!in1 || !in2) {
		usage("Missing arguments", NULL);
		goto out;
	}

	if (!(pkey1 = pkey_read(in1))) {
		if (!quiet) {
			ERR_print_errors_fp(stderr);
			fprintf(stderr, "Unable to read EVP_PKEY from %s\n", in1);
		}
		goto out;
	}

	if (!(pkey2 = pkey_read(in2))) {
		if (!quiet) {
			ERR_print_errors_fp(stderr);
			fprintf(stderr, "Unable to read EVP_PKEY from %s\n", in2);
		}
		goto out;
	}

	rc = (EVP_PKEY_eq(pkey1, pkey2) == 1) ? 0 : 1;
	if (!quiet) {
		ERR_print_errors_fp(stderr);
		fprintf(stdout, "%s\n", !rc ? "match" : "no match");
	}
out:
	EVP_PKEY_free(pkey1);
	EVP_PKEY_free(pkey2);
	return rc;
}
