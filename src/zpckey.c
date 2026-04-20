// SPDX-License-Identifier: MIT
// Copyright contributors to the libzpc project

#include <endian.h>
#include <getopt.h>
#include <libgen.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <linux/types.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <openssl/obj_mac.h>
/* missing in obj_mac.h */
#ifndef SN_aes_128
#define SN_aes_128     "AES-128"
#endif
#ifndef SN_aes_192
#define SN_aes_192     "AES-192"
#endif
#ifndef SN_aes_256
#define SN_aes_256     "AES-256"
#endif

#include "ossl.h"
#include "misc.h"
#include "asn1.h"
#include "uri.h"
#include "zkey/pkey.h"

#ifndef XOR_LOG
#define XOR_LOG(a, b)	(!(a) != !(b))
#endif

static const char *comm = NULL;
static unsigned char id_raw[32] = { 0 };
static char id_hex[64 + 1] = { 0 };

enum outform {
	UNKNOWN = 0,
	URI,
	DER,
	PEM,
};

struct outform_entry {
	enum outform id;
	const char *str;
};

const struct outform_entry outform_map[] = {
	{ URI, "URI" },
	{ DER, "DER" },
	{ PEM, "PEM" },
	{ 0, NULL },
};

struct origin_type_entry {
	const char *type;
	const char *type_long;
};

static struct origin_type_entry origin_type_map[] = {
	{ "uv", "Ultravisor retrievable secrets" },
	{ NULL, NULL },
};

struct origin_alg_entry {
	const char *alg;
	const char *oid;
	bool asym;
};

static struct origin_alg_entry origin_alg_list[] = {
	{ SN_X9_62_prime256v1, "1.2.840.10045.3.1.7", true },
	{ SN_secp384r1, "1.3.132.0.34", true },
	{ SN_secp521r1, "1.3.132.0.35", true },
	{ SN_ED25519, "1.3.101.112", true },
	{ SN_ED448, "1.3.101.113", true },
	{ SN_aes_128, NULL, false },
	{ SN_aes_192, NULL, false },
	{ SN_aes_256, NULL, false },
	{ SN_aes_128_xts, NULL, false },
	{ SN_aes_256_xts, NULL, false },
	{ NULL, NULL, false },
};

static struct option options_compose[] = {
	{ "origin-type", required_argument, NULL, 't'},
	{ "origin-alg", required_argument, NULL, 'a'},
	{ "pubkey", required_argument, NULL, 'p'},
	{ "comment", required_argument, NULL, 'c'},
	{ "uv-secret-id", required_argument, NULL, 'S'},
	{ "uv-secret-name", required_argument, NULL, 'N'},
	{ "out", required_argument, NULL, 'o'},
	{ "outform", required_argument, NULL, 'O'},
	{ "help", no_argument, NULL, 'h'},
	{ NULL, 0, NULL, 0},
};
static const char *o_compose = "t:a:p:c:o:h";

static struct option options_show[] = {
	{ "in", required_argument, NULL, 'i'},
	{ "inform", required_argument, NULL, 'I'},
	{ "help", no_argument, NULL, 'h'},
	{ NULL, 0, NULL, 0},
};
static const char *o_show = "i:h";

struct opts_compose {
	const char *otype;
	const char *oalg;
	const char *comment;
	union {
		struct {
			const char *id_hex;
		} uv;
	};
	const char *pubkey;
	const char *out;
	enum outform outform;
	bool asym;
};

struct opts_show {
	const char *in;
	bool in_der;
};

static int usage_compose(const char *comm, const char *msg, const char *arg)
{
	struct origin_type_entry *ot;
	struct origin_alg_entry *oa;

	if (msg)
		fprintf(stderr, "%s%s\n", msg, arg ?: "");
	fprintf(stderr, "Usage:\n");
	fprintf(stderr, "  %s compose <REQ-ARGS> [<OPT-ARGS>] <ORIGIN-ARGS>\n", comm);
	fprintf(stderr, "\nRequired Arguments:\n");
	fprintf(stderr, "  -t, --origin-type <otype>     Protected Key Origin Type\n");
	fprintf(stderr, "  -a, --origin-alg <oalg>       Protected Key Origin Algorithm\n");
	fprintf(stderr, "\nProtected Key Origin Types (<otype>):\n");
	for (ot = origin_type_map; ot->type; ot++)
		fprintf(stderr, "  %-30s%s\n", ot->type, ot->type_long);
	fprintf(stderr, "\nProtected Key Origin Algorithms (<oalg>):\n");
	for (oa = origin_alg_list; oa->alg; oa++)
		oa->oid ? fprintf(stderr, "  %s (alt.: %s)\n", oa->alg, oa->oid)
			: fprintf(stderr, "  %s\n", oa->alg);
	fprintf(stderr, "\nOptional Arguments:\n");
	fprintf(stderr, "  -p, --pubkey <file>           Public Key file\n");
	fprintf(stderr, "  -o, --out <path>              Output file\n");
	fprintf(stderr, "      --outform <format>        Output file format URI, DER or PEM (default: PEM)\n");
	fprintf(stderr, "  -c, --comment <string>        Comment (metadata)\n");
	fprintf(stderr, "  -h, --help                    Show short help\n");
	fprintf(stderr, "\nOrigin Arguments:\n");
	fprintf(stderr, "      For <otype> = uv:\n");
	fprintf(stderr, "      --uv-secret-id <hexstring>   UV secret ID\n");
	fprintf(stderr, "      --uv-secret-name <string>    UV secret name\n");

	return 1;
}

static int usage_show(const char *comm, const char *msg, const char *arg)
{
	if (msg)
		fprintf(stderr, "%s%s\n", msg, arg ?: "");
	fprintf(stderr, "Usage:\n");
	fprintf(stderr, "  %s show <REQ-ARGS> [<OPT-ARGS>]\n", comm);
	fprintf(stderr, "\nRequired Arguments:\n");
	fprintf(stderr, "  -i, --in <file>               Input file\n");
	fprintf(stderr, "\nOptional Arguments:\n");
	fprintf(stderr, "      --inform <format>         Input file format PEM or DER (default: PEM)\n");
	fprintf(stderr, "  -h, --help                    Show short help\n");

	return 1;
}

static inline const char *skip_0x(const char *optarg)
{
	return (OPENSSL_strncasecmp(optarg, "0x", 2) == 0) ?
		&optarg[2] :
		optarg;
}

static int check_uv_id(const char *uv_id)
{
	size_t len;

	if (!OPENSSL_hexstr2buf_ex(NULL, 0, &len, uv_id, '\0')) {
		fprintf(stderr, "uv-secret-id: wrong format (hex)\n");
		return 1;
	}

	if (len != 32) {
		fprintf(stderr, "uv-secret-id: incorrect length (%lu != 32)\n", len);
		return 1;
	}

	return 0;
}

static char *get_raw_pubkey_hex(const char *file)
{
	unsigned char *rpub, *p = NULL;
	size_t publen = 0, hexlen = 0;
	EVP_PKEY *pkey = NULL;
	char *hex, *rc = NULL;
	BIO *bi = NULL;

	bi = BIO_new_file(file, "r");
	if (!bi) {
		fprintf(stderr, "Unable to read %s\n", file);
		ERR_print_errors_fp(stderr);
		goto out;
	}

	if (!PEM_read_bio_PUBKEY(bi, &pkey, NULL, NULL)) {
		fprintf(stderr, "PEM_read_bio_PUBKEY() %s\n", file);
		ERR_print_errors_fp(stderr);
		goto out;
	}

	if (EVP_PKEY_get_raw_public_key(pkey, NULL, &publen) == OSSL_RV_OK) {
		if (((p = OPENSSL_zalloc(publen)) == NULL)  ||
		    (EVP_PKEY_get_raw_public_key(pkey, p, &publen) != OSSL_RV_OK)) {
			fprintf(stderr, "unable to get raw public key: %s\n", file);
			ERR_print_errors_fp(stderr);
			goto out;
		}
		rpub = p;
	} else {
		if ((publen = EVP_PKEY_get1_encoded_public_key(pkey, &p)) == 0) {
			fprintf(stderr, "unable to get encoded public key: %s\n", file);
			ERR_print_errors_fp(stderr);
			goto out;
		}

		/* skip format byte */
		rpub = p + 1;
		publen--;
	}

	// hex-hex
	if ((OPENSSL_buf2hexstr_ex(NULL, 0, &hexlen, rpub, publen, '\0') != OSSL_RV_OK) ||
	    ((hex = OPENSSL_malloc(hexlen)) == NULL) ||
	    (OPENSSL_buf2hexstr_ex(hex, hexlen, &hexlen, rpub, publen, '\0') != OSSL_RV_OK)) {
		fprintf(stderr, "Unable to hex-encode public key: %s\n", file);
		goto out;
	}
	rc = (char *)hex;
out:
	OPENSSL_free(p);
	EVP_PKEY_free(pkey);
	BIO_free(bi);
	return rc;
}

static int compose(struct opts_compose *o)
{
	HBKZPC *hbk = NULL;
	char *uri = NULL, *pub_hex = NULL;
	const char *blob_hex = NULL;
	BIO *bo = NULL;
	int rc = 1;

	if (!o)
		return 1;

	if (o->pubkey && !(pub_hex = get_raw_pubkey_hex(o->pubkey))) {
		fprintf(stderr, "Unable to fetch pubkey\n");
		goto out;
	}

	if (strcmp(o->otype, "uv") == 0)
		blob_hex = o->uv.id_hex;

	// URI
	uri = uri_compose_new(o->otype, o->oalg,
			      blob_hex, pub_hex,
			      o->comment,
			      NULL, NULL);

	// DER
	hbk = HBKZPC_new();
	if (!hbk) {
		fprintf(stderr, "Unable to create ASN1 structure\n");
		goto out;
	}

	ASN1_STRING_set(hbk->desc, HBKZPC_DER_DESC, -1);
	ASN1_STRING_set(hbk->uri, uri, -1);

	/* output BIO */
	bo = (strcmp(o->out, "-") == 0)
		? BIO_new_fp(stdout, BIO_NOCLOSE)
		: BIO_new_file(o->out, "w");

	if (!bo) {
		fprintf(stderr, "Unable to open file: %s\n", o->out);
		goto out;
	}

	switch (o->outform) {
	case URI:
		if (BIO_printf(bo, "%s\n", uri) != (int)strlen(uri) + 1) {
			fprintf(stderr, "Unable to write URI to %s\n", o->out);
			goto out;
		}
		break;
	case DER:
		if (!i2d_HBKZPC_bio(bo, hbk)) {
			fprintf(stderr, "Unable to write DER file %s\n", o->out);
			goto out;
		}
		break;
	case PEM:
		if (!PEM_write_bio_HBKZPC(bo, hbk)) {
			fprintf(stderr, "Unable to write DER file %s\n", o->out);
			goto out;
		}
		break;
	default:
		break;
	}

	rc = 0;
out:
	OPENSSL_free(uri);
	OPENSSL_free(pub_hex);
	HBKZPC_free(hbk);
	BIO_free(bo);

	return rc;
}

int main_compose(int argc, char * const argv[])
{
	struct opts_compose opts = {
		.out = "-",
		.outform = PEM,
	};
	int c;

	while(1) {
		const struct origin_type_entry *ot;
		const struct origin_alg_entry *oa;
		const struct outform_entry *of;

		c = getopt_long(argc, argv, o_compose, options_compose, NULL);
		if (c < 0)
			break;

		switch (c) {
		case 't':
			for(ot = origin_type_map; ot->type; ot++) {
				if (strcasecmp(optarg, ot->type) == 0)
					opts.otype = ot->type;
			}
			if (!opts.otype)
				return usage_compose(comm, "Origin type not supported: ", optarg);
			break;
		case 'a':
			for(oa = origin_alg_list; oa->alg; oa++) {
				if ((strcasecmp(optarg, oa->alg) == 0) ||
				    (oa->oid &&
				     strcasecmp(optarg, oa->oid) == 0)) {
					opts.oalg = oa->alg;
					opts.asym = oa->asym;
				}
			}
			if (!opts.oalg)
				return usage_compose(comm, "Origin algorithm not supported: ", optarg);
			break;
		case 'p':
			opts.pubkey = optarg;
			break;
		case 'o':
			opts.out = optarg;
			break;
		case 'O':
			for(of = outform_map; of->str; of++) {
				if (strcasecmp(of->str, optarg) == 0)
					opts.outform = of->id;
			}
			break;
		case 'S':
			if (opts.uv.id_hex)
				return usage_compose(comm, "uv: Only uv-secret-name or uv-secret-id is supported", NULL);

			opts.uv.id_hex = skip_0x(optarg);
			if (check_uv_id(opts.uv.id_hex))
				return usage_compose(comm, NULL, NULL);
			break;
		case 'N':
			if (opts.uv.id_hex)
				return usage_compose(comm, "uv: Only uv-secret-name or uv-secret-id is supported", NULL);
			if (!SHA256((const unsigned char *)optarg, strlen(optarg), id_raw) ||
			    (OPENSSL_buf2hexstr_ex(id_hex, 65, NULL, id_raw, sizeof (id_raw), '\0') != OSSL_RV_OK))
				return 1;
			opts.uv.id_hex = id_hex;
			break;
		case 'c':
			opts.comment = optarg;
			break;
		case 'h':
		default:
			return usage_compose(comm, NULL, NULL);
		}
	}

	if (optind < argc)
		return usage_compose(comm, "Wrong arguments", NULL);

	if (!opts.otype || !opts.oalg)
		return usage_compose(comm, "Missing required arguments", NULL);

	if (!opts.asym && opts.pubkey)
		return usage_compose(comm, "Public-Key not supported for algorithm ", opts.oalg);

	if ((strcmp(opts.otype, "uv") == 0) && (!opts.uv.id_hex))
		return usage_compose(comm, "Missing origin arguments (uv)", NULL);

	return compose(&opts);
}

static int show(struct opts_show *o)
{
	HBKZPC *hbk = NULL;
	const char *desc;
	BIO *bi = NULL;
	int desclen;
	int rc = 1;

	if (!o)
		goto out;

	bi = (strcmp(o->in, "-") == 0) ?
		BIO_new_fp(stdin, BIO_NOCLOSE) :
		BIO_new_file(o->in, "r");

	if (!bi) {
		fprintf(stderr, "unable to open %s\n", o->in);
		goto out;
	}

	hbk = (o->in_der) ?
		d2i_HBKZPC_bio(bi, &hbk) :
		PEM_read_bio_HBKZPC(bi, &hbk, NULL, NULL);

	if (!hbk) {
		fprintf(stderr, "unable to read %s\n", o->in);
		goto out;
	}

	desc = (const char *)ASN1_STRING_get0_data(hbk->desc);
	desclen = ASN1_STRING_length(hbk->desc);
	if (!desc || !desclen ||
	    (strncmp(desc, HBKZPC_DER_DESC, desclen) != 0)) {
		fprintf(stderr, "%s: unsupported version %s\n",
			o->in, desclen ? desc : "");
		goto out;
	}

	fprintf(stdout, "%s\n",
		ASN1_STRING_get0_data(hbk->uri));
	rc = 0;
out:
	HBKZPC_free(hbk);
	BIO_free(bi);
	return rc;
}

int main_show(int argc, char * const argv[])
{
	struct opts_show opts = {
		.in_der = false,
	};
	int c;

	while(1) {
		c = getopt_long(argc, argv, o_show, options_show, NULL);
		if (c < 0)
			break;

		switch (c) {
		case 'i':
			opts.in = optarg;
			break;
		case 'I':
			opts.in_der = strcasecmp(optarg, "der") == 0;
			break;
		case 'h':
		default:
			return usage_show(comm, NULL, NULL);
		}
	}

	if (optind < argc)
		return usage_show(comm, "Wrong arguments", NULL);

	if (!opts.in)
		return usage_show(comm, "Missing required arguments", NULL);

	return show(&opts);
}

static int usage_base(const char *comm, const char *msg, const char *arg)
{
	if (msg)
		fprintf(stderr, "%s%s\n\n", msg, arg ?: "");
	fprintf(stderr, "Usage:\n");
	fprintf(stderr, "  %s [OPTIONS] <COMMAND> [<COMMAND-OPTIONS>]\n", comm);
	fprintf(stderr, "\nOptions:\n");
	fprintf(stderr, "  -V, --version                 Show version\n");
	fprintf(stderr, "  -h, --help                    Show short help\n");
	fprintf(stderr, "\nCommands:\n");
	fprintf(stderr, "  compose\n");
	fprintf(stderr, "  show\n");
	fprintf(stderr, "\nCommand Options:\n");
	fprintf(stderr, "  See command help\n");
	fprintf(stderr, "  %s <command> --help\n", comm);

	return 1;
}

static int version(void)
{
	fprintf(stdout, "%s version %s\n", comm, ZPCKEY_VERSION);
	return 0;
}

int main(int argc, char * const argv[])
{
	char *cmd;

	comm = basename(argv[0]);
	if (argc < 2) {
		usage_base(comm, "Missing command", NULL);
		return 1;
	}
	cmd = argv[1];

	if (strcmp(cmd, "--version") == 0 ||
	    strcmp(cmd, "-V") == 0)
		return version();
	else if (strcmp(cmd, "--help") == 0 ||
		 cmd[0] == '-')
		return usage_base(comm, NULL, NULL);
	else if (strcmp(cmd, "compose") == 0)
		return main_compose(argc - 1, &argv[1]);
	else if (strcmp(cmd, "show") == 0)
		return main_show(argc - 1, &argv[1]);
	else
		return usage_base(comm, "Command not supported: ", cmd);

	return 0;
}
