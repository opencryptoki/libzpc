// SPDX-License-Identifier: MIT
// Copyright contributors to the libzpc project
#ifndef _URI_H
#define _URI_H

#include <stdlib.h>

#define URI_PROTOCOL_PREFIX	"hbkzpc"

struct attr {
	const char *key;
	const char *value;
	//unsigned char *data;
	//size_t datalen;
};

struct parsed_uri {
	char *priv;
	size_t privlen;

	/* path attributes */
	struct attr origin_type;
	struct attr origin_alg;
	struct attr origin_blob;
	struct attr origin_pubkey;
	struct attr comment;

	/* query attributes */
	struct attr mkvp;
	struct attr apqns;
};

struct parsed_uri *parsed_uri_new(const char *uri);
void parsed_uri_free(struct parsed_uri *puri);

#endif /*  _URI_H */
