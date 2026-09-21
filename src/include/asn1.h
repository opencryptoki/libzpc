// SPDX-License-Identifier: MIT
// Copyright contributors to the libzpc project
#ifndef _ASN1_H
#define _ASN1_H

#include <openssl/asn1t.h>
#include <openssl/pem.h>

#define HBKZPC_PEM_STRING	"HARDWARE BACKED KEY ZPC"
#define HBKZPC_DER_DESC		"HBKZPC Provider URI v1.0"

struct hbkzpc_sequence_st {
	ASN1_VISIBLESTRING *desc;
	ASN1_UTF8STRING *uri;
};
typedef struct hbkzpc_sequence_st HBKZPC;
DECLARE_ASN1_FUNCTIONS(HBKZPC)

int i2d_HBKZPC_bio(BIO *bp, const HBKZPC *hbkp);
HBKZPC *d2i_HBKZPC_bio(BIO *bp, HBKZPC **hbkpp);

DECLARE_PEM_write_bio(HBKZPC, HBKZPC)
DECLARE_PEM_read_bio(HBKZPC, HBKZPC)
#endif /* _ASN1_H */
