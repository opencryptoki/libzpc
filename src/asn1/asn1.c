// SPDX-License-Identifier: MIT
// Copyright contributors to the libzpc project
#include "asn1.h"

ASN1_SEQUENCE(HBKZPC) = {
	ASN1_EXP(HBKZPC, desc, ASN1_VISIBLESTRING, 0),
	ASN1_EXP(HBKZPC, uri,  ASN1_UTF8STRING,    1),
} ASN1_SEQUENCE_END(HBKZPC);

#include "asn1_gen.c"

int i2d_HBKZPC_bio(BIO *bp, const HBKZPC *hbkp)
{
	return ASN1_i2d_bio_of(HBKZPC, i2d_HBKZPC, bp, hbkp);
}

HBKZPC *d2i_HBKZPC_bio(BIO *bp, HBKZPC **hbkpp)
{
	return ASN1_d2i_bio_of(HBKZPC, HBKZPC_new, d2i_HBKZPC,
			       bp, hbkpp);
}
