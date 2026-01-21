// SPDX-License-Identifier: MIT
// Copyright contributors to the libzpc project
#include <string.h>
#include <openssl/crypto.h>

#include "uri.h"

#define SEP_PROTOCOL		":"
#define SEP_PATHQUERY		"?"
#define SEP_KEYVALUE		"="
#define SEP_PATHATTRS		";"
#define SEP_QUERYATTRS		"&"

#define URI_PROTOCOL		URI_PROTOCOL_PREFIX SEP_PROTOCOL

#define URI_P_ORIGIN_TYPE	"origin-type" SEP_KEYVALUE
#define URI_P_ORIGIN_ALG	"origin-alg" SEP_KEYVALUE
#define URI_P_ORIGIN_BLOB	"origin-blob" SEP_KEYVALUE
#define URI_P_ORIGIN_PUBKEY	"origin-pubkey" SEP_KEYVALUE
#define URI_P_COMMENT		"comment" SEP_KEYVALUE

#define URI_Q_MKVP		"mkvp" SEP_KEYVALUE
#define URI_Q_APQNS		"apqns" SEP_KEYVALUE

static void decode_pct(char *s)
{
	char *rp, *wp, *endptr;
	unsigned long tmp;
	char hex[3] = {0};

	if (!s)
		return;

	if (!strchr(s, '%'))
		return;

	rp = wp = s;
	while(*rp) {
		switch(*rp) {
		case '%':
			if (strlen(rp) < 3)
				goto out;		/* invalid format */

			rp++;				/* skip % */
			memcpy(hex, rp, 2);		/* 2 chars only */

			tmp = strtoul(hex, &endptr, 16);/* convert */
			if (*endptr != '\0')
				goto out;		/* non-hex chars */
			*wp = (char)(tmp & 0xff);

			rp++;
			break;
		default:
			*wp = *rp;
		}

		rp++;
		wp++;
	}
out:
	*wp = '\0';
}

static int parse_attr(char *str, struct attr *attr)
{
	char *key, **p;
	int rc = 1;

	if (!str || !attr)
		goto out;

	/* skip already parsed attribute */
	if (attr->value)
		goto out;

	p = &str;
	key = strsep(p, SEP_KEYVALUE);
	if (!p)
		goto out;

	decode_pct(*p);
	attr->key = key;
	attr->value = *p;

	rc = 0;
out:
	return rc;
}

static inline int match_elem_attrkey(const char *elem, const char *attrkey)
{
	return (strncmp(elem, attrkey, strlen(attrkey)) == 0);
}

static int parse_query(char *qattr, struct parsed_uri *puri)
{
	char **next;

	/* query attributes are optional */
	if (!qattr || !strlen(qattr))
		return 0;

	next = &qattr;
	do {
		char *e = strsep(next, SEP_QUERYATTRS);
		int rc = 0;

		if (match_elem_attrkey(e, URI_Q_MKVP))
			rc = parse_attr(e, &puri->mkvp);
		else if (match_elem_attrkey(e, URI_Q_APQNS))
			rc = parse_attr(e, &puri->apqns);
		else
			rc = 1; /* unknown attribute */
		if (rc)
			return rc;
	} while (*next);

	return 0;
}

static int parse_path(char *pattr, struct parsed_uri *puri)
{
	char **next;

	/* path attributes are mandatory */
	if (!pattr || !strlen(pattr))
		return 1;

	next = &pattr;
	do {
		char *e = strsep(next, SEP_PATHATTRS);
		int rc = 0;

		if (match_elem_attrkey(e, URI_P_ORIGIN_TYPE))
			rc = parse_attr(e, &puri->origin_type);
		else if (match_elem_attrkey(e, URI_P_ORIGIN_ALG))
			rc = parse_attr(e, &puri->origin_alg);
		else if (match_elem_attrkey(e, URI_P_ORIGIN_BLOB))
			rc = parse_attr(e, &puri->origin_blob);
		else if (match_elem_attrkey(e, URI_P_ORIGIN_PUBKEY))
			rc = parse_attr(e, &puri->origin_pubkey);
		else if (match_elem_attrkey(e, URI_P_COMMENT))
			rc = parse_attr(e, &puri->comment);
		else
			rc = 1; /* unknown attribute */
		if (rc)
			return rc;
	} while (*next);

	return 0;
}

static int parse(char *uri, struct parsed_uri *puri)
{
	char *pattr, *qattr;
	char **next;
	int rc;

	if (!uri || !puri)
		return 1;

	if (strncmp(uri, URI_PROTOCOL, strlen(URI_PROTOCOL)) != 0)
		return 1;

	next = &uri;

	/* drop protocol */
	strsep(next, SEP_PROTOCOL);

	pattr = strsep(next, SEP_PATHQUERY);
	qattr = *next;

	rc = parse_path(pattr, puri);
	if (rc) {
		return rc;
	}

	rc = parse_query(qattr, puri);
	if (rc) {
		return rc;
	}

	return 0;
}

void parsed_uri_free(struct parsed_uri *puri)
{
	if (!puri)
		return;

	if (puri->priv)
		OPENSSL_clear_free(puri->priv,
				   puri->privlen);

	OPENSSL_free(puri);
}

struct parsed_uri *parsed_uri_new(const char *uri)
{
	struct parsed_uri *puri;

	puri = OPENSSL_zalloc(sizeof(struct parsed_uri));
	if (!puri)
		return NULL;

	puri->priv = OPENSSL_strdup(uri);
	if (!puri->priv)
		goto err;
	puri->privlen = strlen(uri);

	if(parse(puri->priv, puri))
		goto err;

	return puri;

err:
	parsed_uri_free(puri);
	return NULL;
}
