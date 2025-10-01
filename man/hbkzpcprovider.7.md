% HBKZPCPROVIDER(7) LIBZPC v2
%
% 2026

# NAME

`hbkzpc provider` - An OpenSSL provider that provides an interface to the
hardware-backed key cryptographic operations, available on IBM Z and IBM
LinuxONE.

# DESCRIPTION

IBM Z and IBM LinuxONE systems offer several types of hardware assists with
different features, including the CP Assist for Cryptographic Functions
(*CPACF*) and the IBM Crypto Express (*CEX*) features.

The `hbkzpc provider` enables applications using the OpenSSL crypto library API
to exploit the protected key cryptography (*ZPC*) functions, provided by CPACF
on IBM Z and IBM LinuxONE.

To use the `hbkzpc provider` via the OpenSSL crypto library API, it must be
referenced in the OpenSSL configuration. For more details, see
hbkzpcprovider.conf(5).

## Hardware-backed keys

Hardware-backed keys (*HBK*) are a generic concept, where the secret information
of cryptographic keys is never exposed to the main memory, but cryptographic
operations with such keys are still possible. Instead of the raw secret key
information, opaque key objects are exposed to the applications. The internals
of these opaque key objects (key slot reference, wrapped key blob, etc.) depends
on the concrete implementation of the generic concept. It is essential, that the
knowledge of the opaque key object does not expose any information about the
real secret information of the key.

## IBM Z protected key cryptography

The IBM Z protected key cryptography is the implementation of the generic
hardware-backed key concept on IBM Z and IBM LinuxONE. The platform uses IBM
Crypto Express (*CEX*) adapters (or often called: feature) or the IBM Secure
Execution for Linux ultravisor to securely store secret key material and
securely export them to the firmware. The `hbkzpc provider` can handle opaque
key objects (protected key origins), which describe and reference these secure
keys.

ZPC provides many cryptographic functions with protected keys. The `hbkzpc
provider` supports ECDSA/EdDSA sign/verify operations for a list of
ECC-curves. See section *Provider functions* for more details.

## Protected key origins

A protected key origin for the `hbkzpc provider` is used to internally export
the referenced secure key to the firmware. While the resulting protected keys
are volatile and can become invalid at any time, the protected key origins are
persistent and can be stored without exposing any secret information.

A protected key origin is specified by a HBKZPC unified resource identifier
(URI). These URIs can be encoded to protected key origin files. The `hbkzpc
provider` can handle either URIs directly or URIs which are encoded and stored
in files (DER or PEM). See section *URI* for more details.

The `zpckey` tool supports composing such protected key origins. See zpckey(1)
for more details.

The `hbkzpc provider` supports protected key origins for retrievable secrets in
IBM Secure Execution for Linux (SEL) ultravisor.

## Provider functions

The `hbkzpc provider` plugs into the OpenSSL provider API and provides the
following functions:

- signature-algorithms for ECDSA and EdDSA
- key-manager for provider-specific keys
- store-loader for provider-specific key URIs
- decoder for DER/PEM encoded provider-specific key URI files

## Supported ECC curves

The `hbkzpc provider` supports the following ECC-curves for ECDSA and EdDSA
respectively:

- prime256v1
- secp384r1
- secp521r1
- ED25519
- ED448

# URI

The HBKZPC unified resource identifier (URI) specifies all information of the
protected key origins, which is required for the provider to derive the related
protected key. The URI has the following syntax (ABNF representation):

    hbkzpc-URI    = "hbkzpc:" hbkzpc-param
    hbkzpc-param  = [ hbkzpc-pattr *(";" hbkzpc-pattr) ]

    hbkzpc-pattr  = origin-type / origin-alg / origin-blob /
                    origin-pubkey / comment

    origin-type   = "origin-type"   "=" *pchar
    origin-alg    = "origin-alg"    "=" oid / *(pchar)
    origin-blob   = "origin-blob"   "=" hex-string
    origin-pubkey = "origin-pubkey" "=" hex-string
    comment       = "comment"       "=" *pchar-pct

    oid           = DIGIT *("." DIGIT)

    hex-byte      = 2*HEXDIG
    hex-string    = [ hex-byte *(hex-byte) ]

    pchar-pct     = pchar / pct-encoded
    pchar         = unreserved / res-avail
    res-avail     = ":" / "[" / "]" / "@" / "!" / "$" /
                    "'" / "(" / ")" / "*" / "+" / "," / "="

    pct-encoded   = [ "%" 2*HEXDIG ]
    unreserved    = ALPHA / DIGIT / "-" / "." / "_" / "~"


# ENCODING

The URI can also be encoded and stored to a file. Supported encoding formats are
DER and PEM.

## DER encoding

For the DER encoding, the HBKZPC URI is encapsulated with a ASN.1
structure. Each DER file contains one structure in binary form. The structure
has the following syntax:

    HardwareBackedKeyZPCFormat DEFINITIONS ::= BEGIN
            HBKZPC ::= SEQUENCE {
                    desc   [0] EXPLICIT VisibleString,
                    uri    [1] EXPLICIT UTF8String,
            }
    END

The DER decoder of the `hbkzpc provider` only handles DER files with a
description (*desc*) of *HBKZPC Provider URI v1.0*.

## PEM encoding

The PEM encoding is a base64-encoded DER structure. The encoded data is
surrounded by a start and end tag. A PEM encoded file has the following form:

    -----BEGIN HARDWARE BACKED KEY ZPC-----
    [... <BASE64-encoded data> ...]
    -----END HARDWARE BACKED KEY ZPC-----

The PEM decoder of the `hbkzpc provider` only handles PEM files with the label
*HARDWARE BACKED KEY ZPC*.

# GLOSSARY

CEX
:   IBM Crypto Express

CPACF
:   CP Assist for Cryptographic Functions

HBK
:   hardware-backed key

SEL
:   IBM Secure Execution for Linux

URI
:   unified resource identifier

ZPC
:   IBM Z protected key cryptography

# SEE ALSO

zpckey(1), hbkzpcprovider.conf(5), provider(7SSL).
