% ZPCKEY(1) LIBZPC v2
%
% 2026

# NAME

zpckey - A key management tooling for protected key origins, used by the OpenSSL
provider for protected keys (`hbkzpc provider`).

# SYNOPSIS

zpckey [-h|--help] [-V|--version]

zpckey compose \<REQ-ARGS\> [\<OPT-ARGS\>] \<ORIGIN-ARGS\>

zpckey show \<REQ-ARGS\> [\<OPT-ARGS\>]

# DESCRIPTION

The zpckey command provides key management functions for protected key origins,
used by the `hbkzpc provider` (hbkzpcprovider(7)). IBM Z and IBM LinuxONE offer
different types of cryptographic hardware with different features, including the
CP Assist for Cryptographic Functions (CPACF) and the IBM Crypto Express (CEX)
features.

The CPACF provides functions to perform cryptographic operations with a kind of
hardware-backed keys, the so called protected keys.

The CEX cards provide secure key generation and storage (secure keys), as well
as cryptographic operations with these keys.

# OPTIONS

-V, \--version
: Show version

-h, \--help
: Show short help

# ZPCKEY COMPOSE

The *compose* command supports the composition of protected key origins, which
can be used for the `hbkzpc provider`.

## Required Arguments:

-t, \--origin-type \<otype\>
:    Protected key origin type

-a, \--origin-alg \<oalg\>
:    Protected key origin algorithm

## Protected key origin types (\<otype\>):

- uv: Ultravisor retrievable secrets

## Protected key origin algorithms (\<oalg\>):

- prime256v1 (alt.: 1.2.840.10045.3.1.7)
- secp384r1 (alt.: 1.3.132.0.34)
- secp521r1 (alt.: 1.3.132.0.35)
- ED25519 (alt.: 1.3.101.112)
- ED448 (alt.: 1.3.101.113)
- AES-128
- AES-192
- AES-256
- AES-128-XTS
- AES-256-XTS

## Optional Arguments:

-p, \--pubkey \<file\>
:    Public key file

-o, \--out \<file\>
:    Output file

\--outform \<format\>
:    Output file format URI, DER or PEM (default: PEM)

-c, \--comment \<string\>
:    Comment (metadata)

-h, \--help
:    Show short help

## Origin Arguments:

For \<otype\> = *uv*, one out of the following must be specified:
:    \--uv-secret-id \<hexstring\>
     :    UV secret ID

:    \--uv-secret-name \<string\>
     :    UV secret name

# ZPCKEY SHOW

The *show* command prints information about the key file to stdout.

## Required Arguments:

-i, \--in \<file\>
:    Input file

## Optional Arguments:

\--inform \<format\>
:    Input file format PEM or DER (default: PEM)

-h, \--help
:    Show short help

# SEE ALSO

hbkzpcprovider.conf(5), hbkzpcprovider(7)
