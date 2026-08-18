% ZPCPKCS11.CONF(5) LIBZPC v2
%
% 2026

# NAME

zpcpkcs11.conf - Configuration file for the `zpcpkcs11` PKCS#11 library

# DESCRIPTION

This page documents the format of the configuration file read by the
`zpcpkcs11` PKCS#11 library on initialization. The configuration file maps
PKCS#11 key labels to OpenSSL URIs that reference the corresponding
protected-key origin files. Each entry becomes a PKCS#11 object accessible to
applications that load `zpcpkcs11.so` as their PKCS#11 provider.

# FILE LOCATION

The default configuration file path is:

    /etc/zpcpkcs11/zpcpkcs11.conf

The path can be overridden by setting the environment variable
**ZPCPKCS11_CONFIG** to an alternative file path. The environment variable is
read using *secure_getenv*(3), so it is ignored in set-user-ID and
set-group-ID programs.

# FILE FORMAT

The configuration file is a plain-text file. Each non-empty, non-comment line
specifies one key entry with the following syntax:

    <label>=<uri>

*label*
:   An arbitrary string that identifies the key. It is used as the PKCS#11
    *CKA_LABEL* attribute of the resulting key objects. The label must not
    contain `=`, space, or newline characters.

*uri*
:   An OpenSSL URI that references the key material. The URI is passed to the
    OpenSSL store loader (*OSSL_STORE_open_ex*(3ossl)). Supported URI schemes
    depend on the configured OpenSSL store loaders; the most common forms are:

    - A plain file path (e.g. `/path/to/mykey.pem`).
    - A `file:` URI (e.g. `file:///path/to/mykey.pem`).
    - An `hbkzpc:` URI as described in hbkzpcprovider(7).

    The referenced object may be a protected-key origin private key (or keypair), a clear private
    key PEM file, or a public-key-only PEM file. When a private key or keypair
    is loaded, both a private-key object and (if public material is present) a
    public-key object are created. When a public-key-only PEM file is loaded,
    only a public-key object is created. Keys with unsupported algorithms are
    skipped with a diagnostic message written to *stderr*.

**Comment lines** start with `#` in the first column and are ignored.

**Blank lines** (empty or containing only a newline) are ignored.

Any line that does not match the `<label>=<uri>` syntax is treated as a
syntax error. Processing stops at the first syntax error and
`C_Initialize`(3) returns `CKR_FUNCTION_FAILED`.

# SUPPORTED KEY TYPES

The library loads EC and Edwards-curve keys. Depending on the type of key
material referenced by the URI, it creates private-key objects, public-key
objects, or both (see *PKCS#11 OBJECTS* below). The following algorithms are
supported:

- **ECDSA**: prime256v1 (P-256), secp384r1 (P-384), secp521r1 (P-521)
- **EdDSA**: ED25519, ED448

Keys of any other type produce an error message on *stderr* and are skipped;
the remaining entries in the configuration file continue to be processed.

# PKCS#11 OBJECTS

For each successfully loaded key, the library creates one or two PKCS#11
objects in the single token provided by `zpcpkcs11`, depending on the type of
key material referenced by the URI:

- A **private key** object (`CKO_PRIVATE_KEY`): created when the URI
  references a private key or keypair (e.g. an `hbkzpc:` URI or a clear
  private-key PEM file).
- A **public key** object (`CKO_PUBLIC_KEY`): created when public-key material
  is available (i.e. always for public-key-only PEM files, and for private-key
  PEM files or `hbkzpc:` URIs that include the public portion).

Both objects share the same `CKA_LABEL` (the *label* from the config entry)
and the same `CKA_ID` (derived from the line number of the entry in the
configuration file).

The token is read-only: `C_CreateObject`, `C_CopyObject`, `C_DestroyObject`,
and `C_SetAttributeValue` all return `CKR_TOKEN_WRITE_PROTECTED`.

# EXAMPLES

A minimal configuration file with two keys:

    # Signing key for service A
    service-a-key = /etc/zpcpkcs11/keys/service-a.pem

    # Signing key for service B (using an hbkzpc URI)
    service-b-key = hbkzpc:origin-type=uv;origin-alg=1.2.840.10045.3.1.7;origin-blob=0102...

# ENVIRONMENT

**ZPCPKCS11_CONFIG**
:   If set, overrides the default configuration file path
    `/etc/zpcpkcs11/zpcpkcs11.conf`. Ignored in privileged processes (see
    *secure_getenv*(3)).

# FILES

`/etc/zpcpkcs11/zpcpkcs11.conf`
:   Default configuration file.

# SEE ALSO

hbkzpcprovider(7), hbkzpcprovider.conf(5), zpckey(1), *secure_getenv*(3),
*OSSL_STORE_open_ex*(3ossl).
