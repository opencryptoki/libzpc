% ZPCPKCS11(7) LIBZPC v2
%
% 2026

# NAME

`zpcpkcs11` - A PKCS#11 library providing hardware-backed key cryptographic
operations on IBM Z and IBM LinuxONE.

# DESCRIPTION

The `zpcpkcs11` library (`zpcpkcs11.so`) is a PKCS#11 v3.2 provider that
exposes IBM Z protected-key cryptographic operations through the standard
PKCS#11 Cryptoki API. It is the PKCS#11 counterpart to the `hbkzpc provider`
for OpenSSL (hbkzpcprovider(7)), targeting applications that consume
cryptographic services via PKCS#11 rather than OpenSSL directly.

The library implements the full PKCS#11 v3.2 function list. Functions that are
not supported return `CKR_FUNCTION_NOT_SUPPORTED`. See section *Supported
Functions* for a complete listing.

## Hardware-backed keys

Hardware-backed keys (*HBK*) are a generic concept where the secret information
of cryptographic keys is never exposed to main memory, but cryptographic
operations with such keys are still possible. Instead of the raw secret key
information, opaque key objects are exposed to applications. The IBM Z platform
uses IBM Crypto Express (*CEX*) adapters or the IBM Secure Execution for Linux
ultravisor to securely store secret key material and securely export it to the
firmware.

See hbkzpcprovider(7) for a detailed description of the protected-key
concept and the HBKZPC URI format used to reference these keys.

## Token and slot model

The library presents exactly one slot (slot ID `0`) containing one token
(label `ZPC`). The token is permanently present, hardware-backed, and
**read-only**: object creation, modification, and deletion are not supported.

All keys exposed by the token are loaded at initialization time from the
configuration file. See zpcpkcs11.conf(5) for the configuration file format.

## Session model

The library supports an unlimited number of concurrent read-only sessions
(`CKF_SERIAL_SESSION`). Read-write sessions are accepted but behave
identically to read-only sessions because the token is write-protected.
Asynchronous sessions (`CKF_ASYNC_SESSION`) are not supported.

## Login model

The library accepts `C_Login` and `C_LoginUser` with user type `CKU_USER`.
Login as the security officer (`CKU_SO`) or any other user type returns
`CKR_USER_TYPE_INVALID`. The PIN value is ignored. The library does not
enforce login for any operation; the login state is maintained solely to
satisfy the PKCS#11 state machine expected by callers.

PIN protection is not meaningful in this context: the protected key origins
configured in zpcpkcs11.conf(5) are not access-restricted. Retrievable secrets
and other protected key origins can be transformed into protected keys by any
application via the PKEY ioctl interface, without any additional access control.

# SUPPORTED FUNCTIONS

## Implemented functions

The following functions are fully implemented:

`C_Initialize`, `C_Finalize`, `C_GetInfo`, `C_GetFunctionList`,
`C_GetInterfaceList`, `C_GetInterface`
:   Library lifecycle and introspection.

`C_GetSlotList`, `C_GetSlotInfo`, `C_GetTokenInfo`, `C_GetMechanismList`,
`C_GetMechanismInfo`
:   Slot, token, and mechanism introspection.

`C_OpenSession`, `C_CloseSession`, `C_CloseAllSessions`, `C_GetSessionInfo`,
`C_SessionCancel`
:   Session management.

`C_Login`, `C_LoginUser`, `C_Logout`
:   Login state management (PIN is not verified; only `CKU_USER` is supported).

`C_FindObjectsInit`, `C_FindObjects`, `C_FindObjectsFinal`
:   Object enumeration and search by template attributes.

`C_GetObjectSize`, `C_GetAttributeValue`
:   Object attribute retrieval.

`C_SignInit`, `C_Sign`, `C_SignUpdate`, `C_SignFinal`
:   One-shot and multi-part signing.

`C_VerifyInit`, `C_Verify`, `C_VerifyUpdate`, `C_VerifyFinal`
:   One-shot and multi-part signature verification.

`C_VerifySignatureInit`, `C_VerifySignature`, `C_VerifySignatureUpdate`,
`C_VerifySignatureFinal`
:   PKCS#11 v3.2 combined-signature verify operations.

`C_GetOperationState`, `C_SetOperationState`
:   Always return `CKR_STATE_UNSAVEABLE`.

`C_GetFunctionStatus`, `C_CancelFunction`
:   Always return `CKR_FUNCTION_NOT_PARALLEL`.

## Unsupported functions

All functions not listed above return `CKR_FUNCTION_NOT_SUPPORTED` or
`CKR_TOKEN_WRITE_PROTECTED` where applicable. This includes: encryption,
decryption, digesting, key generation, key wrapping/unwrapping, key
derivation, random number generation, and all message-based operation
variants.

# SUPPORTED MECHANISMS

The library registers the following PKCS#11 mechanisms, all supporting the
`CKF_SIGN` and `CKF_VERIFY` flags:

| Mechanism | Key sizes (bits) |
|---|---|
| `CKM_ECDSA` | 256 – 521 |
| `CKM_ECDSA_SHA1` | 256 – 521 |
| `CKM_ECDSA_SHA224` | 256 – 521 |
| `CKM_ECDSA_SHA256` | 256 – 521 |
| `CKM_ECDSA_SHA384` | 256 – 521 |
| `CKM_ECDSA_SHA512` | 256 – 521 |
| `CKM_ECDSA_SHA3_224` | 256 – 521 |
| `CKM_ECDSA_SHA3_256` | 256 – 521 |
| `CKM_ECDSA_SHA3_384` | 256 – 521 |
| `CKM_ECDSA_SHA3_512` | 256 – 521 |
| `CKM_EDDSA` | 255 – 448 |

All ECDSA mechanisms support `CKF_EC_OID`, `CKF_EC_F_P`,
`CKF_EC_UNCOMPRESS`, and `CKF_EC_COMPRESS`. `CKM_EDDSA` supports
`CKF_EC_OID`, `CKF_EC_F_P`, and `CKF_EC_COMPRESS`.

## Mechanism parameter restrictions

**`CKM_EDDSA`**
:   The `CK_EDDSA_PARAMS` structure is optional. If provided, the following
    restrictions apply; violating either returns `CKR_MECHANISM_PARAM_INVALID`:

    - `phFlag` must be `CK_FALSE`: pre-hash mode (HashEdDSA) is not supported.
    - `ulContextDataLen` must be `0`: non-empty context data is not supported.

## Supported ECC curves

- **ECDSA**: prime256v1 (P-256), secp384r1 (P-384), secp521r1 (P-521)
- **EdDSA**: ED25519, ED448

# INITIALIZATION

When `C_Initialize` is called, the library loads and processes the
configuration file (see zpcpkcs11.conf(5)), creating PKCS#11 key objects for
each valid entry. If initialization fails, `CKR_FUNCTION_FAILED` is returned.

`C_Initialize` requires `CKF_OS_LOCKING_OK` to be set in the flags of the
`CK_C_INITIALIZE_ARGS` structure when arguments are provided.
`CKF_LIBRARY_CANT_CREATE_OS_THREADS` is not supported and causes
`CKR_ARGUMENTS_BAD` to be returned.

# USAGE

To use `zpcpkcs11` with a PKCS#11-aware application, configure the
application to load `zpcpkcs11.so` as its PKCS#11 module. The exact
configuration method depends on the application.

## p11-kit

When using `p11-kit`, create a module configuration file:

    [p11-kit-module]
    module: /path/to/zpcpkcs11.so

## p11tool

Keys available in the token can be enumerated using `p11tool`:

    $ p11tool --provider /path/to/zpcpkcs11.so --list-all
    Object 0:
        URL: pkcs11:model=ZPC;manufacturer=IBM;serial=01;token=ZPC;...
        Type: Private Key (EC/ECDSA)
        Label: my-signing-key
        ...

# CONFIGURATION

The library reads its key configuration from:

    /etc/zpcpkcs11/zpcpkcs11.conf

The path can be overridden with the `ZPCPKCS11_CONFIG` environment variable.
See zpcpkcs11.conf(5) for the full configuration file format.

# ENVIRONMENT

**ZPCPKCS11_CONFIG**
:   Overrides the default configuration file path. Ignored in privileged
    processes (see *secure_getenv*(3)).

# FILES

`/etc/zpcpkcs11/zpcpkcs11.conf`
:   Default key configuration file.

`zpcpkcs11.so`
:   The PKCS#11 shared library.

# GLOSSARY

CEX
:   IBM Crypto Express

CPACF
:   CP Assist for Cryptographic Functions

HBK
:   hardware-backed key

SEL
:   IBM Secure Execution for Linux

ZPC
:   IBM Z protected key cryptography

# SEE ALSO

zpcpkcs11.conf(5), hbkzpcprovider(7), hbkzpcprovider.conf(5), zpckey(1).
