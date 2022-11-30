/*
 * Copyright IBM Corp. 2021
 *
 * libzpc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef ZPC_ERROR_H
# define ZPC_ERROR_H
# ifdef __cplusplus
/* *INDENT-OFF* */
extern "C" {
/* *INDENT-ON* */
# endif

/**
 * \file zpc/error.h
 * \brief Error API.
 */

/**
 * \def ZPC_ERROR_ARG1NULL
 * \brief Function argument 1 is NULL.
 */
# define ZPC_ERROR_ARG1NULL           1

/**
 * \def ZPC_ERROR_ARG2NULL
 * \brief Function argument 2 is NULL.
 */
# define ZPC_ERROR_ARG2NULL           2

/**
 * \def ZPC_ERROR_ARG3NULL
 * \brief Function argument 3 is NULL.
 */
# define ZPC_ERROR_ARG3NULL           3

/**
 * \def ZPC_ERROR_ARG4NULL
 * \brief Function argument 4 is NULL.
 */
# define ZPC_ERROR_ARG4NULL           4

/**
 * \def ZPC_ERROR_ARG5NULL
 * \brief Function argument 5 is NULL.
 */
# define ZPC_ERROR_ARG5NULL           5

/**
 * \def ZPC_ERROR_ARG6NULL
 * \brief Function argument 6 is NULL.
 */
# define ZPC_ERROR_ARG6NULL           6

/**
 * \def ZPC_ERROR_ARG7NULL
 * \brief Function argument 7 is NULL.
 */
# define ZPC_ERROR_ARG7NULL           7

/**
 * \def ZPC_ERROR_ARG8NULL
 * \brief Function argument 8 is NULL.
 */
# define ZPC_ERROR_ARG8NULL           8

/**
 * \def ZPC_ERROR_ARG1RANGE
 * \brief Function argument 1 is out of range.
 */
# define ZPC_ERROR_ARG1RANGE          9

/**
 * \def ZPC_ERROR_ARG2RANGE
 * \brief Function argument 2 is out of range.
 */
# define ZPC_ERROR_ARG2RANGE         10

/**
 * \def ZPC_ERROR_ARG3RANGE
 * \brief Function argument 3 is out of range.
 */
# define ZPC_ERROR_ARG3RANGE         11

/**
 * \def ZPC_ERROR_ARG4RANGE
 * \brief Function argument 4 is out of range.
 */
# define ZPC_ERROR_ARG4RANGE         12

/**
 * \def ZPC_ERROR_ARG5RANGE
 * \brief Function argument 5 is out of range.
 */
# define ZPC_ERROR_ARG5RANGE         13

/**
 * \def ZPC_ERROR_ARG6RANGE
 * \brief Function argument 6 is out of range.
 */
# define ZPC_ERROR_ARG6RANGE         14

/**
 * \def ZPC_ERROR_ARG7RANGE
 * \brief Function argument 7 is out of range.
 */
# define ZPC_ERROR_ARG7RANGE         15

/**
 * \def ZPC_ERROR_ARG8RANGE
 * \brief Function argument 8 is out of range.
 */
# define ZPC_ERROR_ARG8RANGE         16

/**
 * \def ZPC_ERROR_MALLOC
 * \brief Malloc failed.
 */
# define ZPC_ERROR_MALLOC            17

/**
 * \def ZPC_ERROR_KEYNOTSET
 * \brief Key not set.
 */
# define ZPC_ERROR_KEYNOTSET         18

/**
 * \def ZPC_ERROR_KEYSIZE
 * \brief Invalid key size.
 */
# define ZPC_ERROR_KEYSIZE           19

/**
 * \def ZPC_ERROR_IVNOTSET
 * \brief IV not set.
 */
# define ZPC_ERROR_IVNOTSET          20

/**
 * \def ZPC_ERROR_IVSIZE
 * \brief Invalid IV size.
 */
# define ZPC_ERROR_IVSIZE            21

/**
 * \def ZPC_ERROR_TAGSIZE
 * \brief Invalid tag size.
 */
# define ZPC_ERROR_TAGSIZE           22

/**
 * \def ZPC_ERROR_TAGMISMATCH
 * \brief Tag mismatch.
 */
# define ZPC_ERROR_TAGMISMATCH       23

/**
 * \def ZPC_ERROR_HWCAPS
 * \brief Function not supported.
 */
# define ZPC_ERROR_HWCAPS          24

/**
 * \def ZPC_ERROR_SMALLOUTBUF
 * \brief Output buffer too small.
 */
# define ZPC_ERROR_SMALLOUTBUF       25

/**
 * \def ZPC_ERROR_APQNSNOTSET
 * \brief APQNs not set.
 */
# define ZPC_ERROR_APQNSNOTSET       26

/**
 * \def ZPC_ERROR_KEYTYPE
 * \brief Invalid key type.
 */
# define ZPC_ERROR_KEYTYPE           27

/**
 * \def ZPC_ERROR_KEYTYPENOTSET
 * \brief Key type not set.
 */
# define ZPC_ERROR_KEYTYPENOTSET     28

/**
 * \def ZPC_ERROR_IOCTLGENSECK2
 * \brief PKEY_GENSECK2 ioctl failed.
 */
# define ZPC_ERROR_IOCTLGENSECK2     29

/**
 * \def ZPC_ERROR_IOCTLCLR2SECK2
 * \brief PKEY_CLR2SECK2 ioctl failed.
 */
# define ZPC_ERROR_IOCTLCLR2SECK2    30

/**
 * \def ZPC_ERROR_IOCTLBLOB2PROTK2
 * \brief PKEY_BLOB2PROTK2 ioctl failed.
 */
# define ZPC_ERROR_IOCTLBLOB2PROTK2  31

/**
 * \def ZPC_ERROR_WKVPMISMATCH
 * \brief Wrapping key verification pattern mismatch.
 */
# define ZPC_ERROR_WKVPMISMATCH      32

/**
 * \def ZPC_ERROR_DEVPKEY
 * \brief Opening /dev/pkey failed.
 */
# define ZPC_ERROR_DEVPKEY           33

/**
 * \def ZPC_ERROR_CLEN
 * \brief Ciphertext too long.
 */
# define ZPC_ERROR_CLEN              34

/**
 * \def ZPC_ERROR_MLEN
 * \brief Message too long.
 */
# define ZPC_ERROR_MLEN              35

/**
 * \def ZPC_ERROR_AADLEN
 * \brief Additional authenticated data too long.
 */
# define ZPC_ERROR_AADLEN            36

/**
 * \def ZPC_ERROR_PARSE
 * \brief Parse error.
 */
# define ZPC_ERROR_PARSE             38

/**
 * \def ZPC_ERROR_APQNNOTFOUND
 * \brief APQN not found in APQN list.
 */
# define ZPC_ERROR_APQNNOTFOUND      39

/**
 * \def ZPC_ERROR_MKVPLEN
 * \brief MKVP too long.
 */
# define ZPC_ERROR_MKVPLEN           40

/**
 * \def ZPC_ERROR_INITLOCK
 * \brief Initializing a lock failed.
 */
# define ZPC_ERROR_INITLOCK          42

/**
 * \def ZPC_ERROR_OBJINUSE
 * \brief Object is in use.
 */
# define ZPC_ERROR_OBJINUSE          43

/**
 * \def ZPC_ERROR_IOCTLAPQNS4KT
 * \brief PKEY_APQNS4KT ioctl failed.
 */
# define ZPC_ERROR_IOCTLAPQNS4KT     44

/**
 * \def ZPC_ERROR_KEYSIZENOTSET
 * \brief Key-size not set.
 */
# define ZPC_ERROR_KEYSIZENOTSET     45

/**
 * \def ZPC_ERROR_IOCTLGENPROTK
 * \brief PKEY_GENPROTK ioctl failed.
 */
# define ZPC_ERROR_IOCTLGENPROTK     46

/**
 * \def ZPC_ERROR_PROTKEYONLY
 * \brief Protected-key only.
 */
# define ZPC_ERROR_PROTKEYONLY       47

/**
 * \def ZPC_ERROR_KEYSEQUAL
 * \brief Keys are equal.
 */
# define ZPC_ERROR_KEYSEQUAL         48

/**
 * \def ZPC_ERROR_NOTSUP
 * \brief Not supported.
 */
# define ZPC_ERROR_NOTSUP            49

/**
 * \def ZPC_ERROR_EC_INVALID_CURVE
 * \brief Invalid EC curve.
 */
# define ZPC_ERROR_EC_INVALID_CURVE  50

/**
 * \def ZPC_ERROR_EC_CURVE_NOTSET
 * \brief EC curve not set.
 */
# define ZPC_ERROR_EC_CURVE_NOTSET  51

/**
 * \def ZPC_ERROR_EC_PRIVKEY_NOTSET
 * \brief EC private key not set.
 */
# define ZPC_ERROR_EC_PRIVKEY_NOTSET  52

/**
 * \def ZPC_ERROR_EC_PUBKEY_NOTSET
 * \brief EC public key not set.
 */
# define ZPC_ERROR_EC_PUBKEY_NOTSET  53

/**
 * \def ZPC_ERROR_EC_NO_KEY_PARTS
 * \brief No EC key parts given.
 */
# define ZPC_ERROR_EC_NO_KEY_PARTS  54

/**
 * \def ZPC_ERROR_EC_SIGNATURE_INVALID
 * \brief signature invalid.
 */
# define ZPC_ERROR_EC_SIGNATURE_INVALID  55

/**
 * \def ZPC_ERROR_IOCTLBLOB2PROTK3
 * \brief PKEY_BLOB2PROTK3 ioctl failed.
 */
# define ZPC_ERROR_IOCTLBLOB2PROTK3    56

/**
 * \def ZPC_ERROR_IOCTLCLR2SECK3
 * \brief PKEY_CLR2SECK3 ioctl failed.
 */
# define ZPC_ERROR_IOCTLCLR2SECK3    57

/**
 * \def ZPC_ERROR_APQNS_NOTSET
 * \brief No APQNs set for this key, but required for this operation.
 */
# define ZPC_ERROR_APQNS_NOTSET      58

/**
 * \def ZPC_ERROR_EC_SIGNATURE_LENGTH
 * \brief length of given signature is invalid for this EC key.
 */
# define ZPC_ERROR_EC_SIGNATURE_LENGTH  59

/**
 * \def ZPC_ERROR_EC_KEY_PARTS_INCONSISTENT
 * \brief given public/private key parts are inconsistent. They do not belong
 * to the same EC key.
 */
# define ZPC_ERROR_EC_KEY_PARTS_INCONSISTENT  60

/**
 * \def ZPC_ERROR_CCA_HOST_LIB_NOT_AVAILABLE
 * \brief the CCA host library is not available, but required for this function.
 */
# define ZPC_ERROR_CCA_HOST_LIB_NOT_AVAILABLE  61

/**
 * \def ZPC_ERROR_EP11_HOST_LIB_NOT_AVAILABLE
 * \brief the EP11 host library is not available, but required for this function.
 */
# define ZPC_ERROR_EP11_HOST_LIB_NOT_AVAILABLE  62

/**
 * \def ZPC_ERROR_EC_PUBKEY_LENGTH
 * \brief the given EC public key length is invalid.
 */
# define ZPC_ERROR_EC_PUBKEY_LENGTH  63

/**
 * \def ZPC_ERROR_EC_PRIVKEY_LENGTH
 * \brief the given EC private key length is invalid.
 */
# define ZPC_ERROR_EC_PRIVKEY_LENGTH  64

/**
 * \def ZPC_ERROR_EC_NO_CCA_SECUREKEY_TOKEN
 * \brief the given buffer does not contain a valid CCA secure key token.
 */
# define ZPC_ERROR_EC_NO_CCA_SECUREKEY_TOKEN  65

/**
 * \def ZPC_ERROR_EC_NO_EP11_SECUREKEY_TOKEN
 * \brief the given buffer does not contain a valid EP11 secure key token.
 */
# define ZPC_ERROR_EC_NO_EP11_SECUREKEY_TOKEN  66

/**
 * \def ZPC_ERROR_EC_EP11_SPKI_INVALID_LENGTH
 * \brief the imported buffer contains an EP11 SPKI with an invalid length.
 */
# define ZPC_ERROR_EC_EP11_SPKI_INVALID_LENGTH  67

/**
 * \def ZPC_ERROR_EC_EP11_SPKI_INVALID_FOR_CURVE
 * \brief the imported buffer contains an EP11 SPKI with an invalid EC curve.
 */
# define ZPC_ERROR_EC_EP11_SPKI_INVALID_CURVE  68

/**
 * \def ZPC_ERROR_EC_EP11_SPKI_INVALID_FOR_PUBKEY
 * \brief the imported buffer contains an EP11 SPKI with an invalid public key.
 */
# define ZPC_ERROR_EC_EP11_SPKI_INVALID_PUBKEY  69

/**
 * \def ZPC_ERROR_EC_EP11_SPKI_INVALID_MKVP
 * \brief the imported buffer contains an EP11 MACed SPKI with an invalid MKVP.
 */
# define ZPC_ERROR_EC_EP11_SPKI_INVALID_MKVP  70

/**
 * \def ZPC_ERROR_BLOB_NOT_PKEY_EXTRACTABLE
 * \brief the imported buffer contains a key blob that cannot be transformed into a protected key.
 */
# define ZPC_ERROR_BLOB_NOT_PKEY_EXTRACTABLE  71

/**
 * \fn const char *zpc_error_string(int err)
 * \brief Map an error code to the corresponding error string.
 * \param[in] err An error code.
 * \return A pointer to an error string.
 */
__attribute__((visibility("default")))
const char *zpc_error_string(int);

# ifdef __cplusplus
/* *INDENT-OFF* */
}
/* *INDENT-ON* */
# endif
#endif
