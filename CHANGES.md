Changelog {#changes}
===

**Version 1.5.0**

- Support for live guest relocation

**Version 1.4.1**

- Bug fixes

**Version 1.4.0**

- Support for MSA 10 (XTS-FULL) and MSA 11 (HMAC)
- bug fixes.

**Version 1.3.1**

- bug fixes

**Version 1.3.0**

- Support for Ultravisor retrievable secrets
- Handle CCA cipher key token with Encrypted V0 payload
- bug fixes

**Version 1.2.0**

- Support for get/set intermediate iv for CBC and XTS
- Support for internal iv for GCM
- Fix AES EP11 version 6 key support for generate and import_clear
- Exploit KBLOB2PROTK3 ioctl for clear AES and EC keys

**Version 1.1.1**

- Exploit PKEY_KBLOB2PROTK2 for AES EP11 version 6 keys

**Version 1.1.0**

- Implements an ECC-KEY API : `zpc/ecc_key.h`.
- Implements an ECDSA-CTX API : `zpc/ecdsa_ctx.h`.

**Version 1.0.1**

- Updated spec file for rpm build

**Version 1.0**

- Implements an error API : `zpc/error.h`.
- Implements an AES-KEY API : `zpc/aes_key.h`.
- Implements an AES-GCM API : `zpc/aes_gcm.h`.
- Implements an AES-CCM API : `zpc/aes_ccm.h`.
- Implements an AES-XTS API : `zpc/aes_xts.h`.
- Implements an AES-CBC API : `zpc/aes_cbc.h`.
- Implements an AES-ECB API : `zpc/aes_ecb.h`.
- Implements an AES-CMAC API : `zpc/aes_cmac.h`.
