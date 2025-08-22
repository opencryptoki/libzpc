Introduction {#index}
===

The IBM Z Protected-key Crypto library `libzpc` is an open-source library targeting the 64-bit Linux on IBM Z (s390x) platform. It provides interfaces for cryptographic primitives. The underlying implementations make use of z/Architecture's extensive performance-boosting hardware support and its *protected-key* feature which ensures that key material is never present in main memory at any time.

The `libzpc` source is hosted on [GitHub](https://github.com/opencryptoki/libzpc).


Supported crypto
---

Encryption (Cipher):

    AES-128-ECB, AES-192-ECB, AES-256-ECB
    AES-128-CBC, AES-192-CBC, AES-256-CBC
    AES-128-XTS, AES-256-XTS

Message authentication (MAC):

    AES-128-CMAC, AES-192-CMAC, AES-256-CMAC

Hash-based message authentication (HMAC)

    HMAC-SHA-224, HMAC-SHA-256, HMAC-SHA-384, HMAC-SHA-512

Authenticated Encryption (AEAD):

    AES-128-CCM, AES-192-CCM, AES-256-CCM
    AES-128-GCM, AES-192-GCM, AES-256-GCM

Elliptic-curve digital signature create/verify (ECDSA):

    prime256, oid = 1.2.840.10045.3.1.7
    secp384, oid = 1.3.132.0.34
    secp521, oid = 1.3.132.0.35
    ed25519, oid = 1.3.101.112
    ed448, oid = 1.3.101.113

Building
---

Basic prerequisites for building the library only:
- Linux kernel >= 5.7
- C99 compiler (clang, gcc)
- libpthread
- cmake >= 3.10
- make

Additional prerequisites for building the test program:
- C++11 compiler (clang, g++)
- libjson-c devel package >= 0.13
- internet connection

Additional prerequisites for building the html and latex doc:
- doxygen >= 1.8.17
- latex, bibtex

Additional hardware and software prerequisites for ECDSA:
- Message security assist (MSA) 9 (IBM z15 or later)
- Crypto Express 7S CCA coprocessor (CEX7C) or later for CCA type keys
- Crypto Express 7S EP11 coprocessor (CEX7P) or later for EP11 type keys
- CCA host library version 7.1 or later for CCA type keys
- EP11 host library version 3.0 or later for EP11 type keys

Additional hardware and software prerequisites for full-XTS:
- Message security assist (MSA) 10 (IBM z17 or later)
- A KVM guest in IBM Secure Execution mode for PVSECRET type keys
- Kernel 6.13 or later with support for PVSECRET type keys

Additional hardware and software prerequisites for HMAC:
- Message security assist (MSA) 11 (IBM z17 or later)
- A KVM guest in IBM Secure Execution mode for PVSECRET type keys
- Kernel 6.13 or later with support for PVSECRET type keys

Building `libzpc`:

    mkdir build && cd build
    cmake ..
    make

The following options can be passed to `cmake`:
- `-DCMAKE_INSTALL_PREFIX=<path>` : Change the install prefix from `/usr/local/` to `<path>`.
- `-DCMAKE_BUILD_TYPE=<type>` : Choose predefined build options. The choices for `<type>` are `Debug`, `Release`, `RelWithDebInfo`, and `MinSizeRel`.
- `-DBUILD_SHARED_LIBS=ON` : Build a shared object (instead of an archive).
- `-DBUILD_TEST=ON` : Build the test program.
- `-DBUILD_DOC=ON` : Build the html and latex doc.

See `cmake(1)`.

Custom compile options can also be passed to `cmake` via the `CFLAGS` and `CXXFLAGS` environment variables in the usual way.


Building on non-s390x architectures (cross-build)
---

Basic prerequisites for cross-builds:
- Compiler/Toolchain for s390x
- `-devel` packages of all required shared library for s390x

Toolchain-file with the following settings:
- `CMAKE_SYSTEM_NAME`: name of the target system, `Linux`.
- `CMAKE_C_COMPILER`: Path or command of the cross-c-compiler.
- `CMAKE_CXX_COMPILER`: Path or command of the cross-c++-compiler.
- `CMAKE_FIND_ROOT_PATH`: Path to cross-development files (e.g. libraries
  and headers).
- `CMAKE_FIND_ROOT_PATH_MODE_<module>`: Search mode for modules `PROGRAM`,
  `LIBRARY` and `INCLUDE`.

The provided toolchain-file `s390x-tc-debian.cmake` can be used to cross-build on Debian systems.

Building `libzpc` with a s390x cross-toolchain on Debian:
    mkdir cross-build && cd cross-build
    cmake -DCMAKE_TOOLCHAIN_FILE=../s390x-tc-debian.cmake ..
    make

See `cmake(1)`.

Testing
---

To run all tests, do

    ./runtest

from the build directory.

For AES, the following environment variables can be passed to `./runtest`:
- `ZPC_TEST_AES_KEY_TYPE=<type>` : The choices for `<type>` are `ZPC_AES_KEY_TYPE_CCA_DATA`, `ZPC_AES_KEY_TYPE_CCA_CIPHER` and `ZPC_AES_KEY_TYPE_EP11`. AES tests are skipped if this variable is unset or its value is invalid.
- `ZPC_TEST_AES_KEY_SIZE=<size>` : The choices for `<size>` are `128`, `192` and `256`. AES tests are skipped if this variable is unset or its value is invalid.
- `ZPC_TEST_AES_KEY_FLAGS=<flags>` : `<flags>` is a 4 byte unsigned integer value that specifies the key's flags. `<flags>` defaults to `0` if this variable is unset or its value is invalid.
- `ZPC_TEST_AES_KEY_MKVP=<mkvp>` : Test the APQNs that match `<mkvp>`
and key type.
- `ZPC_TEST_AES_KEY_APQNS=<apqns>` : Test the `<apqns>`.

For AES-XTS when using full-XTS keys, the following environment variables can be passed to `./runtest`:
- `ZPC_TEST_AES_XTS_KEY_TYPE=<type>` : The only supported choice for `<type>` is `ZPC_AES_XTS_KEY_TYPE_PVSECRET`.
- `ZPC_TEST_AES_XTS_KEY_SIZE=<size>` : The choices for `<size>` are `128`, and `256`. AES full-XTS tests are skipped if this variable is unset or its value is invalid.
The pvsecret_kat test compares the results from using one full-XTS key to the results from using two separate AES keys with the same key material. This key material must be added to the pvsecret list file.
When this key material is available in the pvsecret list file, also specify
- `ZPC_TEST_AES_KEY_TYPE=<type>` and 
- `ZPC_TEST_AES_KEY_APQNS=<apqns>` or `ZPC_TEST_AES_KEY_MKVP=<mkvp>`.

For ECDSA, the following environment variables can be passed to `./runtest`:
- `ZPC_TEST_EC_KEY_TYPE=<type>` : The choices for `<type>` are `ZPC_EC_KEY_TYPE_CCA` and `ZPC_EC_KEY_TYPE_EP11`. ECDSA tests are skipped if this variable is unset or its value is invalid.
- `ZPC_TEST_EC_KEY_CURVE=<curve>` : The choices for `<curve>` are `p256` (prime256), `p384` (secp384), `p521` (secp521), `ed25519` (ed25519) and `ed448` (ed448). ECDSA tests are skipped if this variable is unset or its value is invalid.
- `ZPC_TEST_EC_KEY_FLAGS=<flags>` : `<flags>` is a 4 byte unsigned integer value that specifies the key's flags. `<flags>` defaults to `0` if this variable is unset or its value is invalid.
- `ZPC_TEST_EC_KEY_MKVP=<mkvp>` : Test the APQNs that match `<mkvp>`
and key type.
- `ZPC_TEST_EC_KEY_APQNS=<apqns>` : Test the `<apqns>`.

For HMAC, the following environment variables can be passed to `./runtest`:
- `ZPC_TEST_HMAC_KEY_TYPE=<type>`       : The only supported choice for `<type>` is `ZPC_HMAC_KEY_TYPE_PVSECRET`.
- `ZPC_TEST_HMAC_HASH_FUNCTION=<hfunc>` : The choices for `<hfunc>` are `SHA-224`, `SHA-256`, `SHA-384`, and `SHA-512`.
There are no MKVP or APQN related variables for HMAC.

For PVSECRET type keys, the following environment variable must be passed to `./runtest`:
- `ZPC_TEST_PVSECRET_LIST_FILE=<list-file>` : The `<list-file>` must be created with the pvsecret utility
as part of s390-tools v2.37 or later. Perform a 'pvsecret list' command and redirect the output to the list file.
Testers may optionally add clear key data, used when creating Ultravisor retrievable secrets, to the
list file. Example:

    7 HMAC-SHA-256-KEY:
     0xb620b6d76f89910aff90ff9 ...  <- the secret ID
     0xa783830e0bd6f3ae8cade16b3004 ...  <- the clear key 

For PVSECRET type full-XTS keys we have a mixed setting of AES_XTS_KEY and AES_KEY definitions, for example:

    5 AES-XTS-128-KEY:
     0x8ace2a9b ... <- secret ID
     0xbe0274e3f3b363 ... <- clear AES XTS key (2 x 16 bytes)
    6 AES-XTS-256-KEY:
     0x2b56938 ... <- secret ID
     0xbf8260655f43 ... <- clear AES XTS key (2 x 32 bytes)
    ...

If clear key data is available, additional tests (pvsecret_kat) are performed.

See

    ./runtest -h

for help.


Installing
---

To install the shared library, do

    sudo make install
    sudo ldconfig


Configuration
---

To do something useful with `libzpc`, at least one CryptoExpress (CEX) HSM with a master key configuration is required.

The device drivers for CEX adapters are documented in chapters 54 and 57 of the kernel 5.7 version of
[Linux on Z and LinuxONE - Device Drivers, Features, and Commands](https://www.ibm.com/support/knowledgecenter/linuxonibm/liaaf/lnz_r_dd.html).

Here are instructions on [how to set an AES master key](https://www.ibm.com/support/knowledgecenter/linuxonibm/liaaf/lnz_r_dtke.html) for a CEX adapter in CCA coprocessor mode using the Trusted Key Entry (TKE).


Programming
---

Applications include the `<zpc/...>` header files corresponding to the APIs required and link with `-lzp`.

With the exeption of `zpc_error_string`, all `libzpc` function return either no value or an integer which is either zero (in case of success) of a non-zero error code (in case of failure).

In case of multiple errors, the `libzpc` API leaves the precedence of error codes undefined. Therefore, applications should always check for a non-zero return value before handling specific errors e.g.:

    rc = zpc_foo();
    if (rc) {
        /* Handle specific error codes. */
        fprintf(stderr, "Error: %d (%s).\n", rc, zpc_error_string(rc));
    }


Debugging
---

Setting the environment variable `ZPC_DEBUG=1` will have the library print debug information to `stderr`.


License
---

See `LICENSE` file.

