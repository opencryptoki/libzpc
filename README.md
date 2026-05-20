Introduction
============

The IBM Z Protected-key Crypto library `libzpc` is an open-source library
targeting the 64-bit Linux on IBM Z (s390x) platform. It provides interfaces for
cryptographic primitives. The underlying implementations make use of
z/Architecture's extensive performance-boosting hardware support and its
*protected-key* feature which ensures that key material is never present in main
memory at any time.

The `libzpc` source is hosted on [GitHub](https://github.com/opencryptoki/libzpc).


Supported crypto
----------------

Elliptic-curve digital signature create/verify (ECDSA):

    prime256, oid = 1.2.840.10045.3.1.7
    secp384, oid = 1.3.132.0.34
    secp521, oid = 1.3.132.0.35
    ed25519, oid = 1.3.101.112
    ed448, oid = 1.3.101.113

Building
--------

Basic prerequisites for building the library only:
- Linux kernel >= 5.7
- C99 compiler (clang, gcc)
- libpthread
- cmake >= 3.10
- make
- OpenSSL >= 3.0.7
- clang-format

Additional prerequisites for building the internal test program:
- C++11 compiler (clang, g++)
- libjson-c devel package >= 0.13
- internet connection

Additional prerequisites for building the man-pages:
- pandoc

Additional prerequisites for building the internal html and latex doc:
- doxygen >= 1.8.17
- latex, bibtex

Additional hardware and software prerequisites for ECDSA:
- Message security assist (MSA) 9 (IBM z15 or later)
- A KVM guest in IBM Secure Execution mode for PVSECRET type keys
- Kernel 6.13 or later with support for PVSECRET type keys

Building `libzpc`:

    cmake -B build -S .
    cmake --build build    # or
    make -C build

The following options can be passed to `cmake`:

- `-DCMAKE_INSTALL_PREFIX=<path>` : Change the install prefix from `/usr/local/`
  to `<path>`.
- `-DCMAKE_BUILD_TYPE=<type>` : Choose predefined build options. The choices for
  `<type>` are `Debug`, `Release`, `RelWithDebInfo`, and `MinSizeRel`.
- `-DBUILD_TEST=ON` : Build test programs.
- `-DBUILD_INTERNAL_TEST=ON` : Build the internal test program.
- `-DBUILD_DOC=ON` : Build the internal html and latex doc.
- `DCMAKE_TOOLCHAIN_FILE=<cross-tc-file>` : Setup a cross-build environment.

See `cmake(1)`.

Custom compile options can also be passed to `cmake` via the `CFLAGS` and
`CXXFLAGS` environment variables in the usual way.


Cross-Building for s390x architecture
-------------------------------------

The core-component of the project, the OpenSSL provider module, can only be
built for the target architecture `s390x`. To build it on non-s390x
architectures, a cross-build environment has to be setup.

Basic prerequisites for cross-builds:
- Compiler/Toolchain for s390x
- `-devel` packages of all required shared library for s390x

Toolchain-file with the following settings:
- `CMAKE_SYSTEM_NAME`: name of the target system, `Linux`.
- `CMAKE_SYSTEM_PROCESSOR`: target processor architecture.
- `CMAKE_C_COMPILER`: Path or command of the cross-c-compiler.
- `CMAKE_CXX_COMPILER`: Path or command of the cross-c++-compiler.
- `CMAKE_FIND_ROOT_PATH`: Path to cross-development files (e.g. libraries
  and headers).
- `CMAKE_FIND_ROOT_PATH_MODE_<module>`: Search mode for modules `PROGRAM`,
  `LIBRARY` and `INCLUDE`.

The provided toolchain-file `s390x-tc-debian.cmake` can be used to cross-build
on Debian systems.

Building `libzpc` with a s390x cross-toolchain on Debian:

    cmake -B build -S . -DCMAKE_TOOLCHAIN_FILE=s390x-tc-debian.cmake
    cmake --build build    # or
    make -C build

See `cmake(1)`.


Building RPM packages
---------------------

Building `libzpc` RPM packages:

    sudo dnf builddep --spec libzpc.spec
    rpmdev-spectool --get-files --sourcedir libzpc.spec
    rpmbuild -ba libzpc.spec

The build results will be in ~/rpmbuild/RPMS and ~/rpmbuild/SRPMS
respectively.


Installing
----------

To install the shared library, do

    cmake -B build -S .
    cmake --build build && sudo cmake --build build --target install   # or
    make -C build       && sudo make -C build install


Configuration
-------------

The hbkzpc provider for OpenSSL can be either configured system-wide or only for
single OpenSSL applications. Both configuration methods are described in the
configuration man page for the hbkzpc provider. See [configuration man
page](man/hbkzpcprovider.conf.5.md) for more details.


Programming
-----------

Applications can use the OpenSSL EVP\_PKEY API and all related algorithms to
exploit the protected-key operations. By using the provider-specific keys,
protected key origins, the OpenSSL will transparently select the configured
hbkzpc provider.

The protected-key origins can be managed with the tool `zpckey`. See [zpckey man
page](man/zpckey.1.md) for more details.


Debugging
---------

Setting the environment variable `ZPC_DEBUG=1` will have the library print debug
information to `stderr`.


Testing
-------

The project provides test scripts to test the provider and its registered
functions. All test scripts can are located in `./test` directory.

- *t\_ossl\_uv\_preparekey*: Checks for existing private keys, extract the
  public keys and compose the related provider protected-key origins.
- *t\_ossl\_uv\_pkey*: Parameter handling tests for provider keys.
- *t_\ossl\_uv\_sign\_verify*: Sign/verify tests with provider keys and
  clear keys.

The test scripts expect required configuration files and key material
relative to the current working directory. It is possible to change this
behavior by setting environment variables:

- *OPENSSL\_CONF*: The path to the used OpenSSL configuration file.
- *ZPC\_SEC\_DIR*: Directory for the required secure keys.
- *ZPC\_KEY\_DIR*: Directory for the generated public keys and protected-key
  origin files.

If the tests pass, the all output of the executed commands is suppressed.
Only for failing tests the command output is logged by default. To enable
the command output in all cases, set the environment variable `V` to `1`.

    V=1 ./test/t_ossl_uv_sign_verify

If the tests should use not the installed OpenSSL command-line utility, it
is possible to set the environment variable `OPENSSL` to the path to the
used executable.

    OPENSSL=/path/to/local/openssl ./test/t_ossl_uv_sign_verify


Internal Testing
----------------

The project provides also internal tests for the core protected-key
functions. To run all internal tests, do

    ./runtest

from the build directory.

For AES, the following environment variables can be passed to
`./runtest`:
- `ZPC_TEST_AES_KEY_TYPE=<type>` : The choices for `<type>` are
  `ZPC_AES_KEY_TYPE_CCA_DATA`, `ZPC_AES_KEY_TYPE_CCA_CIPHER` and
  `ZPC_AES_KEY_TYPE_EP11`. AES tests are skipped if this variable is unset or
  its value is invalid.
- `ZPC_TEST_AES_KEY_SIZE=<size>` : The choices for `<size>` are `128`, `192` and
  `256`. AES tests are skipped if this variable is unset or its value is
  invalid.
- `ZPC_TEST_AES_KEY_FLAGS=<flags>` : `<flags>` is a 4 byte unsigned integer
  value that specifies the key's flags. `<flags>` defaults to `0` if this
  variable is unset or its value is invalid.
- `ZPC_TEST_AES_KEY_MKVP=<mkvp>` : Test the APQNs that match `<mkvp>` and key
  type.
- `ZPC_TEST_AES_KEY_APQNS=<apqns>` : Test the `<apqns>`.

For AES-XTS when using full-XTS keys, the following environment variables can be
passed to `./runtest`:
- `ZPC_TEST_AES_XTS_KEY_TYPE=<type>` : The only supported choice for `<type>` is
  `ZPC_AES_XTS_KEY_TYPE_PVSECRET`.
- `ZPC_TEST_AES_XTS_KEY_SIZE=<size>` : The choices for `<size>` are `128`, and
  `256`. AES full-XTS tests are skipped if this variable is unset or its value
  is invalid.  The pvsecret_kat test compares the results from using one
  full-XTS key to the results from using two separate AES keys with the same key
  material. This key material must be added to the pvsecret list file.  When
  this key material is available in the pvsecret list file, also specify
- `ZPC_TEST_AES_KEY_TYPE=<type>` and
- `ZPC_TEST_AES_KEY_APQNS=<apqns>` or `ZPC_TEST_AES_KEY_MKVP=<mkvp>`.

For ECDSA, the following environment variables can be passed to
`./runtest`:
- `ZPC_TEST_EC_KEY_TYPE=<type>` : The choices for `<type>` are
  `ZPC_EC_KEY_TYPE_CCA` and `ZPC_EC_KEY_TYPE_EP11`. ECDSA tests are skipped if
  this variable is unset or its value is invalid.
- `ZPC_TEST_EC_KEY_CURVE=<curve>` : The choices for `<curve>` are `p256`
  (prime256), `p384` (secp384), `p521` (secp521), `ed25519` (ed25519) and
  `ed448` (ed448). ECDSA tests are skipped if this variable is unset or its
  value is invalid.
- `ZPC_TEST_EC_KEY_FLAGS=<flags>` : `<flags>` is a 4 byte unsigned integer value
  that specifies the key's flags. `<flags>` defaults to `0` if this variable is
  unset or its value is invalid.
- `ZPC_TEST_EC_KEY_MKVP=<mkvp>` : Test the APQNs that match `<mkvp>` and key
  type.
- `ZPC_TEST_EC_KEY_APQNS=<apqns>` : Test the `<apqns>`.

For HMAC, the following environment variables can be passed to `./runtest`:
- `ZPC_TEST_HMAC_KEY_TYPE=<type>` : The only supported choice for `<type>` is
  `ZPC_HMAC_KEY_TYPE_PVSECRET`.
- `ZPC_TEST_HMAC_HASH_FUNCTION=<hfunc>` : The choices for `<hfunc>` are
  `SHA-224`, `SHA-256`, `SHA-384`, and `SHA-512`.  There are no MKVP or APQN
  related variables for HMAC.

For PVSECRET type keys, the following environment variable must be passed to
`./runtest`:
- `ZPC_TEST_PVSECRET_LIST_FILE=<list-file>` : The `<list-file>` must be created
  with the pvsecret utility as part of s390-tools v2.37 or later. Perform a
  'pvsecret list' command and redirect the output to the list file.  Testers may
  optionally add clear key data, used when creating Ultravisor retrievable
  secrets, to the list file. Example:

    7 HMAC-SHA-256-KEY:
     0xb620b6d76f89910aff90ff9 ...  <- the secret ID
     0xa783830e0bd6f3ae8cade16b3004 ...  <- the clear key 

For PVSECRET type full-XTS keys we have a mixed setting of AES_XTS_KEY and
AES_KEY definitions, for example:

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


License
-------

See `LICENSE` file.
