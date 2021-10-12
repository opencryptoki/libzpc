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

Authenticated Encryption (AEAD):

    AES-128-CCM, AES-192-CCM, AES-256-CCM
    AES-128-GCM, AES-192-GCM, AES-256-GCM


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


Testing
---

To run all tests, do

    ./runtest

from the build directory.

The following environment variables can be passed to `./runtest`:
- `ZPC_TEST_AES_KEY_TYPE=<type>` : The choices for `<type>` are `ZPC_AES_KEY_TYPE_CCA_DATA`, `ZPC_AES_KEY_TYPE_CCA_CIPHER` and `ZPC_AES_KEY_TYPE_EP11`. AES tests are skipped if this variable is unset or its value is invalid.
- `ZPC_TEST_AES_KEY_SIZE=<size>` : The choices for `<size>` are `128`, `192` and `256`. AES tests are skipped if this variable is unset or its value is invalid.
- `ZPC_TEST_AES_KEY_FLAGS=<flags>` : `<flags>` is a 4 byte unsigned integer value that specifies the key's flags. `<flags>` defaults to `0` if this variable is unset or its value is invalid.
- `ZPC_TEST_AES_KEY_MKVP=<mkvp>` : Test the APQNs that match `<mkvp>`
and key type.
- `ZPC_TEST_AES_KEY_APQNS=<apqns>` : Test the `<apqns>`.

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

