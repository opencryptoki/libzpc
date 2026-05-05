###############################################################################
set(ZPC_NAME          "libzpc"                                                )
set(ZPC_DESCRIPTION   "IBM Z Protected-key Crypto library"                    )
set(ZPC_VERSION_MAJOR 1                                                       )
set(ZPC_VERSION_MINOR 5                                                       )
set(ZPC_VERSION_PATCH 0                                                       )
set(ZPC_VERSION ${ZPC_VERSION_MAJOR}.${ZPC_VERSION_MINOR}.${ZPC_VERSION_PATCH})
###############################################################################

cmake_minimum_required(
    VERSION 3.10
)

# Honor symbol visibility properties for all target types.
# https://cmake.org/cmake/help/git-stage/policy/CMP0063.html
if(POLICY CMP0063)
    cmake_policy(SET CMP0063 NEW)
endif()

# New in version 3.24: prefer to set the timestamps of all extracted contents
# to the time of the extraction.
# https://cmake.org/cmake/help/git-stage/policy/CMP0135.html
if(POLICY CMP0135)
    cmake_policy(SET CMP0135 NEW)
endif()

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_FLAGS_DEBUG "-Wall -Wextra -m64 -g -O0")
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_FLAGS_DEBUG "-Wall -Wextra -m64 -g -O0")

option(BUILD_ASAN OFF)

if (BUILD_ASAN)
string(APPEND
    CMAKE_C_FLAGS_DEBUG
    " -fsanitize=undefined -fsanitize=address"
)

string(APPEND
    CMAKE_CXX_FLAGS_DEBUG
    " -fsanitize=undefined -fsanitize=address"
)
endif () # BUILD_ASAN

project(${ZPC_NAME}
    VERSION     ${ZPC_VERSION}
    DESCRIPTION ${ZPC_DESCRIPTION}
    LANGUAGES   CXX C ASM
)

set(ZPC_HEADERS
    include/zpc/init.h
    include/zpc/error.h
    include/zpc/aes_key.h
    include/zpc/aes_xts_key.h
    include/zpc/aes_gcm.h
    include/zpc/aes_ccm.h
    include/zpc/aes_xts.h
    include/zpc/aes_xts_full.h
    include/zpc/aes_cbc.h
    include/zpc/aes_ecb.h
    include/zpc/aes_cmac.h
    include/zpc/ecc_key.h
    include/zpc/ecdsa_ctx.h
    include/zpc/hmac_key.h
    include/zpc/hmac.h
)

set(ZPC_SOURCES
    src/globals.c
    src/error.c
    src/misc.c
    src/misc_asm.S
    src/aes_key.c
    src/aes_xts_key.c
    src/aes_ecb.c
    src/aes_cbc.c
    src/aes_xts.c
    src/aes_xts_full.c
    src/aes_cmac.c
    src/aes_ccm.c
    src/aes_gcm.c
    src/ecc_key.c
    src/ecdsa_ctx.c
    src/pvsecrets.c
    src/hmac_key.c
    src/hmac.c

    src/zkey/utils.c
    src/zkey/pkey.c
    src/zkey/cca.c
    src/zkey/ep11.c

    src/zkey/lib/util_base.c
    src/zkey/lib/util_file.c
    src/zkey/lib/util_libc.c
    src/zkey/lib/util_panic.c
    src/zkey/lib/util_path.c
    src/zkey/lib/util_prg.c
)

set(THREADS_PREFER_PTHREAD_FLAG TRUE)
find_package(Threads
    REQUIRED
)

find_package(json-c
    REQUIRED
)

find_package(OpenSSL
    3.0.7
    REQUIRED
)

find_package(PkgConfig
    QUIET
)

add_definitions(
    -D_GNU_SOURCE
)

set(ZPC_LIBS
    Threads::Threads ${CMAKE_DL_LIBS}
)

add_library(
    zpc OBJECT
    ${ZPC_SOURCES}
)

target_include_directories(zpc PRIVATE include src src/zkey)
target_link_libraries(zpc ${ZPC_LIBS})
target_compile_definitions(
    zpc PRIVATE
    ZPC_VERSION_MAJOR=${ZPC_VERSION_MAJOR}
    ZPC_VERSION_MINOR=${ZPC_VERSION_MINOR}
    ZPC_VERSION_PATCH=${ZPC_VERSION_PATCH}
)
include(GNUInstallDirs)

###########################################################
# URI

set (URI_SOURCES
    src/uri.c
)

add_library(
    uri OBJECT
    ${URI_SOURCES}
)

set_target_properties(
    uri
    PROPERTIES
    POSITION_INDEPENDENT_CODE ON
)

target_include_directories(
    uri
    PRIVATE
    ${OPENSSL_INCLUDE_DIR}
)

###########################################################
# zpcprovider

set(ZPCPROVIDER_SOURCES
    src/provider.c
    src/object.c
    src/map.c
    src/store.c
    src/keymgmt.c
)

add_library(
    zpcprovider MODULE
    ${ZPCPROVIDER_SOURCES}
)

set_target_properties(
    zpcprovider
    PROPERTIES
    PREFIX ""
)

target_include_directories(
    zpcprovider
    PRIVATE
    src
    include
    ${OPENSSL_INCLUDE_DIR}
)

target_compile_definitions(
    zpcprovider
    PRIVATE
    PROV_VERSION="${ZPC_VERSION}"
)

target_link_libraries(
    zpcprovider
    PRIVATE
    OpenSSL::Crypto
    $<TARGET_OBJECTS:uri>
    $<TARGET_OBJECTS:zpc>
)

target_link_options(
    zpcprovider
    PRIVATE
    -Wl,--version-script=${CMAKE_SOURCE_DIR}/zpcprovider.map
)

if (BUILD_ASAN)
target_link_options(
    zpcprovider
    BEFORE PUBLIC -fsanitize=undefined
    PUBLIC -fsanitize=address
)
endif () # BUILD_ASAN

if(PkgConfig_FOUND)
    pkg_get_variable(OSSL_MODULESDIR libcrypto modulesdir)
else()
    set(OSSL_MODULESDIR ${CMAKE_INSTALL_LIBEXECDIR})
endif()
message(STATUS "OpenSSL module install directory: ${OSSL_MODULESDIR}")

install(
    TARGETS zpcprovider
    LIBRARY
    DESTINATION ${OSSL_MODULESDIR}
)

install(
    FILES ${CMAKE_BINARY_DIR}/hbkzpcprovider.conf.5
    DESTINATION ${CMAKE_INSTALL_MANDIR}/man5
)

install(
    FILES ${CMAKE_BINARY_DIR}/hbkzpcprovider.7
    DESTINATION ${CMAKE_INSTALL_MANDIR}/man7
)

###########################################################
# Test

option(BUILD_TEST OFF)
option(BUILD_INTERNAL_TEST OFF)

if (BUILD_INTERNAL_TEST)

enable_testing()

set(GTEST_GIT
    https://github.com/google/googletest.git
)
set(GTEST_TAG
    release-1.12.1
)

set(WYCHEPROOF_GIT
    https://github.com/google/wycheproof.git
)
set(WYCHEPROOF_TAG
    2196000605e45d91097147c9c71f26b72af58003
)

set(NIST_AES_URL
    https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/aes/aesmmt.zip
)
set(NIST_AES_SHA256
    12d1616f7a713e807714055973f04efc402f46a14e3d81869717c7ace4ecbaf0
)

set(NIST_AES_GCM_URL
    https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/mac/gcmtestvectors.zip
)
set(NIST_AES_GCM_SHA256
    f9fc479e134cde2980b3bb7cddbcb567b2cd96fd753835243ed067699f26a023
)

set(NIST_AES_CCM_URL
    https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/mac/ccmtestvectors.zip
)
set(NIST_AES_CCM_SHA256
    0e3c96761bd8f1a0b4dfe666146c32f7d367a49968375ff091b8da9ecaa673aa
)

set(NIST_AES_CCM_URL
    https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/mac/ccmtestvectors.zip
)
set(NIST_AES_CCM_SHA256
    0e3c96761bd8f1a0b4dfe666146c32f7d367a49968375ff091b8da9ecaa673aa
)

set(NIST_AES_CMAC_URL
    https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/mac/cmactestvectors.zip
)
set(NIST_AES_CMAC_SHA256
    bdda4edade394c9a2ae74d9cd0921caa120c911a5e735e37abf39d0d5f062be1
)

set(NIST_AES_XTS_URL
    https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/aes/XTSTestVectors.zip
)
set(NIST_AES_XTS_SHA256
    67bb04b018182f65530596786e7783f817d2e56509bf3b1f066609b8e3e29c36
)

set(NIST_ECDSA_URL
    https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/components/186-3ecdsasiggencomponenttestvectors.zip
)
set(NIST_ECDSA_SHA256
    cf07d0b3c961032138a072feba237be51da6ff1f9f5af1230e1d6e84858a164f
)

include(ExternalProject)

ExternalProject_Add(nist_aes
    URL               ${NIST_AES_URL}
    URL_HASH          SHA256=${NIST_AES_SHA256}
    PREFIX            ${CMAKE_BINARY_DIR}/nist_aes
    CONFIGURE_COMMAND ""
    BUILD_COMMAND     ""
    INSTALL_COMMAND   ""
    TEST_COMMAND      ""
)
ExternalProject_Get_Property(nist_aes SOURCE_DIR)
set(NIST_AES_SOURCE_DIR
    ${SOURCE_DIR}
)
add_custom_command(
    OUTPUT            nist_aes_ecb.json
    COMMAND           ${CMAKE_SOURCE_DIR}/misc/nist2json_aes_ecb.pl
                          ${NIST_AES_SOURCE_DIR}/ECBMMT*
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    DEPENDS           nist_aes
)
add_custom_target(nist_aes_ecb_json ALL DEPENDS nist_aes_ecb.json)
add_custom_command(
    OUTPUT            nist_aes_cbc.json
    COMMAND           ${CMAKE_SOURCE_DIR}/misc/nist2json_aes_cbc.pl
                          ${NIST_AES_SOURCE_DIR}/CBCMMT*
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    DEPENDS           nist_aes
)
add_custom_target(nist_aes_cbc_json ALL DEPENDS nist_aes_cbc.json)

ExternalProject_Add(nist_aes_xts
    URL               ${NIST_AES_XTS_URL}
    URL_HASH          SHA256=${NIST_AES_XTS_SHA256}
    PREFIX            ${CMAKE_BINARY_DIR}/nist_aes_xts
    CONFIGURE_COMMAND ""
    BUILD_COMMAND     ""
    INSTALL_COMMAND   ""
    TEST_COMMAND      ""
)
ExternalProject_Get_Property(nist_aes_xts SOURCE_DIR)
set(NIST_AES_XTS_SOURCE_DIR
    ${SOURCE_DIR}
)
add_custom_command(
    OUTPUT            nist_aes_xts.json
    COMMAND           ${CMAKE_SOURCE_DIR}/misc/nist2json_aes_xts.pl
                           ${NIST_AES_XTS_SOURCE_DIR}/'format tweak value input - 128 hex str'/*
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    DEPENDS           nist_aes_xts
)
add_custom_target(nist_aes_xts_json ALL DEPENDS nist_aes_xts.json)

ExternalProject_Add(nist_aes_gcm
    URL               ${NIST_AES_GCM_URL}
    URL_HASH          SHA256=${NIST_AES_GCM_SHA256}
    PREFIX            ${CMAKE_BINARY_DIR}/nist_aes_gcm
    CONFIGURE_COMMAND ""
    BUILD_COMMAND     ""
    INSTALL_COMMAND   ""
    TEST_COMMAND      ""
)
ExternalProject_Get_Property(nist_aes_gcm SOURCE_DIR)
set(NIST_AES_GCM_SOURCE_DIR
    ${SOURCE_DIR}
)
add_custom_command(
    OUTPUT            nist_aes_gcm.json
    COMMAND           ${CMAKE_SOURCE_DIR}/misc/nist2json_aes_gcm.pl
                          ${NIST_AES_GCM_SOURCE_DIR}/*
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    DEPENDS           nist_aes_gcm
)
add_custom_target(nist_aes_gcm_json ALL DEPENDS nist_aes_gcm.json)

ExternalProject_Add(nist_aes_ccm
    URL               ${NIST_AES_CCM_URL}
    URL_HASH          SHA256=${NIST_AES_CCM_SHA256}
    PREFIX            ${CMAKE_BINARY_DIR}/nist_aes_ccm
    CONFIGURE_COMMAND ""
    BUILD_COMMAND     ""
    INSTALL_COMMAND   ""
    TEST_COMMAND      ""
)
ExternalProject_Get_Property(nist_aes_ccm SOURCE_DIR)
set(NIST_AES_CCM_SOURCE_DIR
    ${SOURCE_DIR}
)

ExternalProject_Add(nist_aes_cmac
    URL               ${NIST_AES_CMAC_URL}
    URL_HASH          SHA256=${NIST_AES_CMAC_SHA256}
    PREFIX            ${CMAKE_BINARY_DIR}/nist_aes_cmac
    CONFIGURE_COMMAND ""
    BUILD_COMMAND     ""
    INSTALL_COMMAND   ""
    TEST_COMMAND      ""
)
ExternalProject_Get_Property(nist_aes_cmac SOURCE_DIR)
set(NIST_AES_CMAC_SOURCE_DIR
    ${SOURCE_DIR}
)

ExternalProject_Add(nist_ecdsa
    URL               ${NIST_ECDSA_URL}
    URL_HASH          SHA256=${NIST_ECDSA_SHA256}
    PREFIX            ${CMAKE_BINARY_DIR}/nist_ecdsa
    CONFIGURE_COMMAND ""
    BUILD_COMMAND     ""
    INSTALL_COMMAND   ""
    TEST_COMMAND      ""
)
ExternalProject_Get_Property(nist_ecdsa SOURCE_DIR)
set(NIST_ECDSA_SOURCE_DIR
    ${SOURCE_DIR}
)
add_custom_command(
    OUTPUT            nist_ecdsa.json
    COMMAND           ${CMAKE_SOURCE_DIR}/misc/nist2json_ecdsa.pl
                          ${NIST_ECDSA_SOURCE_DIR}/SigGenComponent.txt
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    DEPENDS           nist_ecdsa
)
add_custom_target(nist_ecdsa_json ALL DEPENDS nist_ecdsa.json)

add_custom_command(
    OUTPUT            nist_eddsa.json
    COMMAND           ${CMAKE_COMMAND} -E copy
                          ${CMAKE_SOURCE_DIR}/misc/nist_eddsa.json
                          ${CMAKE_BINARY_DIR}
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
)
add_custom_target(nist_eddsa_json ALL DEPENDS nist_eddsa.json)

ExternalProject_Add(wycheproof
    GIT_REPOSITORY    ${WYCHEPROOF_GIT}
    GIT_TAG           ${WYCHEPROOF_TAG}
    PREFIX            ${CMAKE_BINARY_DIR}/wycheproof
    CONFIGURE_COMMAND ""
    BUILD_COMMAND     ""
    INSTALL_COMMAND   ""
    TEST_COMMAND      ""
)

ExternalProject_Add(gtest
    GIT_REPOSITORY    ${GTEST_GIT}
    GIT_TAG           ${GTEST_TAG}
    PREFIX            ${CMAKE_BINARY_DIR}/gtest
    INSTALL_COMMAND   ""
    TEST_COMMAND      ""
    CMAKE_ARGS        "-DCMAKE_TOOLCHAIN_FILE=${CMAKE_TOOLCHAIN_FILE}"
)
ExternalProject_Get_Property(gtest SOURCE_DIR BINARY_DIR)
set(GTEST_INCLUDE_DIR
    ${SOURCE_DIR}/googletest/include
)
set(GTEST_LIB_DIR
    ${BINARY_DIR}/lib
)

set(ZPC_TEST_LIBS
    ${GTEST_LIB_DIR}/libgtest_main.a
    ${GTEST_LIB_DIR}/libgtest.a
    Threads::Threads
    json-c::json-c
    $<TARGET_OBJECTS:zpc>
)

set(ZPC_TEST_SOURCES
    test/testlib.cc
    test/b_platform.c
    test/b_headers.c
    test/b_error.c
    test/b_aes_key.c
    test/b_aes_xts_key.c
    test/b_aes_ecb.c
    test/b_aes_cbc.c
    test/b_aes_xts.c
    test/b_aes_xts_full.c
    test/b_aes_cmac.c
    test/b_aes_ccm.c
    test/b_aes_gcm.c
    test/b_ecc_key.c
    test/b_ecdsa_ctx.c
    test/b_hmac_key.c
    test/b_hmac.c
    test/t_system.cc
    test/t_testlib.cc
    test/t_environment.cc
    test/t_error.cc
    test/t_aes_key.cc
    test/t_aes_xts_key.cc
    test/t_aes_ecb.cc
    test/t_aes_cbc.cc
    test/t_aes_cmac.cc
    test/t_aes_xts.cc
    test/t_aes_xts_full.cc
    test/t_aes_ccm.cc
    test/t_aes_gcm.cc
    test/t_ecc_key.cc
    test/t_ecdsa_ctx.cc
    test/t_hmac_key.cc
    test/t_hmac.cc
)

add_executable(runtest ${ZPC_TEST_SOURCES})
add_dependencies(runtest gtest)
target_link_libraries(runtest ${ZPC_TEST_LIBS})
target_include_directories(runtest PRIVATE include src ${GTEST_INCLUDE_DIR})

include(GoogleTest)
gtest_discover_tests(runtest)

endif () # BUILD_INTERNAL_TEST

###########################################################
# doc

option(BUILD_DOC OFF)

if (BUILD_DOC)

find_package(Doxygen)

if (DOXYGEN_FOUND)

set(DOXYFILE
    ${CMAKE_BINARY_DIR}/doc/Doxyfile
)
set(DOXYFILE_IN
    ${CMAKE_SOURCE_DIR}/doc/Doxyfile.in
)
configure_file(${DOXYFILE_IN} ${DOXYFILE} @ONLY)
add_custom_target(doc
    ALL
    COMMAND           ${DOXYGEN_EXECUTABLE} ${DOXYFILE}
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    VERBATIM
)

endif ()

endif ()

###########################################################
# man

find_program(PANDOC pandoc)

if (PANDOC)

add_custom_target(
    man ALL
    COMMAND ${CMAKE_SOURCE_DIR}/conv_man.sh "${CMAKE_SOURCE_DIR}/man" "${CMAKE_BINARY_DIR}"
)

endif () # PANDOC_FOUND
