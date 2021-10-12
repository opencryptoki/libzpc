###########################################################
set(ZPC_NAME          "libzpc"                            )
set(ZPC_DESCRIPTION   "IBM Z Protected-key Crypto library")
set(ZPC_VERSION_MAJOR 0                                   )
set(ZPC_VERSION_MINOR 0                                   )
set(ZPC_VERSION_PATCH 0                                   )
###########################################################

cmake_minimum_required(
    VERSION 3.10
)

# Honor symbol visibility properties for all target types.
# https://cmake.org/cmake/help/git-stage/policy/CMP0063.html
if(POLICY CMP0063)
    cmake_policy(SET CMP0063 NEW)
endif()

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

project(${ZPC_NAME}
    VERSION     ${ZPC_VERSION_MAJOR}.${ZPC_VERSION_MINOR}.${ZPC_VERSION_PATCH}
    DESCRIPTION ${ZPC_DESCRIPTION}
    LANGUAGES   CXX C ASM
)

set(ZPC_HEADERS
    include/zpc/error.h
    include/zpc/aes_key.h
    include/zpc/aes_gcm.h
    include/zpc/aes_ccm.h
    include/zpc/aes_xts.h
    include/zpc/aes_cbc.h
    include/zpc/aes_ecb.h
    include/zpc/aes_cmac.h
)

set(ZPC_SOURCES
    src/globals.c
    src/error.c
    src/misc.c
    src/misc_asm.S
    src/aes_key.c
    src/aes_ecb.c
    src/aes_cbc.c
    src/aes_xts.c
    src/aes_cmac.c
    src/aes_ccm.c
    src/aes_gcm.c

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

find_library(PTHREAD
    REQUIRED
    NAMES pthread
)

find_library(JSON_C
    REQUIRED
    NAMES json-c
)

add_definitions(
    -D_GNU_SOURCE
)

set(ZPC_LIBS
	${PTHREAD} ${CMAKE_DL_LIBS}
)

add_library(zpc ${ZPC_SOURCES})

set_target_properties(zpc
    PROPERTIES
    VERSION               ${ZPC_VERSION_MAJOR}.${ZPC_VERSION_MINOR}.${ZPC_VERSION_PATCH}
    SOVERSION             ${ZPC_VERSION_MAJOR}
    PUBLIC_HEADER         "${ZPC_HEADERS}"
    C_VISIBILITY_PRESET   hidden
    CXX_VISIBILITY_PRESET hidden
    LINK_FLAGS            "-Wl,--version-script=${CMAKE_SOURCE_DIR}/libzpc.map"
)
target_include_directories(zpc PRIVATE include src src/zkey)
target_link_libraries(zpc ${ZPC_LIBS})
target_compile_definitions(
    zpc PRIVATE
    ZPC_VERSION_MAJOR=${ZPC_VERSION_MAJOR}
    ZPC_VERSION_MINOR=${ZPC_VERSION_MINOR}
    ZPC_VERSION_PATCH=${ZPC_VERSION_PATCH}
)
configure_file(libzpc.pc.in libzpc.pc @ONLY)
include(GNUInstallDirs)

install(
    TARGETS zpc
    LIBRARY DESTINATION       ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION       ${CMAKE_INSTALL_LIBDIR}
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/zpc/
)

install(
    FILES       ${CMAKE_BINARY_DIR}/libzpc.pc
    DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/pkgconfig
)

option(BUILD_TEST OFF)

if (BUILD_TEST)

enable_testing()

set(GTEST_URL
    https://github.com/google/googletest/archive/refs/tags/release-1.11.0.zip
)
set(GTEST_SHA256
    353571c2440176ded91c2de6d6cd88ddd41401d14692ec1f99e35d013feda55a
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
    URL             ${GTEST_URL}
    URL_HASH        SHA256=${GTEST_SHA256}
    PREFIX          ${CMAKE_BINARY_DIR}/gtest
    INSTALL_COMMAND ""
    TEST_COMMAND    ""
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
    ${PTHREAD}
    ${JSON_C}
    zpc
)

set(ZPC_TEST_SOURCES
    test/testlib.cc
    test/b_platform.c
    test/b_headers.c
    test/b_error.c
    test/b_aes_key.c
    test/b_aes_ecb.c
    test/b_aes_cbc.c
    test/b_aes_xts.c
    test/b_aes_cmac.c
    test/b_aes_ccm.c
    test/b_aes_gcm.c
    test/t_system.cc
    test/t_testlib.cc
    test/t_environment.cc
    test/t_error.cc
    test/t_aes_key.cc
    test/t_aes_ecb.cc
    test/t_aes_cbc.cc
    test/t_aes_cmac.cc
    test/t_aes_xts.cc
    test/t_aes_ccm.cc
    test/t_aes_gcm.cc
)

add_executable(runtest ${ZPC_TEST_SOURCES})
add_dependencies(runtest gtest)
target_link_libraries(runtest ${ZPC_TEST_LIBS})
target_include_directories(runtest PRIVATE include src ${GTEST_INCLUDE_DIR})

include(GoogleTest)
gtest_discover_tests(runtest)

endif ()

###########################################################
# doc

option(BUILD_DOC OFF)

if (BUILD_DOC)

find_package(Doxygen)

if (DOXYGEN_FOUND)

set(DOXYFILE
    ${CMAKE_SOURCE_DIR}/doc/Doxyfile
)
add_custom_target(doc
    ALL
    COMMAND           ${DOXYGEN_EXECUTABLE} ${DOXYFILE}
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
)

endif ()

endif ()
