/*
 * Copyright IBM Corp. 2021
 *
 * libzpc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

/*
 * Build test for public header files.
 */

#include "zpc/error.h"
#include "zpc/aes_key.h"
#include "zpc/aes_gcm.h"
#include "zpc/aes_ccm.h"
#include "zpc/aes_xts.h"
#include "zpc/aes_cbc.h"
#include "zpc/aes_ecb.h"
#include "zpc/aes_cmac.h"

#ifndef ZPC_ERROR_H
# error "ZPC_ERROR_H undefined."
#endif
#ifndef ZPC_AES_KEY_H
# error "ZPC_AES_KEY_H undefined."
#endif
#ifndef ZPC_AES_GCM_H
# error "ZPC_AES_GCM_H undefined."
#endif
#ifndef ZPC_AES_CCM_H
# error "ZPC_AES_CCM_H undefined."
#endif
#ifndef ZPC_AES_XTS_H
# error "ZPC_AES_XTS_H undefined."
#endif
#ifndef ZPC_AES_CBC_H
# error "ZPC_AES_CBC_H undefined."
#endif
#ifndef ZPC_AES_ECB_H
# error "ZPC_AES_ECB_H undefined."
#endif
#ifndef ZPC_AES_CMAC_H
# error "ZPC_AES_CMC_H undefined."
#endif

int b_headers_not_empty;
