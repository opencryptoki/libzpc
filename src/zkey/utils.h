/*
 * zkey - Generate, re-encipher, and validate secure keys
 *
 * This header file defines the interface to the CCA host library.
 *
 * Copyright IBM Corp. 2019
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef UTILS_H
#define UTILS_H

#include "lib/zt_common.h"

#include "pkey.h"

int sysfs_is_card_online(unsigned int card, enum card_type cardtype);

#define SERIALNR_LENGTH		17

int sysfs_get_serialnr(unsigned int card, char *serialnr, bool verbose);

#endif
