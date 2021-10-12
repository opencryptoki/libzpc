/*
 * Copyright IBM Corp. 2021
 *
 * libzpc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef GLOBALS_H
# define GLOBALS_H

# include <stdbool.h>
# include <pthread.h>

# include "zkey/cca.h"
# include "zkey/ep11.h"

struct hwcaps {
	int aes_gcm;
	int aes_ccm;
	int aes_ecb;
	int aes_cbc;
	int aes_xts;
	int aes_cmac;
};

/*
 * Globals are initialized at the library's constructor
 * and are read-only or lock-protected afterwards.
 */

extern int pkeyfd;

extern struct hwcaps hwcaps;

extern int debug;
extern pthread_mutex_t debuglock;

extern struct cca_lib cca;
extern pthread_mutex_t ccalock;

extern struct ep11_lib ep11;
extern pthread_mutex_t ep11lock;

#endif
