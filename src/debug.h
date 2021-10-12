
/*
 * Copyright IBM Corp. 2021
 *
 * libzpc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef DEBUG_H
# define DEBUG_H

# include "globals.h"

# include <assert.h>
# include <stdio.h>
# include <unistd.h>
# include <sys/types.h>
# include <sys/syscall.h>
# include <string.h>

# define __FILENAME__ \
	(strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)

# define DEBUG(...)													\
do {																\
	if (debug) {													\
		int rc;														\
																	\
		UNUSED(rc);													\
																	\
		rc = pthread_mutex_lock(&debuglock);						\
		assert(rc == 0);											\
																	\
		fprintf(stderr, "libzpc %d.%d.%d: pid %llu: tid %llu: %s: %s:%d: ",	\
				ZPC_VERSION_MAJOR, ZPC_VERSION_MINOR, ZPC_VERSION_PATCH,	\
			    (unsigned long long)getpid(),						\
				(unsigned long long)syscall(SYS_gettid),			\
				__func__, __FILENAME__, __LINE__);					\
		fprintf(stderr, __VA_ARGS__);								\
		fprintf(stderr, "\n");										\
																	\
		rc = pthread_mutex_unlock(&debuglock);						\
		assert(rc == 0);											\
	}																\
} while (0)

#endif
