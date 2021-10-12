/*
 * Copyright IBM Corp. 2021
 *
 * libzpc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#if !defined(__linux__) && !defined(__s390x__)
# error "Supported platforms: linux-s390x."
#endif

int b_platform_not_empty;
