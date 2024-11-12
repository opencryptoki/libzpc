/*
 * Support for Ultravisor retrievable secrets
 *
 * Copyright IBM Corp. 2024
 */

#ifndef PVSECRETS_H
#define PVSECRETS_H


int running_in_se_guest(void);
long max_secrets(void);

#endif
