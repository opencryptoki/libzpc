/*
 * Support for Ultravisor retrievable secrets
 *
 * Copyright IBM Corp. 2024
 *
 */

#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>

#include "pvsecrets.h"

#define SE_GUEST "/sys/firmware/uv/prot_virt_guest"
#define MAX_SECRETS "/sys/firmware/uv/query/max_secrets"

int running_in_se_guest(void)
{
	FILE *fd;
	char se_flag;

	if ((fd = fopen(SE_GUEST, "r")) == NULL)
		return 0;

	if (fread(&se_flag, sizeof(se_flag), 1, fd) != 1) {
		fclose(fd);
		return 0;
	}

	fclose(fd);

	return se_flag - '0' ? 1 : 0;
}

long max_secrets(void)
{
	FILE *fd;
	char buf[8] = { 0, };

	if ((fd = fopen(MAX_SECRETS, "r")) == NULL)
		return 0;

	if (fread(buf, 1, sizeof(buf), fd) == 0) {
		fclose(fd);
		return 0;
	}

	fclose(fd);

	return atol(buf);
}
