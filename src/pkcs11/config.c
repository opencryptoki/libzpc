// SPDX-License-Identifier: MIT
// Copyright contributors to the libzpc project
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "config.h"

#ifndef SYSCONFDIR
#define SYSCONFDIR "/etc"
#endif
#define CONFIG_FILE_NAME SYSCONFDIR"/zpcpkcs11/zpcpkcs11.conf"
#define CONFIG_ENV_VAR "ZPCPKCS11_CONFIG"

int config_process(int (*cb)(const char *label, const char *uri,
			     size_t lineno))
{
	FILE *fp;
	int rc = 1;
	char *line = NULL;
	size_t size = 0, lineno = 0;
	ssize_t nread;
	char *label, *uri, *saveptr;
	const char *config_filename;

	config_filename = secure_getenv(CONFIG_ENV_VAR);
	if (!config_filename)
		config_filename = CONFIG_FILE_NAME;

	fp = fopen(config_filename, "r");
	if (!fp) {
		fprintf(stderr,
			"zpcpkcs11: Failed to read config file '%s': %s\n",
			 config_filename, strerror(errno));
		return 0;
	}

	while ((nread = getline(&line, &size, fp)) != -1) {
		lineno++;

		if (line[0] == '#' || line[0] == '\0' || line[0] == '\n')
			continue;

		label = strtok_r(line, "= ", &saveptr);
		uri = strtok_r(NULL, "\n ", &saveptr);
		if (!label || !uri || strtok_r(NULL, "\n ", &saveptr)) {
			fprintf(stderr, "zpcpkcs11: Syntax error in '%s' line "
				"%zu: expected '<label>=<uri>.\n",
				config_filename, lineno);
			rc = 0;
			break;
		}

		if (cb && cb(label, uri, lineno) != 1)
			fprintf(stderr, "zpcpkcs11: Failed to add key '%s'"
				" in line %zu\n", label, lineno);
	}

	free(line);
	fclose(fp);
	return rc;
}
