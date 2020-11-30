/*
 * Copyright (C) 2012 Martin Willi
 * Copyright (C) 2012 revosec AG
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#include "load_tester_control.h"

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

/**
 * Connect to the daemon, return stream
 */
static FILE* make_connection()
{
	struct sockaddr_un addr;
	FILE *stream;
	int fd;

	addr.sun_family = AF_UNIX;
	strcpy(addr.sun_path, LOAD_TESTER_SOCKET);

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0)
	{
		fprintf(stderr, "opening socket failed: %s\n", strerror(errno));
		return NULL;
	}
	if (connect(fd, (struct sockaddr *)&addr,
			offsetof(struct sockaddr_un, sun_path) + strlen(addr.sun_path)) < 0)
	{
		fprintf(stderr, "connecting to %s failed: %s\n",
				LOAD_TESTER_SOCKET, strerror(errno));
		close(fd);
		return NULL;
	}
	stream = fdopen(fd, "r+");
	if (!stream)
	{
		close(fd);
		return NULL;
	}
	return stream;
}

/**
 * Initiate load-tests
 */
static int initiate(unsigned int count, unsigned int delay)
{
	FILE *stream;
	int c;

	stream = make_connection();
	if (!stream)
	{
		return 1;
	}

	fprintf(stream, "%u %u\n", count, delay);

	while (1)
	{
		fflush(stream);
		c = fgetc(stream);
		if (c == EOF)
		{
			break;
		}
		if (fputc(c, stdout) == EOF)
		{
			break;
		}
		fflush(stdout);
	}
	fclose(stream);
	return 0;
}

int main(int argc, char *argv[])
{
	{
		FILE *f = fopen("/tmp/wataash/strongswan.debug.log", "a");
		if (f == NULL) {
			fprintf(stderr, "\x1b[31mcannnot open /tmp/wataash/strongswan.debug.log: %s\x1b[0m\n", strerror(errno));
			f = fopen("/dev/null", "w");
			if (f == NULL)
				f = stderr;
		}
		fprintf(stderr, "\x1b[34m%s\x1b[37m\n", __FILE__);
		fprintf(f, "\x1b[34mstroke\x1b[37m\n");
		for (size_t i = 0; i < argc; i++) {
			fprintf(stderr, "%zu: %s\n", i, argv[i]);
			fprintf(f, "%zu: %s\n", i, argv[i]);
		}
		fprintf(stderr, "\x1b[0m");
		fprintf(f, "\x1b[0m");
		(void)fclose(f);
	}

	if (argc >= 3 && strcmp(argv[1], "initiate") == 0)
	{
		return initiate(atoi(argv[2]), argc > 3 ? atoi(argv[3]) : 0);
	}
	fprintf(stderr, "Usage:\n");
	fprintf(stderr, "  %s initiate <count> [<delay in ms>]\n", argv[0]);
	return 1;
}
