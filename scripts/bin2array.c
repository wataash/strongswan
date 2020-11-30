/*
 * Copyright (C) 2008 Martin Willi
 * HSR Hochschule fuer Technik Rapperswil
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

#include <stdio.h>

/**
 * convert standard input to binary data to a c array
 */
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

	int i, end = 0;
	unsigned char byte;

	printf("char %s[] = {\n", argc > 1 ? argv[1] : "data");
	while (1)
	{
		printf("  ");
		for (i = 0; i < 16; i++)
		{
			if (fread(&byte, 1, 1, stdin) != 1)
			{
				end = 1;
				break;
			}
			printf("0x%02x,", (unsigned int)byte);
		}
		printf("\n");
		if (end)
		{
			break;
		}
	}
	printf("};\n");
	return 0;
}

