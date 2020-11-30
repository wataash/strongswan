/*
 * Copyright (C) 2010 Martin Willi
 * Copyright (C) 2010 revosec AG
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
#include <asn1/asn1.h>

/**
 * convert string OID to DER encoding
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

	int i, nr = 0;
	chunk_t oid;
	char *decoded;
	bool decode = FALSE;

	if (streq(argv[1], "-d"))
	{
		decode = TRUE;
		nr++;
	}

	while (argc > ++nr)
	{
		if (decode)
		{
			oid = chunk_from_hex(chunk_from_str(argv[nr]), NULL);
			decoded = asn1_oid_to_string(oid);
			printf("%s\n", decoded);
			free(decoded);
			free(oid.ptr);
			continue;
		}
		oid = asn1_oid_from_string(argv[nr]);
		if (oid.len)
		{
			for (i = 0; i < oid.len; i++)
			{
				printf("0x%02x,", oid.ptr[i]);
			}
			printf("\n");
			free(oid.ptr);
		}
		else
		{
			return 1;
		}
	}
	return 0;
}
