/*
 * Copyright (C) 2008 Martin Willi
 * Copyright (C) 2008 Philip Boetschi, Adrian Doerig
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

#include <fast_dispatcher.h>
#include <utils/debug.h>
#include <database/database.h>

#include "filter/auth_filter.h"
#include "controller/user_controller.h"
#include "controller/peer_controller.h"

int main(int arc, char *argv[])
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

	fast_dispatcher_t *dispatcher;
	database_t *db;
	char *socket;
	bool debug;
	char *uri;
	int timeout, threads;

	library_init(NULL, "medsrv");
	if (!lib->plugins->load(lib->plugins,
			lib->settings->get_str(lib->settings, "medsrv.load", PLUGINS)))
	{
		return 1;
	}

	socket = lib->settings->get_str(lib->settings, "medsrv.socket", NULL);
	debug = lib->settings->get_bool(lib->settings, "medsrv.debug", FALSE);
	timeout = lib->settings->get_time(lib->settings, "medsrv.timeout", 900);
	threads = lib->settings->get_int(lib->settings, "medsrv.threads", 5);
	uri = lib->settings->get_str(lib->settings, "medsrv.database", NULL);
	if (uri == NULL)
	{
		fprintf(stderr, "database URI medsrv.database not defined.\n");
		return 1;
	}

	db = lib->db->create(lib->db, uri);
	if (db == NULL)
	{
		fprintf(stderr, "opening database failed.\n");
		return 1;
	}

	dispatcher = fast_dispatcher_create(socket, debug, timeout,
					(fast_context_constructor_t)user_create, db);
	dispatcher->add_filter(dispatcher,
					(fast_filter_constructor_t)auth_filter_create, db);
	dispatcher->add_controller(dispatcher,
					(fast_controller_constructor_t)user_controller_create, db);
	dispatcher->add_controller(dispatcher,
					(fast_controller_constructor_t)peer_controller_create, db);

	dispatcher->run(dispatcher, threads);

	dispatcher->waitsignal(dispatcher);
	dispatcher->destroy(dispatcher);
	db->destroy(db);

	library_deinit();
	return 0;
}
