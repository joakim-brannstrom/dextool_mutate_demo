/*
Copyright (c) 2009-2019 Roger Light <roger@atchoo.org>

All rights reserved. This program and the accompanying materials
are made available under the terms of the Eclipse Public License v1.0
and Eclipse Distribution License v1.0 which accompany this distribution.

The Eclipse Public License is available at
   http://www.eclipse.org/legal/epl-v10.html
and the Eclipse Distribution License is available at
  http://www.eclipse.org/org/documents/edl-v10.php.

Contributors:
   Roger Light - initial implementation and documentation.
   Tatsuzo Osawa - Add epoll.
*/

#include "mux.h"

int mux__init(struct mosquitto_db *db, mosq_sock_t *listensock, int listensock_count)
{
#ifdef WITH_EPOLL
	return mux_epoll__init(db, listensock, listensock_count);
#else
	return mux_poll__init(db, listensock, listensock_count);
#endif
}

int mux__add_out(struct mosquitto_db *db, struct mosquitto *context)
{
#ifdef WITH_EPOLL
	return mux_epoll__add_out(db, context);
#else
	return mux_poll__add_out(db, context);
#endif
}


int mux__remove_out(struct mosquitto_db *db, struct mosquitto *context)
{
#ifdef WITH_EPOLL
	return mux_epoll__remove_out(db, context);
#else
	return mux_poll__remove_out(db, context);
#endif
}


int mux__add_in(struct mosquitto_db *db, struct mosquitto *context)
{
#ifdef WITH_EPOLL
	return mux_epoll__add_in(db, context);
#else
	return mux_poll__add_in(db, context);
#endif
}


int mux__delete(struct mosquitto_db *db, struct mosquitto *context)
{
#ifdef WITH_EPOLL
	return mux_epoll__delete(db, context);
#else
	return mux_poll__delete(db, context);
#endif
}


int mux__handle(struct mosquitto_db *db, mosq_sock_t *listensock, int listensock_count)
{
#ifdef WITH_EPOLL
	return mux_epoll__handle(db, listensock, listensock_count);
#else
	return mux_poll__handle(db, listensock, listensock_count);
#endif
}


int mux__cleanup(struct mosquitto_db *db)
{
#ifdef WITH_EPOLL
	return mux_epoll__cleanup(db);
#else
	return mux_poll__cleanup(db);
#endif
}
