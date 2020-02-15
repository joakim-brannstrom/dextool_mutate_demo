/*
Copyright (c) 2020 Roger Light <roger@atchoo.org>

All rights reserved. This program and the accompanying materials
are made available under the terms of the Eclipse Public License v1.0
and Eclipse Distribution License v1.0 which accompany this distribution.

The Eclipse Public License is available at
   http://www.eclipse.org/legal/epl-v10.html
and the Eclipse Distribution License is available at
  http://www.eclipse.org/org/documents/edl-v10.php.

Contributors:
   Roger Light - initial implementation and documentation.
*/

#ifndef MUX_H
#define MUX_H

#include "mosquitto_broker_internal.h"

int mux_epoll__init(struct mosquitto_db *db, mosq_sock_t *listensock, int listensock_count);
int mux_epoll__add_out(struct mosquitto_db *db, struct mosquitto *context);
int mux_epoll__remove_out(struct mosquitto_db *db, struct mosquitto *context);
int mux_epoll__add_in(struct mosquitto_db *db, struct mosquitto *context);
int mux_epoll__delete(struct mosquitto_db *db, struct mosquitto *context);
int mux_epoll__handle(struct mosquitto_db *db, mosq_sock_t *listensock, int listensock_count);
int mux_epoll__cleanup(struct mosquitto_db *db);

int mux_poll__init(struct mosquitto_db *db, mosq_sock_t *listensock, int listensock_count);
int mux_poll__add_out(struct mosquitto_db *db, struct mosquitto *context);
int mux_poll__remove_out(struct mosquitto_db *db, struct mosquitto *context);
int mux_poll__add_in(struct mosquitto_db *db, struct mosquitto *context);
int mux_poll__delete(struct mosquitto_db *db, struct mosquitto *context);
int mux_poll__handle(struct mosquitto_db *db, mosq_sock_t *listensock, int listensock_count);
int mux_poll__cleanup(struct mosquitto_db *db);

#endif
