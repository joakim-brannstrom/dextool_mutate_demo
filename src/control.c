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

#include "config.h"

#include <stdio.h>

#include "mqtt_protocol.h"
#include "mosquitto_broker_internal.h"

/* Process messages coming in on $CONTROL/<feature>. These messages aren't
 * passed on to other clients. */
int control__process(struct mosquitto_db *db, struct mosquitto *context, struct mosquitto_msg_store *stored)
{
	return MOSQ_ERR_SUCCESS;
}
