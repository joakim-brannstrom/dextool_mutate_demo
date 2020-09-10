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
#include "memory_mosq.h"
#include "send_mosq.h"

#ifdef WITH_CONTROL
/* Process messages coming in on $CONTROL/<feature>. These messages aren't
 * passed on to other clients. */
int control__process(struct mosquitto_db *db, struct mosquitto *context, struct mosquitto_msg_store *stored)
{
	struct mosquitto__control_callback *control_callback;
	int rc = MOSQ_ERR_SUCCESS;

	HASH_FIND(hh, db->control_callbacks, stored->topic, strlen(stored->topic), control_callback);
	if(control_callback){
		rc = control_callback->function(control_callback->data, context, stored->topic, stored->payloadlen, UHPA_ACCESS(stored->payload, stored->payloadlen));
	}

	if(stored->qos == 1){
		if(send__puback(context, stored->source_mid, 0, NULL)) rc = 1;
	}else if(stored->qos == 2){
		if(send__pubrec(context, stored->source_mid, 0, NULL)) rc = 1;
	}

	return rc;
}
#endif

int mosquitto_control_topic_register(const char *topic, MOSQ_FUNC_control_callback callback, void *data)
{
#ifdef WITH_CONTROL
	struct mosquitto_db *db = mosquitto__get_db();
	struct mosquitto__control_callback *control_callback;

	if(topic == NULL || callback == NULL){
		return MOSQ_ERR_INVAL;
	}
	if(strncmp(topic, "$CONTROL/", strlen("$CONTROL/")) || strlen(topic) < strlen("$CONTROL/A/v1")){
		return MOSQ_ERR_INVAL;
	}

	HASH_FIND(hh, db->control_callbacks, topic, strlen(topic), control_callback);
	if(control_callback){
		return MOSQ_ERR_ALREADY_EXISTS;
	}

	control_callback = mosquitto__calloc(1, sizeof(struct mosquitto__control_callback));
	if(control_callback == NULL){
		return MOSQ_ERR_NOMEM;
	}

	control_callback->topic = mosquitto__strdup(topic);
	if(control_callback->topic == NULL){
		mosquitto__free(control_callback);
		return MOSQ_ERR_NOMEM;
	}
	control_callback->function = callback;
	control_callback->data = data;

	HASH_ADD_KEYPTR(hh, db->control_callbacks, control_callback->topic, strlen(control_callback->topic), control_callback);

	return MOSQ_ERR_SUCCESS;
#else
	return MOSQ_ERR_NOT_SUPPORTED;
#endif
}


int mosquitto_control_topic_unregister(const char *topic)
{
#ifdef WITH_CONTROL
	struct mosquitto_db *db = mosquitto__get_db();
	struct mosquitto__control_callback *control_callback;

	if(topic == NULL || strncmp(topic, "$CONTROL/", strlen("$CONTROL/"))){
		return MOSQ_ERR_INVAL;
	}

	HASH_FIND(hh, db->control_callbacks, topic, strlen(topic), control_callback);
	if(control_callback){
		HASH_DELETE(hh, db->control_callbacks, control_callback);
		mosquitto__free(control_callback->topic);
		mosquitto__free(control_callback);
	}

	return MOSQ_ERR_SUCCESS;
#else
	return MOSQ_ERR_NOT_SUPPORTED;
#endif
}


#ifdef WITH_CONTROL
void control__cleanup(struct mosquitto_db *db)
{
	struct mosquitto__control_callback *control_callback, *cc_tmp;

	HASH_ITER(hh, db->control_callbacks, control_callback, cc_tmp){
		HASH_DELETE(hh, db->control_callbacks, control_callback);
		mosquitto__free(control_callback->topic);
		mosquitto__free(control_callback);
	}
}
#endif
