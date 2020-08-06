/*
Copyright (c) 2016-2020 Roger Light <roger@atchoo.org>

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

#include "mosquitto_broker_internal.h"
#include "mosquitto_internal.h"
#include "mosquitto_broker.h"
#include "memory_mosq.h"
#include "utlist.h"

#ifdef WITH_TLS
#  include <openssl/ssl.h>
#endif

const char *mosquitto_client_address(const struct mosquitto *client)
{
	return client->address;
}


bool mosquitto_client_clean_session(const struct mosquitto *client)
{
	return client->clean_start;
}


const char *mosquitto_client_id(const struct mosquitto *client)
{
	return client->id;
}


int mosquitto_client_keepalive(const struct mosquitto *client)
{
	return client->keepalive;
}


void *mosquitto_client_certificate(const struct mosquitto *client)
{
#ifdef WITH_TLS
	if(client->ssl){
		return SSL_get_peer_certificate(client->ssl);
	}else{
		return NULL;
	}
#else
	return NULL;
#endif
}


int mosquitto_client_protocol(const struct mosquitto *client)
{
#ifdef WITH_WEBSOCKETS
	if(client->wsi){
		return mp_websockets;
	}else
#endif
	{
		return mp_mqtt;
	}
}


int mosquitto_client_protocol_version(const struct mosquitto *client)
{
	switch(client->protocol){
		case mosq_p_mqtt31:
			return 3;
		case mosq_p_mqtt311:
			return 4;
		case mosq_p_mqtt5:
			return 5;
		default:
			return 0;
	}
}


int mosquitto_client_sub_count(const struct mosquitto *client)
{
	return client->sub_count;
}


const char *mosquitto_client_username(const struct mosquitto *context)
{
#ifdef WITH_BRIDGE
	if(context->bridge){
		return context->bridge->local_username;
	}else
#endif
	{
		return context->username;
	}
}


int mosquitto_plugin_publish(
		const char *topic,
		int payloadlen,
		const void *payload,
		int qos,
		bool retain,
		mosquitto_property *properties)
{
	struct mosquitto_message_v5 *msg;
	struct mosquitto_db *db;

	msg = mosquitto__malloc(sizeof(struct mosquitto_message_v5));
	if(msg == NULL) return MOSQ_ERR_NOMEM;
	
	msg->next = NULL;
	msg->prev = NULL;
	msg->topic = mosquitto__strdup(topic);
	if(msg->topic == NULL){
		mosquitto__free(msg);
		return MOSQ_ERR_NOMEM;
	}
	msg->payloadlen = payloadlen;
	msg->payload = mosquitto__calloc(1, payloadlen+1);
	if(msg->payload == NULL){
		mosquitto__free(msg->topic);
		mosquitto__free(msg);
		return MOSQ_ERR_NOMEM;
	}
	memcpy(msg->payload, payload, payloadlen);
	msg->qos = qos;
	msg->retain = retain;
	msg->properties = properties;

	db = mosquitto__get_db();

	DL_APPEND(db->plugin_msgs, msg);

	return MOSQ_ERR_SUCCESS;
}


int mosquitto_set_username(struct mosquitto *client, const char *username)
{
	char *u_dup;
	char *old;
	int rc;

	if(!client) return MOSQ_ERR_INVAL;

	if(username){
		u_dup = mosquitto__strdup(username);
		if(!u_dup) return MOSQ_ERR_NOMEM;
	}else{
		u_dup = NULL;
	}

	old = client->username;
	client->username = u_dup;

	rc = acl__find_acls(mosquitto__get_db(), client);
	if(rc){
		client->username = old;
		mosquitto__free(u_dup);
		return rc;
	}else{
		mosquitto__free(old);
		return MOSQ_ERR_SUCCESS;
	}
}

