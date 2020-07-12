/*
Copyright (c) 2009-2020 Roger Light <roger@atchoo.org>

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

#ifndef MOSQUITTO_BROKER_H
#define MOSQUITTO_BROKER_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>

struct mosquitto;
typedef struct mqtt5__property mosquitto_property;

enum mosquitto_protocol {
	mp_mqtt,
	mp_mqttsn,
	mp_websockets
};

/* =========================================================================
 *
 * Utility Functions
 *
 * Use these functions from within your plugin.
 *
 * There are also very useful functions in libmosquitto.
 *
 * ========================================================================= */


/*
 * Function: mosquitto_log_printf
 *
 * Write a log message using the broker configured logging.
 *
 * Parameters:
 * 	level -    Log message priority. Can currently be one of:
 *
 *             MOSQ_LOG_INFO
 *             MOSQ_LOG_NOTICE
 *             MOSQ_LOG_WARNING
 *             MOSQ_LOG_ERR
 *             MOSQ_LOG_DEBUG
 *             MOSQ_LOG_SUBSCRIBE (not recommended for use by plugins)
 *             MOSQ_LOG_UNSUBSCRIBE (not recommended for use by plugins)
 *
 *             These values are defined in mosquitto.h.
 *
 *	fmt, ... - printf style format and arguments.
 */
void mosquitto_log_printf(int level, const char *fmt, ...);


/* =========================================================================
 *
 * Client Functions
 *
 * Use these functions to access client information.
 *
 * ========================================================================= */

/*
 * Function: mosquitto_client_address
 *
 * Retrieve the IP address of the client as a string.
 */
const char *mosquitto_client_address(const struct mosquitto *client);


/*
 * Function: mosquitto_client_clean_session
 *
 * Retrieve the clean session flag value for a client.
 */
bool mosquitto_client_clean_session(const struct mosquitto *client);


/*
 * Function: mosquitto_client_id
 *
 * Retrieve the client id associated with a client.
 */
const char *mosquitto_client_id(const struct mosquitto *client);


/*
 * Function: mosquitto_client_keepalive
 *
 * Retrieve the keepalive value for a client.
 */
int mosquitto_client_keepalive(const struct mosquitto *client);


/*
 * Function: mosquitto_client_certificate
 *
 * If TLS support is enabled, return the certificate provided by a client as an
 * X509 pointer from openssl. If the client did not provide a certificate, then
 * NULL will be returned. This function will only ever return a non-NULL value
 * if the `require_certificate` option is set to true.
 *
 * If TLS is not supported, this function will always return NULL.
 */
void *mosquitto_client_certificate(const struct mosquitto *client);


/*
 * Function: mosquitto_client_protocol
 *
 * Retrieve the protocol with which the client has connected. Can be one of:
 *
 * mp_mqtt (MQTT over TCP)
 * mp_mqttsn (MQTT-SN)
 * mp_websockets (MQTT over Websockets)
 */
int mosquitto_client_protocol(const struct mosquitto *client);


/*
 * Function: mosquitto_client_protocol_version
 *
 * Retrieve the MQTT protocol version with which the client has connected. Can be one of:
 *
 * 3 - for MQTT v3 / v3.1
 * 4 - for MQTT v3.1.1
 * 5 - for MQTT v5
 */
int mosquitto_client_protocol_version(const struct mosquitto *client);


/*
 * Function: mosquitto_client_sub_count
 *
 * Retrieve the number of subscriptions that have been made by a client.
 */
int mosquitto_client_sub_count(const struct mosquitto *client);


/*
 * Function: mosquitto_client_username
 *
 * Retrieve the username associated with a client.
 */
const char *mosquitto_client_username(const struct mosquitto *client);


/* Function: mosquitto_set_username
 *
 * Set the username for a client.
 *
 * This removes and replaces the current username for a client and hence
 * updates its access.
 *
 * username can be NULL, in which case the client will become anonymous, but
 * must not be zero length.
 *
 * In the case of error, the client will be left with its original username.
 *
 * Returns:
 *   MOSQ_ERR_SUCCESS - on success
 *   MOSQ_ERR_INVAL - if client is NULL, or if username is zero length
 *   MOSQ_ERR_NOMEM - on out of memory
 */
int mosquitto_set_username(struct mosquitto *client, const char *username);


/* Function: mosquitto_plugin_publish
 *
 * Publish a message from within a plugin.
 *
 * This function allows a plugin to publish a message. Messages published in
 * this way are treated as coming from the broker and so will not be passed to
 * `mosquitto_auth_acl_check(, MOSQ_ACL_WRITE, , )` for checking. Read access
 * will be enforced as normal for individual clients when they are due to
 * receive the message.
 */
int mosquitto_plugin_publish(
		const char *topic,
		int payloadlen,
		const void *payload,
		int qos,
		bool retain,
		mosquitto_property *properties);

#ifdef __cplusplus
}
#endif

#endif
