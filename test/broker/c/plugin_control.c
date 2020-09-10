#include <stdio.h>
#include <string.h>
#include <mqtt_protocol.h>
#include <mosquitto.h>
#include <mosquitto_broker.h>
#include <mosquitto_plugin.h>

int control_callback(void *data, struct mosquitto *context, const char *topic, int payloadlen, const void *payload)
{
	mosquitto_broker_publish_copy(NULL, topic, payloadlen, payload, 0, 0, NULL);

	return 0;
}


int mosquitto_auth_plugin_version(void)
{
	return MOSQ_AUTH_PLUGIN_VERSION;
}

int mosquitto_auth_plugin_init(void **user_data, struct mosquitto_opt *auth_opts, int auth_opt_count)
{
	int i;
	char buf[100];

	for(i=0; i<100; i++){
		snprintf(buf, sizeof(buf), "$CONTROL/user-management/v%d", i);
		mosquitto_control_topic_register("$CONTROL/user-management/v1", control_callback, NULL);
	}
	return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_plugin_cleanup(void *user_data, struct mosquitto_opt *auth_opts, int auth_opt_count)
{
	int i;
	char buf[100];

	for(i=0; i<100; i++){
		snprintf(buf, sizeof(buf), "$CONTROL/user-management/v%d", i);
		mosquitto_control_topic_unregister("$CONTROL/user-management/v1");
	}
	return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_security_init(void *user_data, struct mosquitto_opt *auth_opts, int auth_opt_count, bool reload)
{
	return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_security_cleanup(void *user_data, struct mosquitto_opt *auth_opts, int auth_opt_count, bool reload)
{
	return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_acl_check(void *user_data, int access, struct mosquitto *client, const struct mosquitto_acl_msg *msg)
{
	return MOSQ_ERR_SUCCESS;
}
