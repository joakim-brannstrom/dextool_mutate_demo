#!/bin/ash
set -e

# Set permissions
user="$(id -u)"
if [ "$user" = '0' ]; then
	[ -d "/mosquitto" ] && chown -R mosquitto:mosquitto /mosquitto || true
fi

if [ "$NO_AUTHENTICATION" = "1" ] && [ "$*" = '/usr/sbin/mosquitto -c /mosquitto/config/mosquitto.conf' ]; then
	# The user wants to run Mosquitto with no authentication, but without
	# providing a configuration file. Use the pre-provided file for this.
	exec /usr/sbin/mosquitto -c /mosquitto-no-auth.conf
else
	# Execute whatever command is requested
	exec "$@"
fi
