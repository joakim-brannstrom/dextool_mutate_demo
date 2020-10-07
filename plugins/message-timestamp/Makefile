all : mosquitto_timestamp.so

mosquitto_timestamp.so : mosquitto_timestamp.c
	$(CC) -I../../include -fPIC -shared $< -o $@
