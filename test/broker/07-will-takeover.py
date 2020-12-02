#!/usr/bin/env python3

# Test whether a will is published when a client takes over an existing session that has a will set.
#
from mosq_test_helper import *


def do_test(proto_ver, clean_session):
    rc = 1
    keepalive = 60

    mid = 1
    connect1_packet = mosq_test.gen_connect("will-helper", keepalive=keepalive, proto_ver=proto_ver)
    connack1_packet = mosq_test.gen_connack(rc=0, proto_ver=proto_ver)

    connect2_packet = mosq_test.gen_connect("will-test", keepalive=keepalive, proto_ver=proto_ver, will_topic="will/test", will_payload=b"LWT", clean_session=clean_session)
    connack2a_packet = mosq_test.gen_connack(rc=0, proto_ver=proto_ver)
    if clean_session == False and proto_ver == 4:
        connack2b_packet = mosq_test.gen_connack(rc=0, flags=1, proto_ver=proto_ver)
    else:
        connack2b_packet = mosq_test.gen_connack(rc=0, proto_ver=proto_ver)

    subscribe_packet = mosq_test.gen_subscribe(mid, "will/test", 0, proto_ver=proto_ver)
    suback_packet = mosq_test.gen_suback(mid, 0, proto_ver=proto_ver)

    publish_packet = mosq_test.gen_publish(topic="will/test", qos=0, payload="Client ready", proto_ver=proto_ver)

    port = mosq_test.get_port()
    broker = mosq_test.start_broker(filename=os.path.basename(__file__), port=port)

    try:
        # Connect helper to look for will being published
        sock1 = mosq_test.do_client_connect(connect1_packet, connack1_packet, timeout=5, port=port)
        mosq_test.do_send_receive(sock1, subscribe_packet, suback_packet, "suback")

        # Connect client with will
        sock2 = mosq_test.do_client_connect(connect2_packet, connack2a_packet, timeout=5, port=port)

        # Send a "ready" message
        sock2.send(publish_packet)
        mosq_test.expect_packet(sock1, "publish 1", publish_packet)

        # Connect client with will again as a separate connection, this should
        # take over from the previous one but not trigger a Will.
        sock3 = mosq_test.do_client_connect(connect2_packet, connack2b_packet, timeout=5, port=port)
        sock2.close()

        # Send the "ready" message again
        sock3.send(publish_packet)
        mosq_test.expect_packet(sock1, "publish 2", publish_packet)
        # If the helper has received a will message, then the ping test will fail
        mosq_test.do_ping(sock1)
        rc = 0

        sock1.close()
        sock2.close()
        sock3.close()
    except mosq_test.TestError:
        pass
    finally:
        broker.terminate()
        broker.wait()
        (stdo, stde) = broker.communicate()
        if rc:
            print(stde.decode('utf-8'))
            print("proto_ver=%d clean_session=%d" % (proto_ver, clean_session))
            exit(rc)


do_test(proto_ver=4, clean_session=True)
do_test(proto_ver=4, clean_session=False)
do_test(proto_ver=5, clean_session=True)
do_test(proto_ver=5, clean_session=False)
