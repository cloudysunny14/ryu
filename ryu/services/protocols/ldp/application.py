import eventlet

# LDPServer needs sockets patched
eventlet.monkey_patch()

# initialize a log handler
# this is not strictly necessary but useful if you get messages like:
#    No handlers could be found for logger "ryu.lib.hub"
import logging
import sys
log = logging.getLogger()
log.addHandler(logging.StreamHandler(sys.stderr))

from ryu.services.protocols.ldp.server import LDPServer 

def neighbor_state_change(state):
    #
    return None

if __name__ == "__main__":
    server = LDPServer(router_id='1.1.1.1', 
                       hello_interval = 5,
                       hold_time = 15,
                       keep_alive = 180,
                       ldp_server_port = 646,
                       enable_ints = ['10.0.2.15'],
                       neighbor_state_change_handler = neighbor_state_change
                       )
    #in_prefix = '10.0.0.0/8'
    #in_label = 55
    #out_prefix = ''
    #server.static_bind_input_label(in_prefix, in_label)
    #server.static_bind_output_label(out_prefix, out_label)
    #server.start()
    eventlet.sleep(5)

    while True:
        eventlet.sleep(5)
