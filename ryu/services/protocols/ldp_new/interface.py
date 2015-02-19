from ryu.controller import event
from ryu.controller import handler
from ryu.lib import hub
from ryu.lib.packet.ldp import LDPHello
from ryu.lib.packet.ldp import CommonHelloParameter
from ryu.lib.packet.ldp import IPv4TransportAddress
from ryu.services.protocols.ldp.event import EventHelloReceived

class Timer(object):
    def __init__(self, handler_):
        assert callable(handler_)

        super(Timer, self).__init__()
        self._handler = handler_
        self._event = hub.Event()
        self._thread = None

    def start(self, interval):
        """interval is in seconds"""
        if self._thread:
            self.cancel()
        self._event.clear()
        self._thread = hub.spawn(self._timer, interval)

    def cancel(self):
        if self._thread is None:
            return
        self._event.set()
        hub.joinall([self._thread])
        self._thread = None

    def is_running(self):
        return self._thread is not None

    def _timer(self, interval):
        # Avoid cancellation during execution of self._callable()
        cancel = self._event.wait(interval)
        if cancel:
            return

        self._handler()

class HelloSendTimer(Timer):
    def __init__(self, config, server, hello_msg):
        super(HelloSendTimer, self).__init__(self._timeout)
        self._hello_msg = hello_msg
        self._server = server
        self._config = config

    def _timeout(self):
        self._server.sendto(self._hello_msg.serialize(),
                (ALL_ROUTERS, LDP_DISCOVERY_PORT))

#TODO: separete common static value
ALL_ROUTERS = '224.0.0.2'
LDP_DISCOVERY_PORT = 646

class LDPInterface(object):
    def __init__(self, app, discovery_server, config):
        self.discovery_server =  discovery_server
        self.app = app
        self.state = None
        self.config = config
        hello_msg = self._generate_hello_msg(config)
        self._hello_timer = HelloSendTimer(config, self.discovery_server, hello_msg)

    def _generate_hello_msg(self, config):
        router_id = config.router_id
        hold_time = config.hold_time
        tlvs = [CommonHelloParameter(hold_time=hold_time,
                t_bit=0, r_bit=0),
                IPv4TransportAddress(addr=router_id)]
        msg = LDPHello(router_id=router_id, msg_id=0,
                tlvs=tlvs)
        return msg

    def start(self):
        self.discovery_server.start(self._recv_handler)
        self._hello_timer.start(self.config.hold_time/3)

    def _recv_handler(self, packet, addr):
        ev = EventHelloReceived(self, packet)
        self.app.send_event(self.app.name, ev)

    def _send_hello(self):
        self.discovery_servery.sendto()
