import socket
from eventlet import semaphore
from ryu.services.protocols.ldp.base import Activity
from ryu.services.protocols.ldp.protocol import Factory
from ryu.services.protocols.ldp.signals.emit import LdpSignalBus 
from ryu.services.protocols.ldp import core_managers
from ryu.services.protocols.ldp.server import LdpProtocol
from ryu.lib.packet.ldp import LDPMessage
from ryu.lib.packet.ldp import LDPHello
from ryu.lib.packet.ldp import CommonHelloParameter
from ryu.lib.packet.ldp import IPv4TransportAddress


# Interface IP address on which to run bgp server. Core service listens on all
# interfaces of the host on port 179 - standard bgp port.
CORE_IP = '::'
ALL_ROUTERS = '224.0.0.2'

class CoreService(Factory, Activity):

    protocol = LdpProtocol

    def __init__(self, common_conf):
        self._common_config = common_conf
        Activity.__init__(self, name='core_service')
        self._signal_bus = LdpSignalBus()
        self._init_signal_listeners()
        self._conf_manager = core_managers.ConfigurationManager(
            self, common_conf
        )
        self._sendlock = semaphore.Semaphore()
        self._hello_msg = {}
        self._hello = None
        self._hello_sock = socket.socket(socket.AF_INET,
            socket.SOCK_DGRAM,
            socket.IPPROTO_UDP)
        self._hello_sock.setsockopt(socket.IPPROTO_IP,
            socket.IP_MULTICAST_TTL, 
            socket.IP_DEFAULT_MULTICAST_TTL)
        self._hello_sock.setsockopt(socket.SOL_IP, 
            socket.IP_MULTICAST_LOOP, 1)
        self._hello_sock.setsockopt
        self._hold_time = common_conf.hold_time
        self._ldp_server_port = common_conf.ldp_server_port

    def _init_signal_listeners(self):
        # TODO:Implemente ldp signal listener
        """
        self._signal_bus.register_listener(
            LdpSignalBus.BGP_DEST_CHANGED,
            lambda _, dest: self.enqueue_for_bgp_processing(dest)
        )
        self._signal_bus.register_listener(
            LdpSignalBus.BGP_VRF_REMOVED,
            lambda _, route_dist: self.on_vrf_removed(route_dist)
        )
        self._signal_bus.register_listener(
            LdpSignalBus.BGP_VRF_ADDED,
            lambda _, vrf_conf: self.on_vrf_added(vrf_conf)
        )
        self._signal_bus.register_listener(
            LdpSignalBus.BGP_VRF_STATS_CONFIG_CHANGED,
            lambda _, vrf_conf: self.on_stats_config_change(vrf_conf)
        )
        """

    @property
    def signal_bus(self):
        return self._signal_bus

    def _run(self, *args, **kwargs):
        recv_addr = (ALL_ROUTERS, self._ldp_server_port)
        #enable_ints = self._common_config.enable_ints
        waiter = kwargs.pop('waiter')
        waiter.set()

        disc_thread, disc_sockets = self._discovery_socket(recv_addr, self.recv_hello)

        self.disc_sockets = disc_sockets
        sess_addr = (CORE_IP, self._ldp_server_port)
        sess_thread, sess_sockets = \
            self._listen_tcp(sess_addr,
            self.start_protocol)
        self.sess_sockets = sess_sockets
        self._start_timers(self._hold_time)
        disc_thread.wait()
        sess_thread.wait()

    def _start_timers(self, hold_time):
        
        hello_interval = hold_time / 3
        self._hello = self._create_timer('Hello Timer', self.send_hello)
        self._hello.start(hello_interval, now=False)
        # TODO: Setup the expire timer
        #self._expiry = self._create_timer('Holdtime Timer', self._expired)
        #self._expiry.start(hold_time, now=False)

    def _send_with_lock(self, msg):
        self._sendlock.acquire()
        try:
            self._hello_sock.sendto(msg.serialize(),
                (ALL_ROUTERS, self._ldp_server_port))
        except socket.error:
            self.send_failed('failed to write to socket')
        finally:
            self._sendlock.release()

    def start_protocol(self, socket):
        ldp_proto = self.build_protocol(socket)
        self._spawn_activity(ldp_proto, socket)

    def build_protocol(self, enable_int):
        ldp_protocol = self.protocol(
            enable_int,
            self._signal_bus
        )
        return ldp_protocol 

    def recv_hello(self, hello):
        assert hello
        msg, rest = LDPMessage.parser(hello)
        print msg

    def send_hello(self):
        hold_time = self._common_config.hold_time
        msg = self._hello_msg.get(hold_time, None)
        if msg is None:
            router_id = self._common_config.router_id
            tlvs = [CommonHelloParameter(hold_time=hold_time,
                t_bit=0, r_bit=0),
                IPv4TransportAddress(addr=router_id)]
            msg = LDPHello(router_id=router_id, msg_id=0,
                tlvs=tlvs)
            self._hello_msg[hold_time] = msg
        self._send_with_lock(msg)


