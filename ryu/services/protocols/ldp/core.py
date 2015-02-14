import socket
from eventlet import semaphore
from ryu.services.protocols.ldp.base import Activity
from ryu.services.protocols.ldp.protocol import Factory
from ryu.services.protocols.ldp.signals.emit import LdpSignalBus 
from ryu.services.protocols.ldp import core_managers
from ryu.services.protocols.ldp.server import LdpProtocol
from ryu.services.protocols.ldp.utils import ldp as ldp_utils
from ryu.lib.packet import ldp
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
        self._router_id = common_conf.router_id
        self._sendlock = semaphore.Semaphore()
        self._hello_msg = {}
        self._hello = None
        self._disc_socket = None
        self._hold_time = common_conf.hold_time
        self._ldp_server_port = common_conf.ldp_server_port
        self.peers = {}

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
        iface = self._common_config.iface
        #enable_ints = self._common_config.enable_ints
        waiter = kwargs.pop('waiter')
        waiter.set()
        disc_thread, disc_socket = \
            self._discovery_socket(recv_addr, self.recv_hello, iface)
        self._disc_socket = disc_socket.values()[0]
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
        self._hello.start(hello_interval, now=True)
        # TODO: Setup the expire timer
        #self._expiry = self._create_timer('Holdtime Timer', self._expired)
        #self._expiry.start(hold_time, now=False)

    def _send_with_lock(self, msg):
        self._sendlock.acquire()
        try:
            self._disc_socket.sendto(msg.serialize(),
                (ALL_ROUTERS, self._ldp_server_port))
            #self._hello_sock.sendto(msg.serialize(),
            #k    (ALL_ROUTERS, self._ldp_server_port))
        except socket.error:
            self.send_failed('failed to write to socket')
        finally:
            self._sendlock.release()

    def start_protocol(self, socket):
        assert socket
        peer_addr, peer_port = self.get_remotename(socket)
        peer = self.peers.get(peer_addr, None)
        if peer is None:
            peer = Peer(self._common_config, self.signal_bus, peer_addr)
            self.peers[peer_addr] = peer
        ldp_proto = self.build_protocol(socket)
        bind_ip, bind_port = self.get_localname(socket)
        peer._host_bind_ip = bind_ip
        peer._host_bind_port = bind_port
        self._spawn_activity(ldp_proto, peer)

    def build_protocol(self, socket):
        ldp_protocol = self.protocol(
            socket,
            self._signal_bus
        )
        return ldp_protocol 

    def recv_hello(self, hello):
        assert hello
        msg, rest = LDPMessage.parser(hello)
        peer_router_id = msg.header.router_id
        if ldp_utils.from_inet_ptoi(peer_router_id) < \
              ldp_utils.from_inet_ptoi(self._router_id):
            trans_addr = LDPMessage.retrive_tlv(ldp.LDP_TLV_IPV4_TRANSPORT_ADDRESS, msg)
            if trans_addr is not None:
                peer_addr = (trans_addr.addr, self._ldp_server_port)
                bind_addr = (self._router_id, 0)
                self._connect_tcp(peer_addr=peer_addr,
                    conn_handler=self.start_protocol,
                    bind_address=bind_addr)

    def send_hello(self):
        hold_time = self._common_config.hold_time
        msg = self._hello_msg.get(hold_time, None)
        if msg is None:
            tlvs = [CommonHelloParameter(hold_time=hold_time,
                t_bit=0, r_bit=0),
                IPv4TransportAddress(addr=self._router_id)]
            msg = LDPHello(router_id=self._router_id, msg_id=0,
                tlvs=tlvs)
            self._hello_msg[hold_time] = msg
        self._send_with_lock(msg)

