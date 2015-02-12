import socket
from ryu.services.protocols.ldp.base import Activity
from ryu.services.protocols.ldp.protocol import Factory
from ryu.services.protocols.ldp.signals.emit import LdpSignalBus 
from ryu.services.protocols.ldp import core_managers
from ryu.services.protocols.ldp.server import LdpProtocol

# Interface IP address on which to run bgp server. Core service listens on all
# interfaces of the host on port 179 - standard bgp port.
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
        recv_addr = (ALL_ROUTERS, self._common_config.ldp_server_port)
        enable_ints = self._common_config.enable_ints
        waiter = kwargs.pop('waiter')
        waiter.set()


        server_thread, sockets = self._discovery_socket(enable_ints, recv_addr,
                                                  self.recv_hello)
        self.receive_sockets = sockets
        server_thread.wait()


    def build_protocol(self, socket):
        assert socket
        # Check if its a reactive connection or pro-active connection
        _, remote_port = self.get_remotename(socket)
        remote_port = int(remote_port)

        ldp_protocol = self.protocol(
            socket,
            self._signal_bus
        )
        return ldp_protocol 

    def recv_hello(self, hello):
        """Handler of new connection requests on bgp server port.

        Checks if new connection request is valid and starts new instance of
        protocol.
        """
        assert hello 


