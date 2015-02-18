import socket
from eventlet import semaphore

from ryu.lib import hub
from ryu.base import app_manager
from ryu.controller import handler
from ryu.services.protocols.ldp import event as ldp_event
from ryu.services.protocols.ldp.interface import LDPInterface 

class LDPManager(app_manager.RyuApp):
    @staticmethod
    def _instance_name(router_id):
        return 'LDP-%s' % (router_id)

    def __init__(self, *args, **kwargs):
        super(LDPManager, self).__init__(*args, **kwargs)
        self._args = args
        self._kwargs = kwargs
        self.name = ldp_event.LDP_MANAGER_NAME
        #self.shutdown = hub.Queue()
        self.interfaces = []
        self.peers = {} #key interface
        #self.session_thread = hub.spawn(self._session_thread)

    def start(self):
        print 'start'
        t = hub.spawn(self._shutdown_loop)
        super(LDPManager, self).start()
        return t

    @handler.set_ev_cls(ldp_event.EventLDPConfigRequest)
    def config_request_handler(self, ev):
        print 'config request'
        config = ev.config
        iface_conf = ev.interface
        interface = self._new_interface(iface_conf, config)
        self.interfaces.append(interface)
        #TODO: delay timer
        interface.start()
        rep = ldp_event.EventLDPConfigReply(self._instance_name(config.router_id), interface, config)
        self.reply_to_request(ev, rep)

    def _new_interface(self, iface_conf, conf):
        server = DiscoverServer(iface_conf.ip_address)
        interface = LDPInterface(server, conf)
        return interface

    def _shutdown_loop(self):
        app_mgr = app_manager.AppManager.get_instance()
        while self.is_active or not self.shutdown.empty():
            instance = self.shutdown.get()
            app_mgr.uninstantiate(instance.name)
            app_mgr.uninstantiate(instance.monitor_name)
            del self._instances[instance.name]

    def start_discover(self):
        pass

    def start_listen(self):
        pass

ALL_ROUTER = '224.0.0.2'
LDP_DISCOVERY_PORT = 646

class DiscoverServer(object):

    def __init__(self, iface):
        self.write_lock = semaphore.Semaphore()
        sock = socket.socket(socket.AF_INET, 
            socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET,
             socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_IP,
            socket.IP_MULTICAST_LOOP, 0)
        if hasattr(socket, "SO_REUSEPORT"):
            sock.setsockopt(socket.SOL_SOCKET,
                socket.SO_REUSEPORT, 1)
        sock.setsockopt(socket.IPPROTO_IP,
            socket.IP_ADD_MEMBERSHIP,
            socket.inet_aton(ALL_ROUTER) + socket.inet_aton(iface))
        sock.setsockopt(socket.SOL_IP,
             socket.IP_MULTICAST_IF,
             socket.inet_aton(iface))
        sock.bind((ALL_ROUTER, self.LDP_DISCOVERY_PORT))
        self.socket = sock

    def start(self, handler):
        hub.spawn(self._recv_loop, handler)

    def sendto(self, *args):
        self.write_lock.acquire()
        try:
            self.socket.sendto(*args)
        finally:
            self.write_lock.release()

    def _recv_loop(self, handler):
        while True:
            data, addr = self.socket.recvfrom(8192)
            hub.spawn(handler, data, addr)

class LDPStatistics(object):
    """"""
