from ryu.lib import hub
from socket import IPPROTO_TCP, TCP_NODELAY
from eventlet import semaphore

from ryu.services.protocols.ldp.api.base import call
from ryu.services.protocols.ldp.core_manager import CORE_MANAGER
from ryu.services.protocols.ldp.signals.emit import LdpSignalBus
from ryu.services.protocols.ldp.rtconf.common import DEFAULT_HELLO_INTERVAL
from ryu.services.protocols.ldp.rtconf.common import DEFAULT_HOLD_TIME
from ryu.services.protocols.ldp.rtconf.common import DEFAULT_KEEP_ALIVE
from ryu.services.protocols.ldp.rtconf.common import DEFAULT_LDP_SERVER_PORT
from ryu.services.protocols.ldp.rtconf.common import ROUTER_ID 
from ryu.services.protocols.ldp.rtconf.common import ENABLE_INTS 
from ryu.services.protocols.ldp.rtconf.common import HELLO_INTERVAL 
from ryu.services.protocols.ldp.rtconf.common import KEEP_ALIVE 
from ryu.services.protocols.ldp.rtconf.common import LDP_SERVER_PORT 
from ryu.services.protocols.bgp.base import Activity
from ryu.services.protocols.bgp.protocol import Protocol

class LDPServer(object):
    def __init__(self,  router_id, enable_ints,
        hello_interval = DEFAULT_HELLO_INTERVAL,
        hold_time = DEFAULT_HOLD_TIME,
        keep_alive = DEFAULT_KEEP_ALIVE,
        ldp_server_port = DEFAULT_LDP_SERVER_PORT,
        neighbor_state_change_handler = None):
        super(LDPServer, self).__init__()

        settings = {}
        settings[ROUTER_ID] = router_id
        settings[ENABLE_INTS] = enable_ints
        settings[HELLO_INTERVAL] = hello_interval
        settings[KEEP_ALIVE] = keep_alive
        settings[LDP_SERVER_PORT] = ldp_server_port
        self._core_start(settings)
        self._init_signal_listeners()

    def _core_start(self, settings):
        waiter = hub.Event()
        call('core.start', waiter=waiter, **settings)
        waiter.wait()

    def _init_signal_listeners(self):
        """
        CORE_MANAGER.get_core_service()._signal_bus.register_listener(
            LdpSignalBus.LDP_NEIGHBOR_STATE_CHANGE,
            lambda _, info:
            self._notify_ldp_neighbor_state_change()
        )
        """
        pass

class LdpProtocol(Protocol, Activity):
    """Protocol that handles BGP messages.
    """

    def __init__(self, socket, signal_bus, is_reactive_conn=False):
        # Validate input.
        if socket is None:
            raise ValueError('Invalid arguments passed.')
        self._remotename = self.get_remotename(socket)
        self._localname = self.get_localname(socket)
        activity_name = ('LdpProtocol %s, %s, %s' % (is_reactive_conn,
                                                     self._remotename,
                                                     self._localname))
        Activity.__init__(self, name=activity_name)
        # Intialize instance variables.
        self._socket = socket
        self._socket.setsockopt(IPPROTO_TCP, TCP_NODELAY, 1)
        self._sendlock = semaphore.Semaphore()
        self._signal_bus = signal_bus
        self._holdtime = None
        self._keepalive = None
        self._is_bound = False

    @property
    def is_reactive(self):
        return self._is_reactive

    @property
    def holdtime(self):
        return self._holdtime

    @property
    def keepalive(self):
        return self._keepalive

    def is_local_router_id_greater(self):
        """Compares *True* if local router id is greater when compared to peer
        bgp id.

        Should only be called after protocol has reached OpenConfirm state.
        """

    def connection_made(self):
        """Connection to peer handler.

        We send bgp open message to peer and intialize related attributes.
        """

    def connection_lost(self, reason):
        """Stops all timers and notifies peer that connection is lost.
        """



