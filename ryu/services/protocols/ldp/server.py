import logging
import traceback
import socket

from ryu.lib import hub
from socket import IPPROTO_TCP, TCP_NODELAY
from eventlet import semaphore

from ryu.lib.packet import ldp
from ryu.services.protocols.ldp.api.base import call

from ryu.services.protocols.ldp.core_manager import CORE_MANAGER
from ryu.services.protocols.ldp.signals.emit import LdpSignalBus
from ryu.services.protocols.ldp.rtconf.common import DEFAULT_HELLO_INTERVAL
from ryu.services.protocols.ldp.rtconf.common import DEFAULT_HOLD_TIME
from ryu.services.protocols.ldp.rtconf.common import DEFAULT_KEEP_ALIVE
from ryu.services.protocols.ldp.rtconf.common import DEFAULT_LDP_SERVER_PORT
from ryu.services.protocols.ldp.rtconf.common import ROUTER_ID 
from ryu.services.protocols.ldp.rtconf.common import IFACE
from ryu.services.protocols.ldp.rtconf.common import HELLO_INTERVAL 
from ryu.services.protocols.ldp.rtconf.common import KEEP_ALIVE 
from ryu.services.protocols.ldp.rtconf.common import LDP_SERVER_PORT 
from ryu.services.protocols.ldp.base import Activity
from ryu.services.protocols.ldp.protocol import Protocol
from ryu.services.protocols.ldp.constants import LDP_FSM_CONNECT
from ryu.services.protocols.ldp.constants import LDP_FSM_INIT_SENT

LOG = logging.getLogger('ldp_server.server')

LDP_MIN_MSG_LEN = 19
LDP_MAX_MSG_LEN = 4096

class LDPServer(object):
    def __init__(self,  router_id, iface,
        hello_interval = DEFAULT_HELLO_INTERVAL,
        hold_time = DEFAULT_HOLD_TIME,
        keep_alive = DEFAULT_KEEP_ALIVE,
        ldp_server_port = DEFAULT_LDP_SERVER_PORT,
        neighbor_state_change_handler = None):
        super(LDPServer, self).__init__()

        settings = {}
        settings[ROUTER_ID] = router_id
        settings[IFACE] = iface
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
    """Protocol that handles LDP messages.
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

    def _run(self, peer):
        # We know the peer we are connected to, we send open message.
        self._peer = peer
        self.connection_made()

        # We wait for peer to send messages.
        self._recv_loop()

    def _recv_loop(self):
        """Sits in tight loop collecting data received from peer and
        processing it.
        """
        required_len = LDP_MIN_MSG_LEN
        conn_lost_reason = "Connection lost as protocol is no longer active"
        try:
            while True:
                next_bytes = self._socket.recv(required_len)
                if len(next_bytes) == 0:
                    conn_lost_reason = 'Peer closed connection'
                    break
                self.data_received(next_bytes)
        except socket.error as err:
            conn_lost_reason = 'Connection to peer lost: %s.' % err
        except ldp.LdpExc as ex:
            conn_lost_reason = 'Connection to peer lost, reason: %s.' % ex
        except Exception as e:
            LOG.debug(traceback.format_exc())
            conn_lost_reason = str(e)
        finally:
            self.connection_lost(conn_lost_reason)

    def data_received(self, next_bytes):
        try:
            self._data_received(next_bytes)
        except ldp.LdpExc as exc:
            if exc.SEND_ERROR:
                self.send_notification(exc.CODE, exc.SUB_CODE)
            else:
                self._socket.close()
            raise exc

    def _data_received(self, next_bytes):
        """Maintains buffer of bytes received from peer and extracts bgp
        message from this buffer if enough data is received.

        Validates bgp message marker, length, type and data and constructs
        appropriate bgp message instance and calls handler.

        :Parameters:
            - `next_bytes`: next set of bytes received from peer.
        """
        # Append buffer with received bytes.
        self._recv_buff += next_bytes

        while True:
            # If current buffer size is less then minimum bgp message size, we
            # return as we do not have a complete bgp message to work with.
            if len(self._recv_buff) < BGP_MIN_MSG_LEN:
                return

            # Parse message header into elements.
            auth, length, ptype = BgpProtocol.parse_msg_header(
                self._recv_buff[:BGP_MIN_MSG_LEN])

            # Check if we have valid bgp message marker.
            # We should get default marker since we are not supporting any
            # authentication.
            if (auth != BgpProtocol.MESSAGE_MARKER):
                LOG.error('Invalid message marker received: %s' % auth)
                raise bgp.NotSync()

            # Check if we have valid bgp message length.
            check = lambda: length < BGP_MIN_MSG_LEN\
                or length > BGP_MAX_MSG_LEN

            # RFC says: The minimum length of the OPEN message is 29
            # octets (including the message header).
            check2 = lambda: ptype == BGP_MSG_OPEN\
                and length < BGPOpen._MIN_LEN

            # RFC says: A KEEPALIVE message consists of only the
            # message header and has a length of 19 octets.
            check3 = lambda: ptype == BGP_MSG_KEEPALIVE\
                and length != BGPKeepAlive._MIN_LEN

            # RFC says: The minimum length of the UPDATE message is 23
            # octets.
            check4 = lambda: ptype == BGP_MSG_UPDATE\
                and length < BGPUpdate._MIN_LEN

            if check() or check2() or check3() or check4():
                raise bgp.BadLen(ptype, length)

            # If we have partial message we wait for rest of the message.
            if len(self._recv_buff) < length:
                return
            msg, rest = BGPMessage.parser(self._recv_buff)
            self._recv_buff = rest

            # If we have a valid bgp message we call message handler.
            self._handle_msg(msg)

    def send_notification(self, code, subcode):
        """Utility to send notification message.

        Closes the socket after sending the message.
        :Parameters:
            - `socket`: (socket) - socket over which to send notification
             message.
            - `code`: (int) - BGP Notification code
            - `subcode`: (int) - BGP Notification sub-code

        RFC ref: http://tools.ietf.org/html/rfc4486
        http://www.iana.org/assignments/bgp-parameters/bgp-parameters.xhtml
        """
        notification = BGPNotification(code, subcode)
        reason = notification.reason
        self._send_with_lock(notification)
        self._signal_bus.bgp_error(self._peer, code, subcode, reason)
        if len(self._localname):
            LOG.error('Sent notification to %r >> %s' % (self._localname,
                                                         notification))
        self._socket.close()

    def connection_made(self):
        """Connection to peer handler.

        We send bgp open message to peer and intialize related attributes.
        """
        assert self._peer.state == LDP_FSM_CONNECT
        # We have a connection with peer we send open message.
        open_msg = self._peer.create_init_msg()
        self._holdtime = open_msg.hold_time
        self._peer.state = LDP_FSM_INIT_SENT
        if not self.is_reactive:
            self._peer.state.bgp_state = self.state
        self.sent_open_msg = open_msg
        self.send(open_msg)
        self._peer.connection_made()

    def connection_lost(self, reason):
        """Stops all timers and notifies peer that connection is lost.
        """

