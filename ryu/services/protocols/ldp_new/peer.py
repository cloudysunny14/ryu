import socket
import logging
import traceback
import struct
import abc
import six

from ryu.services.protocols.ldp import event as ldp_event

from ryu.lib.packet import ldp
from ryu.lib.packet.ldp import LDPMessage
LOG = logging.getLogger('ldp.Peer')

LDP_MIN_MSG_LEN = 10

@six.add_metaclass(abc.ABCMeta)
class LDPState(object):
    def __init__(self, peer):
        super(LDPState, self).__init__()
        self.peer = peer

    @abc.abstractmethod
    def action(self):
        pass

    @abc.abstractmethod
    def then(self):
        pass

    @abc.abstractmethod
    def state(self):
        pass

class LDPStateNone(LDPState):
    def action(self):
        pass

    def then(self, event):
        pass

    def state(self):
        pass

class LDPActiveStatePresent(LDPState):
    def action(self):
        self.peer.send_init()

    def then(self, event):
        return ldp_event.LDP_STATE_INITIAL

    def state(self):
        return ldp_event.LDP_STATE_PRESENT

class LDPActiveStateInitial(LDPState):
    def action(self):
        self.peer.send_keep_alive()
        self.peer.start_keep_alive_timer()

    def then(self, event):
        return ldp_event.LDP_STATE_OPEN

    def state(self):
        return ldp_event.LDP_STATE_INITIAL

class LDPActiveStateOpen(LDPState):
    def action(self):
        self.peer.reset_keep_alive()

    def then(self, event):
        return ldp_event.LDP_STATE_OPEN

    def state(self):
        return ldp_event.LDP_STATE_OPEN

class LDPPassiveStatePresent(LDPState):
    def action(self):
        pass

    def then(self, event):
        self.peer.send_init()
        return ldp_event.LDP_STATE_INITIAL

    def state(self):
        return ldp_event.LDP_STATE_PRESENT

class LDPPassiveStateInitial(LDPState):
    def action(self):
        pass

    def then(self, event):
        self.peer.send_keepalive()
        return ldp_event.LDP_STATE_OPEN

    def state(self):
        return ldp_event.LDP_STATE_INITIAL

class LDPActiveStateOpen(LDPState):
    def action(self):
        self.peer.reset_keep_alive()

    def then(self, event):
        return ldp_event.LDP_STATE_OPEN

    def state(self):
        return ldp_event.LDP_STATE_OPEN

class Peer(object):
    _ACTIVE_STATE_MAP = {
        ldp_event.LDP_STATE_PRESENT: LDPActiveStatePresent,
        ldp_event.LDP_STATE_INITIAL: LDPActiveStateInitial,
        ldp_event.LDP_STATE_OPEN: LDPActiveStateOpen
    }
    _PASSIVE_STATE_MAP = {
        ldp_event.LDP_STATE_PRESENT: LDPPassiveStatePresent,
        ldp_event.LDP_STATE_INITAL: LDPPassiveStateInitial,
        ldp_event.LDP_STATE_OPEN: LDPPassiveStateOpen
    }
    def __init__(self, app, router_id, trans_addr):
        self._app = app
        self.router_id = router_id
        self.trans_addr = trans_addr
        self._socket = None
        self._recv_buff = ''
        self._state = ldp_event.LDP_STATE_DOWN
        self._state_map = {}
        self._state_instance = None

    def conn_handle(self, socket, is_active):
        self._socket = socket
        self._recv_loop()
        if is_active:
            self._state_map = self._ACTIVE_STATE_MAP
        else:
            self._state_map = self._PASSIVE_STATE_MAP
        self.state_change(ldp_event.LDP_STATE_PRESENT)

    def state_change(self, new_state):
        if self.state == new_state:
            return
        old_state = self.state
        self.state = new_state
        self.state_impl = self._state_map[new_state](self)
        state_changed = ldp_event.EventLDPStateChanged(
            self.name, self.monitor_name, self.interface, self.config,
            old_state, new_state)
        self.send_event_to_observers(state_changed)
        self.state_impl.action()

    def _recv_loop(self):
        required_len = LDP_MIN_MSG_LEN
        conn_lost_reason = "Connection lost as protocol is no longer active"
        try:
            while True:
                next_bytes = self._socket.recv(required_len)
                if len(next_bytes) == 0:
                    print 'peer closed'
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
        # Append buffer with received bytes.
        self._recv_buff += next_bytes

        while True:
            if len(self._recv_buff) < LDP_MIN_MSG_LEN:
                return

            version, pdu_len, router_id, label_space_id \
                = Peer.parse_msg_header(
                    self._recv_buff[:LDP_MIN_MSG_LEN])
            # RFC
            buf_len = len(self._recv_buff) - 4
            if buf_len < pdu_len:
                return
            msg, rest = LDPMessage.parser(self._recv_buff)
            self._recv_buff = rest
            # If we have a valid bgp message we call message handler.
            self._handle_msg(msg)

    def _handle_msg(self, msg):
        msg_type = msg.type
        # state change by msg type
        # if initial recv, call then and current state change call
        if msg_type == INITIAL:
            if self.state != ldp_event.PRESENT:
                raise()
            new_state = self.state_impl.then()
            self.change_state(new_state)


    @staticmethod
    def parse_msg_header(buff):
        return struct.unpack('!HH4sH', buff)


    def connection_lost(self, reason):
        """Stops all timers and notifies peer that connection is lost.
        """

