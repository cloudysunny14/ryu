from collections import namedtuple
import logging
import socket
import time

from ryu.services.protocols.ldp.signals.emit import LdpSignalBus
from ryu.services.protocols.ldp import constants
from ryu.services.protocols.ldp.base import Activity
from ryu.services.protocols.ldp.base import Sink
from ryu.services.protocols.ldp.base import Source
from ryu.services.protocols.ldp.utils import stats
from ryu.services.protocols.bgp.utils.evtlet import EventletIOFactory

#TODO:RPC Server
#from ryu.services.protocols.ldp.net_ctrl import NET_CONTROLLER

PeerCounterNames = namedtuple(
    'PeerCounterNames',
    ('RECV_PREFIXES',
     'RECV_UPDATES',
     'SENT_UPDATES',
     'RECV_NOTIFICATION',
     'SENT_NOTIFICATION',
     'SENT_REFRESH',
     'RECV_REFRESH',
     'FSM_ESTB_TRANSITIONS')
)(
    'recv_prefixes',
    'recv_updates',
    'sent_updates',
    'recv_notification',
    'sent_notification',
    'sent_refresh',
    'recv_refresh',
    'fms_established_transitions'
)

class PeerState(object):
    def __init__(self, peer, signal_bus):
        # Back pointer to peer whose stats this instances represents.
        self.peer = peer
        # Current state of BGP finite state machine.
        self._ldp_state = constants.LDP_FSM_PRESENT
        self._established_time = 0
        self._last_bgp_error = None
        self.counters = {
        }
        self._signal_bus = signal_bus

        # TODO(JK): refactor other counters to use signals also
        self._signal_bus.register_listener(
            ('error', 'ldp', self.peer),
            self._remember_last_bgp_error
        )

        self._signal_bus.register_listener(
            LdpSignalBus.LDP_NOTIFICATION_RECEIVED + (self.peer,),
            lambda _, msg: self.incr(PeerCounterNames.RECV_NOTIFICATION)
        )

        self._signal_bus.register_listener(
            LdpSignalBus.LDP_NOTIFICATION_SENT + (self.peer,),
            lambda _, msg: self.incr(PeerCounterNames.SENT_NOTIFICATION)
        )

    def _remember_last_bgp_error(self, identifier, data):
        self._last_bgp_error = dict([(k, v)
                                     for k, v in data.iteritems()
                                     if k != 'peer'])

    @property
    def recv_prefix(self):
        # Number of prefixes received from peer.
        return self.counters[PeerCounterNames.RECV_PREFIXES]

    @property
    def ldp_state(self):
        return self._bgp_state

    @ldp_state.setter
    def ldp_state(self, new_state):
        old_state = self._bgp_state
        if old_state == new_state:
            return

        self._bgp_state = new_state
        """
        NET_CONTROLLER.send_rpc_notification(
            'neighbor.state',
            {
                'ip_address': self.peer.ip_address,
                'state': new_state
            }
        )

        # transition to Established from another state
        if new_state == const.BGP_FSM_ESTABLISHED:
            self.incr(PeerCounterNames.FSM_ESTB_TRANSITIONS)
            self._established_time = time.time()
            self._signal_bus.adj_up(self.peer)
            NET_CONTROLLER.send_rpc_notification(
                'neighbor.up', {'ip_address': self.peer.ip_address}
            )
        # transition from Established to another state
        elif old_state == const.BGP_FSM_ESTABLISHED:
            self._established_time = 0
            self._signal_bus.adj_down(self.peer)
            NET_CONTROLLER.send_rpc_notification(
                'neighbor.down', {'ip_address': self.peer.ip_address}
            )

        LOG.debug('Peer %s BGP FSM went from %s to %s' %
                  (self.peer.ip_address, old_state, self.bgp_state))
        """

    def incr(self, counter_name, incr_by=1):
        if counter_name not in self.counters:
            raise ValueError('Un-recognized counter name: %s' % counter_name)
        counter = self.counters.setdefault(counter_name, 0)
        counter += incr_by
        self.counters[counter_name] = counter

    def get_count(self, counter_name):
        if counter_name not in self.counters:
            raise ValueError('Un-recognized counter name: %s' % counter_name)
        return self.counters.get(counter_name, 0)

    @property
    def total_msg_sent(self):
        """Returns total number of UPDATE, NOTIFICATION and ROUTE_REFRESH
         message sent to this peer.
         """
        return (self.get_count(PeerCounterNames.SENT_REFRESH) +
                self.get_count(PeerCounterNames.SENT_UPDATES))

    @property
    def total_msg_recv(self):
        """Returns total number of UPDATE, NOTIFCATION and ROUTE_REFRESH
        messages received from this peer.
        """
        return (self.get_count(PeerCounterNames.RECV_UPDATES) +
                self.get_count(PeerCounterNames.RECV_REFRESH) +
                self.get_count(PeerCounterNames.RECV_NOTIFICATION))

    def get_stats_summary_dict(self):
        """Returns basic stats.

        Returns a `dict` with various counts and stats, see below.
        """
        return None

class Peer(Source, Sink, Activity):

    def __init__(self, common_conf, signal_bus, peer_addr):
        peer_activity_name = 'Peer: %s' % peer_addr
        Activity.__init__(self, name=peer_activity_name)
        Source.__init__(self, version_num=1)
        Sink.__init__(self)

        # Current configuration of this peer.
        self._common_conf = common_conf
        self._signal_bus = signal_bus

        self._peer_addr = peer_addr
        # Host Bind IP
        self._host_bind_ip = None
        self._host_bind_port = None

        # TODO(PH): revisit maintaining state/stats information.
        # Peer state.
        self.state = PeerState(self, self._signal_bus)
        self._periodic_stats_logger = \
            self._create_timer('Peer State Summary Stats Timer',
                               stats.log,
                               stats_resource=self._neigh_conf,
                               stats_source=self.state.get_stats_summary_dict)
        if self._neigh_conf.stats_log_enabled:
            self._periodic_stats_logger.start(self._neigh_conf.stats_time)

        # Bound protocol instance
        self._protocol = None

        # Setting this event starts the connect_loop loop again
        # Clearing this event will stop the connect_loop loop
        self._connect_retry_event = EventletIOFactory.create_custom_event()

    def create_init_msg(self):
        return None
