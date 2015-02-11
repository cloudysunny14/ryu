import logging
import numbers

from types import BooleanType
from types import IntType
from types import LongType

from ryu.services.protocols.ldp.utils.validation import is_valid_ipv4
from ryu.services.protocols.ldp import rtconf
from ryu.services.protocols.ldp.base import validate
from ryu.services.protocols.ldp.rtconf.base import compute_optional_conf
from ryu.services.protocols.ldp.rtconf.base import ConfigValueError
from ryu.services.protocols.ldp.rtconf.base import MissingRequiredConf
from ryu.services.protocols.ldp.rtconf.base import ConfigTypeError
from ryu.services.protocols.ldp.rtconf.base import BaseConf
from ryu.services.protocols.ldp.rtconf.base import BaseConfListener

ROUTER_ID = 'router_id'
ENABLE_INTS = 'enable_ints'
HELLO_INTERVAL = 'hello_interval'
HOLD_TIME = 'hold_time'
KEEP_ALIVE = 'keep_alive'
LDP_SERVER_PORT = 'ldp_server_port'
TCP_CONN_TIMEOUT = 'tcp_conn_timeout'
LABEL_RANGE = 'label_range'

DEFAULT_HELLO_INTERVAL = 5
DEFAULT_HOLD_TIME = 15
DEFAULT_KEEP_ALIVE = 60
DEFAULT_LDP_SERVER_PORT = 646
DEFAULT_TCP_CONN_TIMEOUT = 30
DEFAULT_LABEL_RANGE = (100, 100000)

@validate(name=HOLD_TIME)
def validate_hold_time(hold_time):
    if ((hold_time is None) or (not isinstance(hold_time, IntType)) or
            hold_time < 10):
        raise ConfigValueError(desc='Invalid hold_time configuration value %s'
                               % hold_time)

    return hold_time

@validate(name=HELLO_INTERVAL)
def validate_hello_interval(hello_interval):
    if ((hello_interval is None) or (not isinstance(hello_interval, IntType)) or
            hello_interval < 1):
        raise ConfigValueError(desc='Invalid hello interval configuration value %s'
                               % hello_interval)

    return hello_interval 

@validate(name=ROUTER_ID)
def validate_router_id(router_id):
    if not router_id:
        raise MissingRequiredConf(conf_name=ROUTER_ID)

    if not isinstance(router_id, str):
        raise ConfigTypeError(conf_name=ROUTER_ID)
    if not is_valid_ipv4(router_id):
        raise ConfigValueError(desc='Invalid router id %s' % router_id)

    return router_id

@validate(name=ENABLE_INTS)
def validate_enable_ints(enable_ints):
    if not enable_ints:
        raise MissingRequiredConf(conf_name=ENABLE_INTS)

    if not isinstance(enable_ints, list):
        raise ConfigTypeError(conf_name=ROUTER_ID)
    for addr in enable_ints:
        if not is_valid_ipv4(addr):
            raise ConfigValueError(desc='Invalid router id %s' % addr)

    return enable_ints

@validate(name=LABEL_RANGE)
def validate_label_range(label_range):
    min_label, max_label = label_range
    if (not min_label or not max_label
            or not isinstance(min_label, numbers.Integral)
            or not isinstance(max_label, numbers.Integral) or min_label < 17
            or min_label >= max_label):
        raise ConfigValueError(desc=('Invalid label_range configuration value:'
                                     ' (%s).' % label_range))

    return label_range

@validate(name=LDP_SERVER_PORT)
def validate_ldp_server_port(server_port):
    if not isinstance(server_port, numbers.Integral):
        raise ConfigTypeError(desc=('Invalid bgp sever port configuration '
                                    'value %s' % server_port))
    if server_port <= 0 or server_port > 65535:
        raise ConfigValueError(desc='Invalid server port %s' % server_port)

    return server_port


@validate(name=TCP_CONN_TIMEOUT)
def validate_tcp_conn_timeout(tcp_conn_timeout):
    # TODO(apgw-dev) made-up some valid values for this settings, check if we
    # have a standard value in any routers
    if not isinstance(tcp_conn_timeout, numbers.Integral):
        raise ConfigTypeError(desc=('Invalid tcp connection timeout '
                                    'configuration value %s' %
                                    tcp_conn_timeout))

    if tcp_conn_timeout < 10:
        raise ConfigValueError(desc=('Invalid tcp connection timeout'
                                     ' configuration value %s' %
                                     tcp_conn_timeout))

    return tcp_conn_timeout

@validate(name=KEEP_ALIVE)
def validate_keep_alive(keep_alive):
    if ((keep_alive is None) or (not isinstance(keep_alive, IntType)) or
            keep_alive < 10):
        raise ConfigValueError(desc='Invalid hold_time configuration value %s'
                               % keep_alive)

    return keep_alive 

class CommonConf(BaseConf):
    """Encapsulates configurations applicable to all peer sessions.

    Currently if any of these configurations change, it is assumed that current
    active peer session will be bought down and restarted.
    """
    CONF_CHANGED_EVT = 1

    VALID_EVT = frozenset([CONF_CHANGED_EVT])

    REQUIRED_SETTINGS = frozenset([ROUTER_ID, ENABLE_INTS])

    OPTIONAL_SETTINGS = frozenset([HELLO_INTERVAL,
                                   HOLD_TIME,
                                   KEEP_ALIVE, 
                                   LDP_SERVER_PORT])

    def __init__(self, **kwargs):
        super(CommonConf, self).__init__(**kwargs)

    def _init_opt_settings(self, **kwargs):
        super(CommonConf, self)._init_opt_settings(**kwargs)
        self._settings[HELLO_INTERVAL] = compute_optional_conf(
            HELLO_INTERVAL, DEFAULT_HELLO_INTERVAL, **kwargs)
        self._settings[HOLD_TIME] = compute_optional_conf(
            HOLD_TIME, DEFAULT_HOLD_TIME, **kwargs)
        self._settings[KEEP_ALIVE] = compute_optional_conf(
            KEEP_ALIVE, DEFAULT_KEEP_ALIVE, **kwargs)
        self._settings[LDP_SERVER_PORT] = compute_optional_conf(
            LDP_SERVER_PORT, DEFAULT_LDP_SERVER_PORT, **kwargs)
        self._settings[TCP_CONN_TIMEOUT] = compute_optional_conf(
            TCP_CONN_TIMEOUT, DEFAULT_TCP_CONN_TIMEOUT, **kwargs)
        self._settings[LABEL_RANGE] = compute_optional_conf(
            LABEL_RANGE, DEFAULT_LABEL_RANGE, **kwargs)

    # =========================================================================
    # Required attributes
    # =========================================================================
    @property
    def router_id(self):
        return self._settings[ROUTER_ID]

    @property
    def enable_ints(self):
        return self._settings[ENABLE_INTS]

    # =========================================================================
    # Optional attributes with valid defaults.
    # =========================================================================

    @property
    def tcp_conn_timeout(self):
        return self._settings[TCP_CONN_TIMEOUT]

    @property
    def label_range(self):
        return self._settings[LABEL_RANGE]

    @property
    def keep_alive(self):
        return self._settings[KEEP_ALIVE]

    @property
    def hello_interval(self):
        return self._settings[HELLO_INTERVAL]

    @property
    def ldp_server_port(self):
        return self._settings[LDP_SERVER_PORT]

    @classmethod
    def get_req_settings(self):
        self_confs = super(CommonConf, self).get_req_settings()
        self_confs.update(CommonConf.REQUIRED_SETTINGS)
        return self_confs

    @classmethod
    def get_valid_evts(self):
        self_valid_evts = super(CommonConf, self).get_valid_evts()
        self_valid_evts.update(CommonConf.VALID_EVT)
        return self_valid_evts

    @classmethod
    def get_opt_settings(self):
        self_confs = super(CommonConf, self).get_opt_settings()
        self_confs.update(CommonConf.OPTIONAL_SETTINGS)
        return self_confs

    def update(self, **kwargs):
        """Updates global configuration settings with given values.

        First checks if given configuration values differ from current values.
        If any of the configuration values changed, generates a change event.
        Currently we generate change event for any configuration change.
        Note: This method is idempotent.
        """
        # Update inherited configurations
        super(CommonConf, self).update(**kwargs)
        conf_changed = False

        # Validate given configurations and check if value changed
        for conf_name, conf_value in kwargs.items():
            rtconf.base.get_validator(conf_name)(conf_value)
            item1 = self._settings.get(conf_name, None)
            item2 = kwargs.get(conf_name, None)

            if item1 != item2:
                conf_changed = True

        # If any configuration changed, we update configuration value and
        # notify listeners
        if conf_changed:
            for conf_name, conf_value in kwargs.items():
                # Since all new values are already validated, we can use them
                self._settings[conf_name] = conf_value

            self._notify_listeners(CommonConf.CONF_CHANGED_EVT, self)


class CommonConfListener(BaseConfListener):
    """Base listener for various changes to common configurations."""

    def __init__(self, global_conf):
        super(CommonConfListener, self).__init__(global_conf)
        global_conf.add_listener(CommonConf.CONF_CHANGED_EVT,
                                 self.on_update_common_conf)

    def on_update_common_conf(self, evt):
        raise NotImplementedError('This method should be overridden.')

