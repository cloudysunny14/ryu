from abc import ABCMeta
from abc import abstractmethod

from ryu.services.protocols.ldp.base import get_validator
from ryu.services.protocols.ldp.base import LDPSException
from ryu.services.protocols.ldp.base import add_ldp_error_metadata
from ryu.services.protocols.ldp.base import RUNTIME_CONF_ERROR_CODE

# Constants related to errors.
CONF_NAME = 'conf_name'
CONF_VALUE = 'conf_value'

@add_ldp_error_metadata(code=RUNTIME_CONF_ERROR_CODE, sub_code=1,
                        def_desc='Error with runtime-configuration.')
class RuntimeConfigError(LDPSException):
    """Base class for all runtime configuration errors.
    """
    pass

@add_ldp_error_metadata(code=RUNTIME_CONF_ERROR_CODE, sub_code=2,
                        def_desc='Missing required configuration.')
class MissingRequiredConf(RuntimeConfigError):
    """Exception raised when trying to configure with missing required
    settings.
    """
    def __init__(self, **kwargs):
        conf_name = kwargs.get('conf_name')
        if conf_name:
            super(MissingRequiredConf, self).__init__(
                desc='Missing required configuration: %s' % conf_name)
        else:
            super(MissingRequiredConf, self).__init__(desc=kwargs.get('desc'))

@add_ldp_error_metadata(code=RUNTIME_CONF_ERROR_CODE, sub_code=4,
                        def_desc='Incorrect Value for configuration.')
class ConfigValueError(RuntimeConfigError):
    """Exception raised when configuration value is of correct type but
    incorrect value.
    """
    def __init__(self, **kwargs):
        conf_name = kwargs.get(CONF_NAME)
        conf_value = kwargs.get(CONF_VALUE)
        if conf_name and conf_value:
            super(ConfigValueError, self).__init__(
                desc='Incorrect Value %s for configuration: %s' %
                (conf_value, conf_name))
        elif conf_name:
            super(ConfigValueError, self).__init__(
                desc='Incorrect Value for configuration: %s' % conf_name)
        else:
            super(ConfigValueError, self).__init__(desc=kwargs.get('desc'))

@add_ldp_error_metadata(code=RUNTIME_CONF_ERROR_CODE, sub_code=3,
                        def_desc='Incorrect Type for configuration.')
class ConfigTypeError(RuntimeConfigError):
    """Exception raised when configuration value type miss-match happens.
    """
    def __init__(self, **kwargs):
        conf_name = kwargs.get(CONF_NAME)
        conf_value = kwargs.get(CONF_VALUE)
        if conf_name and conf_value:
            super(ConfigTypeError, self).__init__(
                desc='Incorrect Type %s for configuration: %s' %
                (conf_value, conf_name))
        elif conf_name:
            super(ConfigTypeError, self).__init__(
                desc='Incorrect Type for configuration: %s' % conf_name)
        else:
            super(ConfigTypeError, self).__init__(desc=kwargs.get('desc'))

class ConfEvent(object):
    """Encapsulates configuration settings change/update event."""

    def __init__(self, evt_src, evt_name, evt_value):
        """Creates an instance using given parameters.

        Parameters:
            -`evt_src`: (BaseConf) source of the event
            -`evt_name`: (str) name of event, has to be one of the valid
            event of `evt_src`
            - `evt_value`: (tuple) event context that helps event handler
        """
        if evt_name not in evt_src.get_valid_evts():
            raise ValueError('Event %s is not a valid event for type %s.' %
                             (evt_name, type(evt_src)))
        self._src = evt_src
        self._name = evt_name
        self._value = evt_value

    @property
    def src(self):
        return self._src

    @property
    def name(self):
        return self._name

    @property
    def value(self):
        return self._value

    def __repr__(self):
        return '<ConfEvent(%s, %s, %s)>' % (self.src, self.name, self.value)

    def __str__(self):
        return ('ConfEvent(src=%s, name=%s, value=%s)' %
                (self.src, self.name, self.value))

    def __cmp__(self, other):
        return cmp((other.src, other.name, other.value),
                   (self.src, self.name, self.value))

# =============================================================================
# Configuration base classes.
# =============================================================================

class BaseConf(object):
    """Base class for a set of configuration values.

    Configurations can be required or optional. Also acts as a container of
    configuration change listeners.
    """
    __metaclass__ = ABCMeta

    def __init__(self, **kwargs):
        self._req_settings = self.get_req_settings()
        self._opt_settings = self.get_opt_settings()
        self._valid_evts = self.get_valid_evts()
        self._listeners = {}
        self._settings = {}

        # validate required and unknown settings
        self._validate_req_unknown_settings(**kwargs)

        # Initialize configuration settings.
        self._init_req_settings(**kwargs)
        self._init_opt_settings(**kwargs)

    @property
    def settings(self):
        """Returns a copy of current settings."""
        return self._settings.copy()

    @classmethod
    def get_valid_evts(self):
        return set()

    @classmethod
    def get_req_settings(self):
        return set()

    @classmethod
    def get_opt_settings(self):
        return set()

    @abstractmethod
    def _init_opt_settings(self, **kwargs):
        """Sub-classes should override this method to initialize optional
         settings.
        """
        pass

    @abstractmethod
    def update(self, **kwargs):
        # Validate given values
        self._validate_req_unknown_settings(**kwargs)

    def _validate_req_unknown_settings(self, **kwargs):
        """Checks if required settings are present.

        Also checks if unknown requirements are present.
        """
        # Validate given configuration.
        self._all_attrs = (self._req_settings | self._opt_settings)
        if not kwargs and len(self._req_settings) > 0:
            raise MissingRequiredConf(desc='Missing all required attributes.')

        given_attrs = frozenset(kwargs.keys())
        unknown_attrs = given_attrs - self._all_attrs
        if unknown_attrs:
            raise RuntimeConfigError(desc=(
                'Unknown attributes: %s' %
                ', '.join([str(i) for i in unknown_attrs]))
            )
        missing_req_settings = self._req_settings - given_attrs
        if missing_req_settings:
            raise MissingRequiredConf(conf_name=list(missing_req_settings))

    def _init_req_settings(self, **kwargs):
        for req_attr in self._req_settings:
            req_attr_value = kwargs.get(req_attr)
            if req_attr_value is None:
                raise MissingRequiredConf(conf_name=req_attr_value)
            print 'validate req_attr : %s' % str(req_attr)
            # Validate attribute value
            req_attr_value = get_validator(req_attr)(req_attr_value)
            self._settings[req_attr] = req_attr_value

    def add_listener(self, evt, callback):
        #   if (evt not in self.get_valid_evts()):
        #       raise RuntimeConfigError(desc=('Unknown event %s' % evt))

        listeners = self._listeners.get(evt, None)
        if not listeners:
            listeners = set()
            self._listeners[evt] = listeners
        listeners.update([callback])

    def remove_listener(self, evt, callback):
        if evt in self.get_valid_evts():
            listeners = self._listeners.get(evt, None)
            if listeners and (callback in listeners):
                listeners.remove(callback)
                return True

        return False

    def _notify_listeners(self, evt, value):
        listeners = self._listeners.get(evt, [])
        for callback in listeners:
            callback(ConfEvent(self, evt, value))

    def __repr__(self):
        return '%s(%r)' % (self.__class__, self._settings)

class BaseConfListener(object):
    """Base class of all configuration listeners."""
    __metaclass__ = ABCMeta

    def __init__(self, base_conf):
        pass
    # TODO(PH): re-vist later and check if we need this check
#         if not isinstance(base_conf, BaseConf):
#             raise TypeError('Currently we only support listening to '
#                             'instances of BaseConf')

def compute_optional_conf(conf_name, default_value, **all_config):
    """Returns *conf_name* settings if provided in *all_config*, else returns
     *default_value*.

    Validates *conf_name* value if provided.
    """
    conf_value = all_config.get(conf_name)
    if conf_value is not None:
        # Validate configuration value.
        conf_value = get_validator(conf_name)(conf_value)
    else:
        conf_value = default_value
    return conf_value
