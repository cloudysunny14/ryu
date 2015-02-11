import logging
import traceback

from ryu.services.protocols.ldp.base import add_ldp_error_metadata
from ryu.services.protocols.ldp.base import API_ERROR_CODE
from ryu.services.protocols.ldp.base import LDPSException
from ryu.services.protocols.ldp.core_manager import CORE_MANAGER

LOG = logging.getLogger('ldp_server.api.base')

API_SYM = 'name'

# API call registry
_CALL_REGISTRY = {}

@add_ldp_error_metadata(code=API_ERROR_CODE,
                        sub_code=1,
                        def_desc='Unknown API error.')
class ApiException(LDPSException):
    pass


@add_ldp_error_metadata(code=API_ERROR_CODE,
                        sub_code=2,
                        def_desc='API symbol or method is not known.')
class MethodNotFound(ApiException):
    pass


@add_ldp_error_metadata(code=API_ERROR_CODE,
                        sub_code=3,
                        def_desc='Error related to BGPS core not starting.')
class CoreNotStarted(ApiException):
    pass

def register(**kwargs):
    """Decorator for registering API function.

    Does not do any check or validation.
    """
    def decorator(func):
        _CALL_REGISTRY[kwargs.get(API_SYM, func.func_name)] = func
        return func

    return decorator


def is_call_registered(call_name):
    return call_name in _CALL_REGISTRY

def get_call(call_name):
    print str(_CALL_REGISTRY)
    return _CALL_REGISTRY.get(call_name)

def call(symbol, **kwargs):
    """Calls/executes LDPS public API identified by given symbol and passes
    given kwargs as param.
    """
    LOG.info("API method %s called with args: %s", symbol, str(kwargs))
    import all  # noqa
    if not is_call_registered(symbol):
        message = 'Did not find any method registered by symbol %s' % symbol
        raise MethodNotFound(message)

    if not symbol.startswith('core') and not CORE_MANAGER.started:
        raise CoreNotStarted(desc='CoreManager is not active.')

    call = get_call(symbol)
    print call
    try:
        return call(**kwargs)
    except LDPSException as r:
        LOG.error(traceback.format_exc())
        raise r
    except Exception as e:
        LOG.error(traceback.format_exc())
        raise ApiException(desc=str(e))
