from ryu.lib import hub
from ryu.services.protocols.ldp.api.base import register
from ryu.services.protocols.ldp.core_manager import CORE_MANAGER
from ryu.services.protocols.ldp.rtconf.base import RuntimeConfigError
from ryu.services.protocols.ldp.rtconf.common import CommonConf

@register(name='core.start')
def start(**kwargs):
    """Starts new context using provided configuration.

    Raises RuntimeConfigError if a context is already active.
    """
    if CORE_MANAGER.started:
        raise RuntimeConfigError('Current context has to be stopped to start '
                                 'a new context.')

    try:
        waiter = kwargs.pop('waiter')
    except KeyError:
        waiter = hub.Event()
    common_config = CommonConf(**kwargs)
    hub.spawn(CORE_MANAGER.start, *[], **{'common_conf': common_config,
                                          'waiter': waiter})
    return True

