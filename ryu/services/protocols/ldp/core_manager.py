"""
 Core Manager module dedicated for providing CORE_MANAGER singleton
"""
from ryu.services.protocols.ldp.base import Activity
from ryu.services.protocols.ldp.base import ActivityException
from ryu.services.protocols.ldp.rtconf.neighbors import NeighborsConf


class _CoreManager(Activity):
    """Core service manager.
    """

    def __init__(self):
        self._common_conf = None
        self._neighbors_conf = None
        self._core_service = None
        super(_CoreManager, self).__init__()

    def _run(self, *args, **kwargs):
        self._common_conf = kwargs.pop('common_conf')
        from ryu.services.protocols.ldp.core import CoreService
        self._core_service = CoreService(self._common_conf)
        waiter = kwargs.pop('waiter')
        core_activity = self._spawn_activity(self._core_service, waiter=waiter)
        core_activity.wait()

    def get_core_service(self):
        self._check_started()
        return self._core_service

    def _check_started(self):
        if not self.started:
            raise ActivityException('Cannot access any property before '
                                    'activity has started')

    @property
    def common_conf(self):
        self._check_started()
        return self._common_conf

# _CoreManager instance that manages core bgp service and configuration data.
CORE_MANAGER = _CoreManager()
