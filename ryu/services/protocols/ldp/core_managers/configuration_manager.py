from ryu.services.protocols.ldp.rtconf.common import CommonConfListener

import logging

LOG = logging.getLogger('ldpserverpeaker.core_managers.table_mixin')


class ConfigurationManager(CommonConfListener):
    def __init__(self, core_service, common_conf):
        self._signal_bus = core_service.signal_bus
        self._common_config = common_conf
        CommonConfListener.__init__(self, common_conf)

    def on_update_common_conf(self, evt):
        raise NotImplementedError()

