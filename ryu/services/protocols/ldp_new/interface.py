class LDPInterface(object):
    def __init__(self, discovery_server, config):
        self.discovery_server =  discovery_server 
        self.state = None
        self.config = config
    
    def start(self, discovery_server):
        print 'start server'
        self.discovery_server.start(self._recv_handler)

    def _recv_handler(self, data, addr):
        print addr
        pass
