import abc
import logging
import socket
import time
import traceback
import weakref
import netaddr
import struct

from ryu.lib import hub
from ryu.lib.hub import Timeout
from ryu.lib import sockopt
from ryu.services.protocols.ldp.utils.evtlet import LoopingCall

# Logger instance for this module.
LOG = logging.getLogger('ldpservice.base')

# Various error codes
ACTIVITY_ERROR_CODE = 100
RUNTIME_CONF_ERROR_CODE = 200
BIN_ERROR = 300
NET_CTRL_ERROR_CODE = 400
API_ERROR_CODE = 500
PREFIX_ERROR_CODE = 600
LDP_PROCESSOR_ERROR_CODE = 700
CORE_ERROR_CODE = 800

# Registry of custom exceptions
# Key: code:sub-code
# Value: exception class
_EXCEPTION_REGISTRY = {}

class LDPSException(Exception):
    """Base exception class for all BGPS related exceptions.
    """

    CODE = 1
    SUB_CODE = 1
    DEF_DESC = 'Unknown exception.'

    def __init__(self, desc=None):
        super(LDPSException, self).__init__()
        if not desc:
            desc = self.__class__.DEF_DESC
        kls = self.__class__
        self.message = '%d.%d - %s' % (kls.CODE, kls.SUB_CODE, desc)

    def __repr__(self):
        kls = self.__class__
        return '<%s(desc=%s)>' % (kls, self.message)

    def __str__(self, *args, **kwargs):
        return self.message


def add_ldp_error_metadata(code, sub_code, def_desc='unknown'):
    """Decorator for all exceptions that want to set exception class meta-data.
    """
    # Check registry if we already have an exception with same code/sub-code
    if _EXCEPTION_REGISTRY.get((code, sub_code)) is not None:
        raise ValueError('BGPSException with code %d and sub-code %d '
                         'already defined.' % (code, sub_code))

    def decorator(klass):
        """Sets class constants for exception code and sub-code.

        If given class is sub-class of BGPSException we sets class constants.
        """
        if issubclass(klass, LDPSException):
            _EXCEPTION_REGISTRY[(code, sub_code)] = klass
            klass.CODE = code
            klass.SUB_CODE = sub_code
            klass.DEF_DESC = def_desc
        return klass
    return decorator

@add_ldp_error_metadata(code=ACTIVITY_ERROR_CODE,
                        sub_code=1,
                        def_desc='Unknown activity exception.')
class ActivityException(LDPSException):
    """Base class for exceptions related to Activity.
    """
    pass

class Activity(object):
    """Base class for a thread of execution that provides some custom settings.

    Activity is also a container of other activities or threads that it has
    started. Inside a Activity you should always use one of the spawn method
    to start another activity or greenthread. Activity is also holds pointers
    to sockets that it or its child activities of threads have create.
    """
    __metaclass__ = abc.ABCMeta

    def __init__(self, name=None):
        self._name = name
        if self._name is None:
            self._name = 'UnknownActivity: ' + str(time.time())
        self._child_thread_map = weakref.WeakValueDictionary()
        self._child_activity_map = weakref.WeakValueDictionary()
        self._asso_socket_map = weakref.WeakValueDictionary()
        self._timers = weakref.WeakValueDictionary()
        self._started = False

    @property
    def name(self):
        return self._name

    @property
    def started(self):
        return self._started

    def _validate_activity(self, activity):
        """Checks the validity of the given activity before it can be started.
        """
        if not self._started:
            raise ActivityException(desc='Tried to spawn a child activity'
                                    ' before Activity was started.')

        if activity.started:
            raise ActivityException(desc='Tried to start an Activity that was '
                                    'already started.')

    def _spawn_activity(self, activity, *args, **kwargs):
        """Starts *activity* in a new thread and passes *args* and *kwargs*.

        Maintains pointer to this activity and stops *activity* when this
        activity is stopped.
        """
        self._validate_activity(activity)

        # Spawn a new greenthread for given activity
        greenthread = hub.spawn(activity.start, *args, **kwargs)
        self._child_thread_map[activity.name] = greenthread
        self._child_activity_map[activity.name] = activity
        return greenthread

    def _spawn_activity_after(self, seconds, activity, *args, **kwargs):
        self._validate_activity(activity)

        # Schedule to spawn a new greenthread after requested delay
        greenthread = hub.spawn_after(seconds, activity.start, *args,
                                      **kwargs)
        self._child_thread_map[activity.name] = greenthread
        self._child_activity_map[activity.name] = activity
        return greenthread

    def _validate_callable(self, callable_):
        if callable_ is None:
            raise ActivityException(desc='Callable cannot be None')

        if not hasattr(callable_, '__call__'):
            raise ActivityException(desc='Currently only supports instances'
                                    ' that have __call__ as callable which'
                                    ' is missing in given arg.')
        if not self._started:
            raise ActivityException(desc='Tried to spawn a child thread '
                                    'before this Activity was started.')

    def _spawn(self, name, callable_, *args, **kwargs):
        self._validate_callable(callable_)
        greenthread = hub.spawn(callable_, *args, **kwargs)
        self._child_thread_map[name] = greenthread
        return greenthread

    def _spawn_after(self, name, seconds, callable_, *args, **kwargs):
        self._validate_callable(callable_)
        greenthread = hub.spawn_after(seconds, callable_, *args, **kwargs)
        self._child_thread_map[name] = greenthread
        return greenthread

    def _create_timer(self, name, func, *arg, **kwarg):
        timer = LoopingCall(func, *arg, **kwarg)
        self._timers[name] = timer
        return timer

    @abc.abstractmethod
    def _run(self, *args, **kwargs):
        """Main activity of this class.

        Can launch other activity/callables here.
        Sub-classes should override this method.
        """
        raise NotImplementedError()

    def start(self, *args, **kwargs):
        """Starts the main activity of this class.

        Calls *_run* and calls *stop* when *_run* is finished.
        This method should be run in a new greenthread as it may not return
        immediately.
        """
        if self.started:
            raise ActivityException(desc='Activity already started')

        self._started = True
        try:
            self._run(*args, **kwargs)
        except LDPSException:
            LOG.error(traceback.format_exc())
        finally:
            if self.started:  # could have been stopped somewhere else
                self.stop()

    def pause(self, seconds=0):
        """Relinquishes hub for given number of seconds.

        In other words is puts to sleep to give other greeenthread a chance to
        run.
        """
        hub.sleep(seconds)

    def _stop_child_activities(self):
        """Stop all child activities spawn by this activity.
        """
        # Iterating over items list instead of iteritems to avoid dictionary
        # changed size during iteration
        child_activities = self._child_activity_map.items()
        for child_name, child_activity in child_activities:
            LOG.debug('%s: Stopping child activity %s ' %
                      (self.name, child_name))
            if child_activity.started:
                child_activity.stop()

    def _stop_child_threads(self, name=None):
        """Stops all threads spawn by this activity.
        """
        child_threads = self._child_thread_map.items()
        for thread_name, thread in child_threads:
            if not name or thread_name is name:
                LOG.debug('%s: Stopping child thread %s' %
                          (self.name, thread_name))
                thread.kill()
                del self._child_thread_map[thread_name]

    def _close_asso_sockets(self):
        """Closes all the sockets linked to this activity.
        """
        asso_sockets = self._asso_socket_map.items()
        for sock_name, sock in asso_sockets:
            LOG.debug('%s: Closing socket %s - %s' %
                      (self.name, sock_name, sock))
            sock.close()

    def _stop_timers(self):
        timers = self._timers.items()
        for timer_name, timer in timers:
            LOG.debug('%s: Stopping timer %s' % (self.name, timer_name))
            timer.stop()

    def stop(self):
        """Stops all child threads and activities and closes associated
        sockets.

        Re-initializes this activity to be able to start again.
        Raise `ActivityException` if activity is not currently started.
        """
        if not self.started:
            raise ActivityException(desc='Cannot call stop when activity is '
                                    'not started or has been stopped already.')

        LOG.debug('Stopping activity %s.' % (self.name))
        self._stop_timers()
        self._stop_child_activities()
        self._stop_child_threads()
        self._close_asso_sockets()

        # Setup activity for start again.
        self._started = False
        self._asso_socket_map = weakref.WeakValueDictionary()
        self._child_activity_map = weakref.WeakValueDictionary()
        self._child_thread_map = weakref.WeakValueDictionary()
        self._timers = weakref.WeakValueDictionary()
        LOG.debug('Stopping activity %s finished.' % self.name)

    def _canonicalize_ip(self, ip):
        addr = netaddr.IPAddress(ip)
        if addr.is_ipv4_mapped():
            ip = str(addr.ipv4())
        return ip

    def get_remotename(self, sock):
        addr, port = sock.getpeername()[:2]
        return (self._canonicalize_ip(addr), str(port))

    def get_localname(self, sock):
        addr, port = sock.getsockname()[:2]
        return (self._canonicalize_ip(addr), str(port))

    def _listen_sockets_tcp(self, info):
        return None

    def _recv_sockets_discovery(self, info, mcast_addr):
        listen_sockets = {}
        for res in info:
            af, socktype, proto, cannonname, sa = res
            sock = None
            try:
                sock = socket.socket(af, socktype, proto)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                if hasattr(socket, "SO_REUSEPORT"):
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
                mreq = struct.pack("4sl",
socket.inet_aton(mcast_addr), socket.INADDR_ANY)
                sock.setsockopt(
                    socket.IPPROTO_IP,
                    socket.IP_ADD_MEMBERSHIP,
                    mreq)
                # TODO: confirm work with sock.bind(sa)
                # sock.bind(sa)
                sock.bind(('', 646))
                listen_sockets[sa] = sock
            except socket.error:
                 if sock:
                     sock.close()

        return listen_sockets

    def _listen_socket_tcp(self, info):
        listen_sockets = {}
        for res in info:
            af, socktype, proto, cannonname, sa = res
            sock = None
            try:
                sock = socket.socket(af, socktype, proto)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                if af == socket.AF_INET6:
                    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)

                sock.bind(sa)
                sock.listen(50)
                listen_sockets[sa] = sock
            except socket.error:
                if sock:
                    sock.close()

        return listen_sockets

    def _server(self, listen_sockets, conn_handle):
        count = 0
        server = None
        for sa in listen_sockets.keys():
            name = self.name + '_server@' + str(sa[0])
            if count == 0:
                import eventlet
                server = eventlet.spawn(self._listen_socket_loop,
                                        listen_sockets[sa], conn_handle)

                count += 1
            else:
                self._spawn(name, self._listen_socket_loop,
                            listen_sockets[sa], conn_handle)
        return server

    def _recv_server(self, recv_sockets, recv_handle):
        count = 0
        server = None
        for sa in recv_sockets.keys():
            name = self.name + '_server@' + str(sa[0])
            if count == 0:
                import eventlet
                server = eventlet.spawn(self._recv_socket_loop,
                                        recv_sockets[sa], recv_handle)

                count += 1
            else:
                self._spawn(name, self._recv_socket_loop,
                            recv_sockets[sa], recv_handle)
        return server

    def _discovery_socket(self, mcast_addr, loc_addr, recv_handle):
        info = socket.getaddrinfo(None, loc_addr[1], socket.AF_UNSPEC,
                                  socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        recv_sockets = self._recv_sockets_discovery(info,
mcast_addr)
        server = self._recv_server(recv_sockets, recv_handle)

        return server, recv_sockets


    def _listen_tcp(self, loc_addr, conn_handle):
        info = socket.getaddrinfo(None, loc_addr[1], socket.AF_UNSPEC,
                                  socket.SOCK_STREAM, 0, socket.AI_PASSIVE)

        listen_sockets = self._listen_socket_tcp(info)
        server = self._server(listen_sockets, conn_handle)

        return server, listen_sockets

    def _recv_socket_loop(self, s, recv_handle):
        while True:
            data, addr = s.recvfrom(10240)
            client_name = self.name + '_clinet@' + str(addr)
            self._spawn(client_name, recv_handle, data)

    def _listen_socket_loop(self, s, conn_handle):
        while True:
            sock, client_address = s.accept()
            client_address, port = self.get_remotename(sock)
            LOG.debug('Connect request received from client for port'
                      ' %s:%s' % (client_address, port))
            client_name = self.name + '_client@' + client_address
            self._asso_socket_map[client_name] = sock
            self._spawn(client_name, conn_handle, sock)

    def _listen_socket(self, loc_addr, socktype, conn_handle):
        """Creates a server socket which listens on `port` number.

        For each connection `server_factory` starts a new protocol.
        """
        info = socket.getaddrinfo(None, loc_addr[1], socket.AF_UNSPEC,
                                  socktype, 0, socket.AI_PASSIVE)
        listen_sockets = {}
        for res in info:
            af, socktype, proto, cannonname, sa = res
            sock = None
            try:
                sock = socket.socket(af, socktype, proto)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                if af == socket.AF_INET6:
                    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)

                sock.bind(sa)
                sock.listen(50)
                listen_sockets[sa] = sock
            except socket.error:
                if sock:
                    sock.close()

        count = 0
        server = None
        for sa in listen_sockets.keys():
            name = self.name + '_server@' + str(sa[0])
            if count == 0:
                import eventlet
                server = eventlet.spawn(self._listen_socket_loop,
                                        listen_sockets[sa], conn_handle)

                count += 1
            else:
                self._spawn(name, self._listen_socket_loop,
                            listen_sockets[sa], conn_handle)
        return server, listen_sockets

    def _connect_tcp(self, peer_addr, conn_handler, time_out=None,
                     bind_address=None, password=None):
        """Creates a TCP connection to given peer address.

        Tries to create a socket for `timeout` number of seconds. If
        successful, uses the socket instance to start `client_factory`.
        The socket is bound to `bind_address` if specified.
        """
        LOG.debug('Connect TCP called for %s:%s' % (peer_addr[0],
                                                    peer_addr[1]))
        if netaddr.valid_ipv4(peer_addr[0]):
            family = socket.AF_INET
        else:
            family = socket.AF_INET6
        with Timeout(time_out, socket.error):
            sock = socket.socket(family)
            if bind_address:
                sock.bind(bind_address)
            if password:
                sockopt.set_tcp_md5sig(sock, peer_addr[0], password)
            sock.connect(peer_addr)
            # socket.error exception is rasied in cese of timeout and
            # the following code is executed only when the connection
            # is established.

        # Connection name for pro-active connection is made up of
        # local end address + remote end address
        local = self.get_localname(sock)[0]
        remote = self.get_remotename(sock)[0]
        conn_name = ('L: ' + local + ', R: ' + remote)
        self._asso_socket_map[conn_name] = sock
        # If connection is established, we call connection handler
        # in a new thread.
        self._spawn(conn_name, conn_handler, sock)
        return sock

# Registry of validators for configuration/settings.
_VALIDATORS = {}


def validate(**kwargs):
    """Defines a decorator to register a validator with a name for look-up.

    If name is not provided we use function name as name of the validator.
    """
    def decorator(func):
        _VALIDATORS[kwargs.pop('name', func.func_name)] = func
        return func

    return decorator


def get_validator(name):
    """Returns a validator registered for given name.
    """
    print 'validator : %s' % str(_VALIDATORS)
    return _VALIDATORS.get(name)

