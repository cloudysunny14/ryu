import struct

from ryu.lib import addrconv
from . import packet_base
from . import packet_utils
from ryu.lib.stringify import StringifyMixin

_VERSION = 1

MPLS_ECHO_REQUEST = 1
MPLS_ECHO_REPLY = 2

MPLS_REPLY_MODE_DONOT_REPLY = 1
MPLS_REPLY_MODE_UDP_PACKET = 2
MPLS_REPLY_MODE_UDP_WITH_RT_ALERT = 3
MPLS_REPLY_MODE_APP_LEVEL_CTL_CH = 4


TARGET_FEC_STACK = 1
DOWNSTREAM_MAPPING = 2
PAD = 3
VENDOR_ENTERPRISE_NUMBER = 5
INTERFACE_AND_LABEL_STACK = 7
ERRORED_TLVS = 9
REPLY_TOS_BYTE = 10
LSP_PING_TLV_SIZE = 4
LSP_PING_TYPE_SIZE = 2

#Target Fec Stack Sub Type
LDP_IPV4_PREFIX = 1
LDP_IPV6_PREFIX = 2
RSVP_IPV4_LSP = 3
RSVP_IPV6_LSP = 4
VPN_IPV4_PREFIX = 6
VPN_IPV6_PREFIX = 7
L2_VPN_ENDPOINT = 8
FEC_128_PSEUDOWIRE = 10
FEC_129_PSEUDOWIRE = 11
BGP_LABELED_IPV4_PREFIX = 12
BGP_LABELED_IPV6_PREFIX = 13
GENERIC_IPV4_PREFIX = 14
GENERIC_IPV6_PREFIX = 15
NIL_FEC = 16

class LSPPingBasicTLV(StringifyMixin):
    """  """
    tlv_type = None
    _BASIC_PACK_STR = '!HH'
    _BASIC_PACK_LEN = struct.calcsize(_BASIC_PACK_STR)

    def __init__(self, buf=None, *_args, **_kwargs):
        super(LSPPingBasicTLV, self).__init__()
        if buf:
            (self.tlv_type, tlv_length) = struct.unpack(
                self._BASIC_PACK_STR, buf[:LSP_PING_TLV_SIZE])
            assert len(buf) >= tlv_length + LSP_PING_TLV_SIZE
            self.len = tlv_length
            self._tlv_info = buf[LSP_PING_TLV_SIZE:]
            self._tlv_info = self._tlv_info[:self.len]

    @staticmethod
    def get_type(buf):
        (tlv_type, ) = struct.unpack('!H', buf[:LSP_PING_TYPE_SIZE])
        return tlv_type

    @staticmethod
    def set_tlv_type(subcls, tlv_type):
        assert issubclass(subcls, LSPPingBasicTLV)
        subcls.tlv_type = tlv_type

    @staticmethod
    def set_sub_tlv_type(subcls, tlv_type):
        assert issubclass(subcls, LSPPingBasicTLV)
        subcls.tlv_type = tlv_type

    def serialize(self):
        return bytearray(struct.pack(self._BASIC_PACK_STR, self.tlv_type, self.len))

def pad(bin, len_):
    assert len(bin) <= len_
    return bin + (len_ - len(bin)) * '\0'

class MPLSEcho(packet_base.PacketBase):
    """
       0                   1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |         Version Number        |         Global Flags          |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |  Message Type |   Reply mode  |  Return Code  | Return Subcode|
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                        Sender's Handle                        |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                        Sequence Number                        |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                    TimeStamp Sent (seconds)                   |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                  TimeStamp Sent (microseconds)                |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                  TimeStamp Received (seconds)                 |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                TimeStamp Received (microseconds)              |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                            TLVs ...                           |
      .                                                               .
      .                                                               .
      .                                                               .
      |                                                               |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    """
    _PACK_STR = '!HHBBBBIIIIII'
    _PACK_LEN = struct.calcsize(_PACK_STR)
    _MSG_TYPES = {}
    _tlv_parsers = {}

    def __init__(self, type=MPLS_ECHO_REQUEST, version=_VERSION, v_flag=0, reply_mode=None, return_code=0, return_sub_code=0, senders_handle=None, sequence_num=0, timestamp_sent=0, timestamp_recv=0, tlvs=None):
        self.type = type
        self.version = version
        self.v_flag = v_flag
        self.reply_mode = reply_mode
        self.return_code = return_code
        self.return_sub_code = return_sub_code
        self.senders_handle = senders_handle
        self.sequence_num = sequence_num
        self.timestamp_sent = timestamp_sent
        self.timestamp_recv = timestamp_recv
        self.tlvs = tlvs

    @classmethod
    def parser(cls, buf):
        (version, global_flag, type_,
            reply_mode, return_code, return_sub_code, 
            senders_handle, sequence_num, timestamp_sent_1,
            timestamp_sent_2, timestamp_recv_1,
            timestamp_recv_2) = struct.unpack_from(cls._PACK_STR, buf)
        rest = buf[cls._PACK_LEN:]
        tlvs = []
        while rest:
            print ''.join('{:02x}'.format(x) for x in rest)
            tlv_type = LSPPingBasicTLV.get_type(rest)
            tlv = cls.get_tlv_type(tlv_type)(rest)
            tlvs.append(tlv)
            offset = LSP_PING_TLV_SIZE + tlv.len
            rest = rest[offset:]

        timestamp_sent = float(timestamp_sent_1) + timestamp_sent_2 * (10 ** -6) 
        timestamp_recv = float(timestamp_recv_1) + timestamp_recv_2 * (10 ** -6)
        return cls(type=type_, version=version,
            v_flag=global_flag, reply_mode=reply_mode,
            return_code=return_code, return_sub_code=return_sub_code,
            senders_handle=senders_handle, sequence_num=sequence_num, 
            timestamp_sent=timestamp_sent, timestamp_recv=timestamp_recv, tlvs=tlvs), rest
        
    def serialize(self):
        msg_bin = self.serialize_tlvs()
        ts_1, ts_2 = [int(t) for t in ("%.6f" % self.timestamp_sent).split('.')]
        tr_1, tr_2 = [int(t) for t in ("%.6f" % self.timestamp_recv).split('.')]
        msg_bin = bytearray(struct.pack(self._PACK_STR, 
            self.version, self.v_flag, self.type, 
            self.reply_mode,
            self.return_code, self.return_sub_code,
            self.senders_handle, self.sequence_num,
            ts_1, ts_2, tr_1, tr_2)) + msg_bin
        return msg_bin

    def serialize_tlvs(self):
        data = bytearray()
        for tlv in self.tlvs:
            data += tlv.serialize()

        return data

    @classmethod
    def get_tlv_type(cls, tlv_type):
        return cls._tlv_parsers[tlv_type]

    @classmethod
    def set_tlv_type(cls, tlv_type):
        def _set_type(tlv_cls):
            tlv_cls.set_tlv_type(tlv_cls, tlv_type)
            cls._tlv_parsers[tlv_cls.tlv_type] = tlv_cls
            return tlv_cls
        return _set_type

    @classmethod
    def retrive_tlv(cls, tlv_type, msg):
        for tlv in msg.tlvs:
            if tlv_type == tlv.tlv_type:
                return tlv
        return None

    def __len__(self):
        return self._MIN_LEN + len(self.data)

@MPLSEcho.set_tlv_type(TARGET_FEC_STACK)
class TargetFecStack(LSPPingBasicTLV):
    _sub_tlv_parsers = {}
    def __init__(self, buf=None, *args, **kwargs):
        super(TargetFecStack, self).__init__(buf, *args, **kwargs)
        if buf:
            rest = self._tlv_info
            self.sub_tlvs = []
            while rest:
                tlv_type = TargetFecStack.get_sub_type(rest)
                tlv = TargetFecStack.get_sub_tlv_type(tlv_type)(rest)
                self.sub_tlvs.append(tlv)
                sub_tlv_len = \
                  LSPPingBasicTLV._BASIC_PACK_LEN + len(tlv)
                rest = rest[sub_tlv_len:]
        else:
            self.sub_tlvs = kwargs['sub_tlvs']

    def serialize(self):
        tlv = bytearray()
        for sub_tlv in self.sub_tlvs:
            tlv = tlv + sub_tlv.serialize()
        self.len = len(tlv)
        return LSPPingBasicTLV.serialize(self) + tlv

    @classmethod
    def get_sub_type(cls, buf):
        (tlv_type, ) = struct.unpack('!H', buf[:LSP_PING_TYPE_SIZE])
        return tlv_type

    @classmethod
    def get_sub_tlv_type(cls, sub_tlv_type):
        return cls._sub_tlv_parsers[sub_tlv_type]

    @classmethod
    def set_sub_tlv_type(cls, sub_tlv_type):
        def _set_type(sub_tlv_cls):
            sub_tlv_cls.set_sub_tlv_type(sub_tlv_cls, sub_tlv_type)
            cls._sub_tlv_parsers[sub_tlv_cls.tlv_type] = sub_tlv_cls 
            print str(cls._sub_tlv_parsers)
            return sub_tlv_cls 
        return _set_type

@TargetFecStack.set_sub_tlv_type(LDP_IPV4_PREFIX)
class IPv4PrefixTLV(LSPPingBasicTLV):
    """
       0                   1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                          IPv4 prefix                          |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      | Prefix Length |         Must Be Zero                          |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    """

    _PACK_STR = '!4sB'
    _LEN = struct.calcsize(_PACK_STR)
    _FIXED_LEN = 8

    def __init__(self, buf=None, *args, **kwargs):
        super(IPv4PrefixTLV, self).__init__(buf, *args, **kwargs)
        if buf:
            (prefix, self.prefix_len) = \
                struct.unpack(self._PACK_STR, self._tlv_info)
            self.prefix = addrconv.ipv4.bin_to_text(prefix)
        else:
            self.prefix = kwargs['prefix']
            self.prefix_len = kwargs['prefix_len']

    def serialize(self):
        tlv = bytearray(struct.pack("B", self.prefix_len))
        tlv = pad(tlv, 4)
        tlv = addrconv.ipv4.text_to_bin(self.prefix) + tlv
        self.len = self._LEN
        return LSPPingBasicTLV.serialize(self) + tlv

    def __len__(self):
        return 8
