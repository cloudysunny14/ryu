"""
RFC 3036 LDP 
"""
import abc
import six
import struct
import copy
import netaddr
import numbers

from ryu.ofproto.ofproto_parser import msg_pack_into
from ryu.lib.stringify import StringifyMixin
from ryu.lib.packet import afi as addr_family
from ryu.lib.packet import safi as subaddr_family
from ryu.lib.packet import packet_base
from ryu.lib.packet import stream_parser
from ryu.lib import addrconv

_VERSION = 1

LDP_MSG_NOTIFICATION = 0x0001
LDP_MSG_HELLO = 0x0100
LDP_MSG_INIT = 0x0200
LDP_MSG_KEEPALIVE = 0x0201
LDP_MSG_ADDR = 0x0300
LDP_MSG_ADDRWITHDRAW = 0x0301
LDP_MSG_LABEL_MAPPING = 0x0400
LDP_MSG_LABEL_REQUEST = 0x0401
LDP_MSG_LABEL_WITHDRAW = 0x0402
LDP_MSG_LABEL_RELEASE = 0x0403
LDP_MSG_LABEL_ABORTREQ = 0x0404

LDP_TLV_COMMON_HELLO_PARAM = 0x0400
LDP_TLV_IPV4_TRANSPORT_ADDRESS = 0x0401
LDP_TLV_COMMON_SESSION_PARAMETERS = 0x0500
LDP_TLV_ADDRESS_LIST = 0x0101
LDP_TLV_FEC = 0x0100
LDP_TLV_GENERIC_LABEL = 0x0200
LDP_TLV_SIZE = 4
LDP_TLV_TYPE_SIZE = 2

LDP_FEC_PREFIX = 2
LDP_FEC_HOST_ADDRESS = 3

class LdpExc(Exception):
    """Base ldp exception."""

    CODE = 0
    """LDP error code."""

    SUB_CODE = 0
    """LDP error sub-code."""

    SEND_ERROR = True
    """Flag if set indicates Notification message should be sent to peer."""

    def __init__(self, data=''):
        self.data = data

    def __str__(self):
        return '<%s %r>' % (self.__class__.__name__, self.data)

class LDPBasicTLV(StringifyMixin):
    """  """
    tlv_type = None
    _BASIC_PACK_STR = '!HH'
    def __init__(self, buf=None, *_args, **_kwargs):
        super(LDPBasicTLV, self).__init__()
        if buf:
            (tlv_type, tlv_length) = struct.unpack(
                self._BASIC_PACK_STR, buf[:LDP_TLV_SIZE])
            assert len(buf) >= tlv_length + LDP_TLV_SIZE
            self.len = tlv_length
            self._tlv_info = buf[LDP_TLV_SIZE:]
            self._tlv_info = self._tlv_info[:self.len]

    @staticmethod
    def get_type(buf):
        (tlv_type, ) = struct.unpack('!H', buf[:LDP_TLV_TYPE_SIZE])
        return tlv_type

    @staticmethod
    def set_tlv_type(subcls, tlv_type):
        assert issubclass(subcls, LDPBasicTLV)
        subcls.tlv_type = tlv_type

    def serialize(self):
        return bytearray(struct.pack(self._BASIC_PACK_STR, self.tlv_type, self.len))

class LDPHeader(StringifyMixin):
    """
       0                   1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |  Version                      |         PDU Length            |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                         LDP Identifier                        |
       +                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                               |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    """
    _HDR_PACK_STR = '!HH4sH'  # version, len, lsr id, label space id
    _HDR_PACK_LEN = struct.calcsize(_HDR_PACK_STR)
    _HDR_LEN = 6

    def __init__(self, version=_VERSION, length=None, router_id='0.0.0.0',
                 label_space_id=0):
        self.version = version
        self.length = length
        self.router_id = router_id
        self.label_space_id = label_space_id

    @classmethod
    def parser(cls, buf):
        if len(buf) < cls._HDR_PACK_LEN:
            raise stream_parser.StreamParser.TooSmallException(
                '%d < %d' % (len(buf), cls._HDR_PACK_LEN))
        (version, length, router_id, label_space_id,
            ) = struct.unpack_from(cls._HDR_PACK_STR, buffer(buf))
        router_id = addrconv.ipv4.bin_to_text(router_id)
        rest = buf[cls._HDR_PACK_LEN:]

        return {
            "version": version,
            "length": length,
            "router_id": router_id,
            "label_space_id": label_space_id,
        }, rest

    def serialize(self):
        router_id = addrconv.ipv4.text_to_bin(self.router_id)
        self.length += self._HDR_LEN
        return bytearray(struct.pack(self._HDR_PACK_STR, self.version,
                         self.length, router_id, self.label_space_id))


class _TypeDisp(object):
    _TYPES = {}
    _REV_TYPES = None
    _UNKNOWN_TYPE = None

    @classmethod
    def register_unknown_type(cls):
        def _register_type(subcls):
            cls._UNKNOWN_TYPE = subcls
            return subcls
        return _register_type

    @classmethod
    def register_type(cls, type_):
        cls._TYPES = cls._TYPES.copy()

        def _register_type(subcls):
            cls._TYPES[type_] = subcls
            cls._REV_TYPES = None
            return subcls
        return _register_type

    @classmethod
    def _lookup_type(cls, type_):
        try:
            return cls._TYPES[type_]
        except KeyError:
            return cls._UNKNOWN_TYPE

    @classmethod
    def _rev_lookup_type(cls, targ_cls):
        if cls._REV_TYPES is None:
            rev = dict((v, k) for k, v in cls._TYPES.iteritems())
            cls._REV_TYPES = rev
        return cls._REV_TYPES[targ_cls]

class LDPFecElement(StringifyMixin):
    """  """
    fec_type = None
    _FEC_TYPE_PACK_STR = '!B'
    _FEC_TYPE_LEN = struct.calcsize(_FEC_TYPE_PACK_STR)

    def __init__(self, buf=None, *_args, **_kwargs):
        super(LDPFecElement, self).__init__()
        if buf:
            (self.fec_type,) = struct.unpack(
                self._FEC_TYPE_PACK_STR, buf[:self._FEC_TYPE_LEN])
            self._fec_element_info = buf[self._FEC_TYPE_LEN:]

    @staticmethod
    def get_type(buf):
        length = struct.calcsize('B')
        (fec_type, ) = struct.unpack('!B', buf[:length])
        return fec_type

    @staticmethod
    def set_fec_type(subcls, fec_type):
        assert issubclass(subcls, LDPFecElement)
        subcls.fec_type = fec_type

    def serialize(self):
        return bytearray(struct.pack(self._FEC_TYPE_PACK_STR, self.fec_type))

class LDPMessage(packet_base.PacketBase, _TypeDisp):
    """Base class for LDP messages.
2492     0                   1                   2                   3
2493     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
2494    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
2495    |U|   Message Type              |      Message Length           |
2496    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
2497    |                     Message ID                                |
2498    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
2499    |                                                               |
2500    +                                                               +
2501    |                     Mandatory Parameters                      |
2502    +                                                               +
2503    |                                                               |
2504    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
2505    |                                                               |
2506    +                                                               +
2507    |                     Optional Parameters                       |
2508    +                                                               +
2509    |                                                               |
2510    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    """

    _tlv_parsers = {}
    _MSG_HDR_PACK_STR = '!HHL'
    _MSG_HDR_LEN = struct.calcsize(_MSG_HDR_PACK_STR)
    _MSG_ID_LEN = 4

    def __init__(self, type_, version=_VERSION, length = None, router_id='0.0.0.0',
                 label_space_id=0, msg_len=None, msg_id=0, tlvs=None,
                 include_header=True):
        if include_header:
            self.header = LDPHeader(version, length, router_id, label_space_id)
        self.type = type_
        self.msg_len = msg_len
        self.msg_id = msg_id
        self.tlvs = tlvs

    @classmethod
    def parser(cls, buf, include_header=True):
        if include_header:
            ldp_hdr, rest = LDPHeader.parser(buf)
        else:
            rest = buf
            ldp_hdr = {"include_header": False}
        print len(rest)
        (type_, msg_len, msg_id) = struct.unpack_from(cls._MSG_HDR_PACK_STR, buffer(rest))
        if len(rest) < msg_len:
            raise stream_parser.StreamParser.TooSmallException(
                '%d < %d' % (len(rest), msg_len))
        subcls = cls._lookup_type(type_)
        eotlv = msg_len + cls._MSG_ID_LEN
        tlv_bin = rest[cls._MSG_HDR_LEN:eotlv]
        tlvs = []
        while tlv_bin:
            tlv_type = LDPBasicTLV.get_type(tlv_bin)
            tlv = cls.get_tlv_type(tlv_type)(tlv_bin)
            tlvs.append(tlv)
            offset = LDP_TLV_SIZE + tlv.len
            tlv_bin = tlv_bin[offset:]
        rest = rest[eotlv:]
        return subcls(msg_len=msg_len, msg_id=msg_id,
            tlvs=tlvs, **ldp_hdr), rest 

    def serialize(self, include_header=True):
        # fixup
        msg_bin = self.serialize_tlvs()
        self.msg_len = self._MSG_ID_LEN + len(msg_bin)
        msg_bin = bytearray(struct.pack(self._MSG_HDR_PACK_STR, self.type,
            self.msg_len, self.msg_id)) + msg_bin
        if include_header:
            self.header.length = len(msg_bin)
            msg_bin = self.header.serialize() + msg_bin
        else:
            del self.header
        return msg_bin

    def serialize_tlvs(self):
        data = bytearray()
        for tlv in self.tlvs:
            data += tlv.serialize()

        return data

    def __len__(self):
        # XXX destructive
        buf = self.serialize()
        return len(buf)

    @classmethod
    def get_tlv_type(cls, tlv_type):
        print tlv_type
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

@LDPMessage.register_type(LDP_MSG_HELLO)
class LDPHello(LDPMessage):
    """ """
    def __init__(self, version=_VERSION, length=None, msg_len=None,
                 router_id='0.0.0.0', label_space_id=0, msg_id=0, tlvs=None,
                 include_header=True):
        super(LDPHello, self).__init__(LDP_MSG_HELLO,
            router_id = router_id, msg_id = msg_id, length=length, msg_len=msg_len, tlvs=tlvs, include_header=include_header)


@LDPMessage.register_type(LDP_MSG_INIT)
class LDPInit(LDPMessage):
    """ """
    def __init__(self, version=_VERSION, length=None, msg_len=None,
                 router_id='0.0.0.0', label_space_id=0, msg_id=0, tlvs=None,
                 include_header=True):
        super(LDPInit, self).__init__(LDP_MSG_INIT,
            router_id = router_id, msg_id = msg_id, length=length, msg_len=msg_len, tlvs=tlvs, include_header=include_header)

@LDPMessage.register_type(LDP_MSG_NOTIFICATION)
class LDPNotification(LDPMessage):
    """ TODO """

@LDPMessage.register_type(LDP_MSG_KEEPALIVE)
class LDPKeepAlive(LDPMessage):
    def __init__(self, version=_VERSION, length=None, msg_len=None,
                 router_id='0.0.0.0', label_space_id=0, msg_id=0, tlvs=None,
                 include_header=True):
        super(LDPKeepAlive, self).__init__(LDP_MSG_KEEPALIVE,
            router_id = router_id, msg_id = msg_id, length=length, msg_len=msg_len,
            tlvs=tlvs, include_header=include_header)

@LDPMessage.register_type(LDP_MSG_ADDR)
class LDPAddress(LDPMessage):
    """ """
    def __init__(self, version=_VERSION, length=None, msg_len=None,
                 router_id='0.0.0.0', label_space_id=0, msg_id=0, tlvs=None,
                 include_header=True):
        super(LDPAddress, self).__init__(LDP_MSG_ADDR,
            router_id = router_id, msg_id = msg_id, length=length, msg_len=msg_len,
            tlvs=tlvs, include_header=include_header)

@LDPMessage.set_tlv_type(LDP_TLV_ADDRESS_LIST)
class AddressList(LDPBasicTLV):
    """
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |0|0| Address List (0x0101)     |      Length                   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Address Family            |                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               |
   |                                                               |
   |                        Addresses                              |
   ~                                                               ~
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    """
    _PACK_STR = '!H%ds'

    def __init__(self, buf=None, *args, **kwargs):
        super(AddressList, self).__init__(buf, *args, **kwargs)
        if buf:
            address_list_len = len(self._tlv_info) - struct.calcsize('H')
            packstr = self._PACK_STR % (address_list_len)
            (self.address_family, addresses) = struct.unpack(
                packstr, self._tlv_info)
            self.address_list = []
            # currentry, support ipv4 address family.
            address_len = struct.calcsize('4s')
            while addresses:
                addr = addresses[:address_len]
                addresses = addresses[address_len:]
                self.address_list.append(addrconv.ipv4.bin_to_text(addr))
        else:
            self.address_family = kwargs['address_family']
            self.address_list = kwargs['addresses']

    def serialize(self):
        tlv = bytearray(struct.pack('!H', self.address_family))
        for addr in self.address_list:
            addr = addrconv.ipv4.text_to_bin(addr)
            tlv = tlv + addr
        self.len = len(tlv)
        return LDPBasicTLV.serialize(self) + tlv

@LDPMessage.register_type(LDP_MSG_LABEL_MAPPING)
class LDPLabelMapping(LDPMessage):
    """ """
    def __init__(self, version=_VERSION, length=None, msg_len=None,
                 router_id='0.0.0.0', label_space_id=0, msg_id=0, tlvs=None,
                 include_header=True):
        super(LDPLabelMapping, self).__init__(LDP_MSG_LABEL_MAPPING,
            router_id = router_id, msg_id = msg_id, length=length, msg_len=msg_len,
            tlvs=tlvs, include_header=include_header)

@LDPMessage.set_tlv_type(LDP_TLV_FEC)
class Fec(LDPBasicTLV):
    """
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |0|0| FEC (0x0100)              |      Length                   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                        FEC Element 1                          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   ~                                                               ~
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                        FEC Element n                          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    """
    _fec_parsers = {}

    def __init__(self, buf=None, *args, **kwargs):
        super(Fec, self).__init__(buf, *args, **kwargs)
        if buf:
            rest = self._tlv_info
            self.fec_elements = []
            while rest:
                fec_type = LDPFecElement.get_type(rest)
                fec = Fec.get_fec_type(fec_type)(rest)
                self.fec_elements.append(fec)
                fec_len = LDPFecElement._FEC_TYPE_LEN + fec._len
                rest = rest[fec_len:]
        else:
            self.fec_elements = kwargs['fec_elements']

    def serialize(self):
        tlv = bytearray()
        for element in self.fec_elements:
            tlv = tlv + element.serialize()
        self.len = len(tlv)
        return LDPBasicTLV.serialize(self) + tlv

    @classmethod
    def get_fec_type(cls, fec_type):
        return cls._fec_parsers[fec_type]

    @classmethod
    def set_fec_type(cls, fec_type):
        def _set_type(fec_cls):
            fec_cls.set_fec_type(fec_cls, fec_type)
            cls._fec_parsers[fec_cls.fec_type] = fec_cls
            return fec_cls
        return _set_type

def pad(bin, len_):
    assert len(bin) <= len_
    return bin + (len_ - len(bin)) * '\0'

@Fec.set_fec_type(LDP_FEC_PREFIX)
class PrefixFecElement(LDPFecElement):
    """
       0                   1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |  Prefix (2)   |     Address Family            |     PreLen    |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                     Prefix                                    |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    """
    _PACK_STR = '!HB%ds'
    def __init__(self, buf=None, *args, **kwargs):
        super(PrefixFecElement, self).__init__(buf, *args, **kwargs)
        if buf:
            prefix_len = (len(self._fec_element_info) - struct.calcsize('HB'))
            pack_str = self._PACK_STR % (prefix_len)
            (self.address_type, self.element_len, prefix) = struct.unpack(
                pack_str, self._fec_element_info)
            self.prefix = addrconv.ipv4.bin_to_text(pad(prefix, 4))
            self._len = struct.calcsize(pack_str)
        else:
            self.address_type = kwargs['address_type']
            self.element_len = kwargs['element_len']
            self.prefix = kwargs['prefix']

    def serialize(self):
        element = bytearray(struct.pack('!HB', self.address_type,
            self.element_len))
        element = element + addrconv.ipv4.text_to_bin(self.prefix)
        return LDPFecElement.serialize(self) + element

@LDPMessage.set_tlv_type(LDP_TLV_GENERIC_LABEL)
class GenericLabel(LDPBasicTLV):
    """
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |0|0| Generic Label (0x0200)    |      Length                   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Label                                                     |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    """
    _fec_parsers = {}

    _PACK_STR = '!I'

    def __init__(self, buf=None, *args, **kwargs):
        super(GenericLabel, self).__init__(buf, *args, **kwargs)
        if buf:
            (self.label, ) = struct.unpack(self._PACK_STR, self._tlv_info)
        else:
            self.label = kwargs['label']

    def serialize(self):
        tlv = bytearray(struct.pack(self._PACK_STR, self.label))
        self.len = len(tlv)
        return LDPBasicTLV.serialize(self) + tlv

@LDPMessage.set_tlv_type(LDP_TLV_COMMON_HELLO_PARAM)
class CommonHelloParameter(LDPBasicTLV):
    """
    2880        0                   1                   2                   3
2881        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
2882       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
2883       |0|0| Common Hello Parms(0x0400)|      Length                   |
2884       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
2885       |      Hold Time                |T|R| Reserved                  |
2886       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    """
    _PACK_STR = '!HH'
    _T_BIT_MASK = 0x80
    _T_BIT_SHIFT = 15
    _R_BIT_MASK = 0x40
    _R_BIT_SHIFT = 14
    _RESERVE_BIT_MASK = 0x3fff

    def __init__(self, buf=None, *args, **kwargs):
        super(CommonHelloParameter, self).__init__(buf, *args, **kwargs)
        if buf:
            (self.hold_time, reserved) = struct.unpack(
                self._PACK_STR, self._tlv_info)
            self.t_bit = (reserved & self._T_BIT_MASK) >> self._T_BIT_SHIFT
            self.r_bit = (reserved & self._R_BIT_MASK) >> self._R_BIT_SHIFT
            self.reserved = reserved & ~(self._T_BIT_MASK + self._R_BIT_MASK)
        else:
            self.hold_time = kwargs['hold_time']
            self.t_bit = kwargs['t_bit'] << self._T_BIT_SHIFT
            self.r_bit = kwargs['r_bit'] << self._R_BIT_SHIFT
            self.reserved = self.t_bit + self.r_bit

    def serialize(self):
        tlv = bytearray(struct.pack(self._PACK_STR, self.hold_time, self.reserved))
        self.len = len(tlv)
        return LDPBasicTLV.serialize(self) + tlv

@LDPMessage.set_tlv_type(LDP_TLV_IPV4_TRANSPORT_ADDRESS)
class IPv4TransportAddress(LDPBasicTLV):
    _PACK_STR = '!4s'
    def __init__(self, buf=None, *args, **kwargs):
        super(IPv4TransportAddress, self).__init__(buf, *args, **kwargs)
        if buf:
            (addr, ) = struct.unpack(
                self._PACK_STR, self._tlv_info)
            self.addr = addrconv.ipv4.bin_to_text(addr)
        else:
            self.addr = kwargs['addr']

    def serialize(self):
        addr = addrconv.ipv4.text_to_bin(self.addr)
        tlv = bytearray(struct.pack(self._PACK_STR, addr))
        self.len = len(tlv)
        return LDPBasicTLV.serialize(self) + tlv

@LDPMessage.set_tlv_type(LDP_TLV_COMMON_SESSION_PARAMETERS)
class CommonSessionParameters(LDPBasicTLV):
    """
           0                   1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |0|0| Common Sess Parms (0x0500)|      Length                   |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      | Protocol Version              |      KeepAlive Time           |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |A|D|  Reserved |     PVLim     |      Max PDU Length           |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                 Receiver LDP Identifier                       |
      +                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                               |
      -+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-++
    """
    _PACK_STR = '!HHBBH4sH'
    _A_BIT_MASK = 0x80
    _A_BIT_SHIFT = 7
    _D_BIT_MASK = 0x40
    _D_BIT_SHIFT = 6

    def __init__(self, buf=None, *args, **kwargs):
        super(CommonSessionParameters, self).__init__(buf, *args, **kwargs)
        if buf:
            (self.proto_ver, self.keepalive_time, reserved, 
                self.pvlim, self.max_pdu_len, recv_lsr_id,
                self.receiver_label_space_id) = struct.unpack(
                    self._PACK_STR, self._tlv_info)
            self.receiver_lsr_id = addrconv.ipv4.bin_to_text(recv_lsr_id)
            self.a_bit = (reserved & self._A_BIT_MASK) >> self._A_BIT_SHIFT
            self.d_bit = (reserved & self._D_BIT_MASK) >> self._D_BIT_SHIFT
            self.reserved = reserved - (self.a_bit + self.d_bit)
        else:
            self.proto_ver = kwargs['proto_ver']
            self.keepalive_time = kwargs['keepalive_time']
            self.a_bit = kwargs['a_bit'] << self._A_BIT_SHIFT
            self.d_bit = kwargs['d_bit'] << self._D_BIT_SHIFT
            self.reserved = self.a_bit + self.d_bit
            self.pvlim = kwargs['pvlim']
            self.max_pdu_len = kwargs['max_pdu_len']
            self.receiver_lsr_id = kwargs['receiver_lsr_id']
            self.receiver_label_space_id = kwargs['receiver_label_space_id']

    def serialize(self):
        recv_lsr_id = addrconv.ipv4.text_to_bin(self.receiver_lsr_id)
        tlv = bytearray(struct.pack(self._PACK_STR, self.proto_ver,
            self.keepalive_time, self.reserved, self.pvlim,
            self.max_pdu_len, recv_lsr_id,
            self.receiver_label_space_id))
        self.len = len(tlv)
        return LDPBasicTLV.serialize(self) + tlv

