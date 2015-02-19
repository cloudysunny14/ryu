import socket
import logging

LOG = logging.getLogger('ldp_util')

def from_inet_ptoi(bgp_id):
    """Convert an IPv4 address string format to a four byte long.
    """
    four_byte_id = None
    try:
        packed_byte = socket.inet_pton(socket.AF_INET, bgp_id)
        four_byte_id = long(packed_byte.encode('hex'), 16)
    except ValueError:
        LOG.debug('Invalid bgp id given for conversion to integer value %s' %
                  bgp_id)

    return four_byte_id

