# Copyright (C) 2013,2014 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2013,2014 YAMAMOTO Takashi <yamamoto at valinux co jp>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import unittest
from nose.tools import eq_
from nose.tools import ok_

from ryu.lib.packet import ldp
from ryu.lib.packet import afi
from ryu.lib.packet import safi


class Test_ldp(unittest.TestCase):
    """ Test case for ryu.lib.packet.bgp
    """

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_hello(self):
        tlvs = [ldp.CommonHelloParameter(hold_time = 15, t_bit = 0,
                r_bit = 0), ldp.IPv4TransportAddress(addr='1.1.1.1')]
        msg = ldp.LDPHello(router_id = '1.1.1.1', msg_id = 0, tlvs = tlvs)
        binmsg = msg.serialize()
        msg2, rest = ldp.LDPMessage.parser(binmsg)
        eq_(str(msg), str(msg2))
        eq_(rest, '')


