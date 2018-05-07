#! /usr/bin/env python
########################################################################
# SimpleFIX
# Copyright (C) 2016-2018, David Arnold.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
########################################################################

import sys
import unittest

from simplefix import FixMessage, FixParser, SOH_STR


def make_str(s):
    if sys.version_info.major == 2:
        return bytes(s)
    else:
        return bytes(s, 'ASCII')


# Python 2.6's unittest.TestCase doesn't have assertIsNone()
def test_none(self, other):
    return True if other is None else False


# Python 2.6's unittest.TestCase doesn't have assertIsNotNone()
def test_not_none(self, other):
    return False if other is None else True


class ParserTests(unittest.TestCase):


    def setUp(self):
        if not hasattr(self, "assertIsNotNone"):
            ParserTests.assertIsNotNone = test_not_none
        if not hasattr(self, "assertIsNone"):
            ParserTests.assertIsNone = test_none
        return

    def tearDown(self):
        pass

    def test_parse_empty_string(self):
        """Test parsing empty string."""
        parser = FixParser()
        msg = parser.get_message()
        self.assertIsNone(msg)
        return

    def test_basic_fix_message(self):
        """Test parsing basic FIX message."""
        pkt = FixMessage()
        pkt.append_pair(8, "FIX.4.2")
        pkt.append_pair(35, "D")
        pkt.append_pair(29, "A")
        buf = pkt.encode()

        p = FixParser()
        p.append_buffer(buf)
        m = p.get_message()

        self.assertIsNotNone(m)
        self.assertEqual(b"FIX.4.2", m.get(8))
        self.assertEqual(b"D", m.get(35))
        self.assertEqual(b"A", m.get(29))
        return

    def test_parse_partial_string(self):
        """Test parsing incomplete FIX message."""
        parser = FixParser()
        parser.append_buffer("8=FIX.4.2\x019=")
        msg = parser.get_message()
        self.assertIsNone(msg)

        parser.append_buffer("5\x0135=0\x0110=161\x01")
        msg = parser.get_message()
        self.assertIsNotNone(msg)
        self.assertEqual(b"FIX.4.2", msg.get(8))
        self.assertEqual(b"5", msg.get(9))
        self.assertEqual(b"0", msg.get(35))
        self.assertEqual(b"161", msg.get(10))
        return

    def test_get_buffer(self):
        """Test reassembly of message fragments."""
        parser = FixParser()
        parser.append_buffer("8=FIX.4.2\x019=")
        msg = parser.get_message()
        self.assertIsNone(msg)

        buf = parser.get_buffer()
        self.assertEqual(b"9=", buf)

        parser.append_buffer("5\x0135=0\x0110=161\x01")
        msg = parser.get_message()
        self.assertIsNotNone(msg)

        buf = parser.get_buffer()
        self.assertEqual(b"", buf)
        return

    def test_leading_junk_pairs(self):
        """Test that leading junk pairs are ignored."""
        parser = FixParser()
        parser.append_buffer("1=2\x013=4\x018=FIX.4.2\x01"
                             "9=5\x0135=0\x0110=161\x01")
        msg = parser.get_message()
        self.assertIsNotNone(msg)
        self.assertIsNone(msg.get(1))
        self.assertIsNone(msg.get(3))
        return

    def test_junk_pairs(self):
        """Test that complete junk paris are ignored."""
        parser = FixParser()
        parser.append_buffer("1=2\x013=4\x015=6\x01")
        msg = parser.get_message()
        self.assertIsNone(msg)
        return

    def test_raw_data(self):
        """Test parsing of raw data fields."""
        raw = b"raw\x01data"

        pkt = FixMessage()
        pkt.append_pair(8, "FIX.4.2")
        pkt.append_pair(35, "D")
        pkt.append_data(95, 96, raw)
        pkt.append_pair(20000, "private tag")
        buf = pkt.encode()

        parser = FixParser()
        parser.append_buffer(buf)
        msg = parser.get_message()

        self.assertIsNotNone(msg)
        self.assertEqual(b"FIX.4.2", msg.get(8))
        self.assertEqual(b"D", msg.get(35))
        self.assertEqual(len(raw), int(msg.get(95)))
        self.assertEqual(raw, msg.get(96))
        self.assertEqual(b"private tag", msg.get(20000))
        return

    def test_raw_data_tags(self):
        """Test functions to add and remove raw data tags."""
        raw = b"raw\x015000=1"

        pkt = FixMessage()
        pkt.append_pair(8, "FIX.4.2")
        pkt.append_pair(35, "D")
        pkt.append_data(5001, 5002, raw)
        pkt.append_pair(20000, "private tag")
        buf = pkt.encode()

        parser = FixParser()
        parser.add_raw(5001, 5002)
        parser.append_buffer(buf)
        msg = parser.get_message()

        self.assertIsNotNone(msg)
        self.assertEqual(b"FIX.4.2", msg.get(8))
        self.assertEqual(b"D", msg.get(35))
        self.assertEqual(len(raw), int(msg.get(5001)))
        self.assertEqual(raw, msg.get(5002))
        self.assertEqual(b"private tag", msg.get(20000))

        parser.reset()
        parser.remove_raw(5001, 5002)
        parser.append_buffer(buf)
        msg = parser.get_message()

        self.assertIsNotNone(msg)
        self.assertEqual(b"FIX.4.2", msg.get(8))
        self.assertEqual(b"D", msg.get(35))
        self.assertEqual(len(raw), int(msg.get(5001)))
        self.assertEqual(b"raw", msg.get(5002))
        self.assertEqual(b"1", msg.get(5000))
        self.assertEqual(b"private tag", msg.get(20000))
        return

    def test_embedded_equals_96_no_95(self):
        """Test a Logon with 96 but no 95, and an embedded equals."""

        raw = b"8=FIX.4.2" + SOH_STR + \
              b"9=169" + SOH_STR + \
              b"35=A" + SOH_STR + \
              b"52=20171213-01:41:08.063" + SOH_STR + \
              b"49=HelloWorld" + SOH_STR + \
              b"56=1234" + SOH_STR + \
              b"34=1" + SOH_STR + \
              b"96=ABC=DE" + SOH_STR + \
              b"98=0" + SOH_STR + \
              b"108=30" + SOH_STR + \
              b"554=HelloWorld" + SOH_STR + \
              b"8013=Y" + SOH_STR + \
              b"10=166" + SOH_STR

        parser = FixParser()
        parser.append_buffer(raw)
        msg = parser.get_message()

        self.assertIsNotNone(msg)
        return

    def test_eol_is_eom_after_soh(self):
        """Test parsing with EOL indicating EOM."""

        raw = b"8=FIX.4.2" + SOH_STR + \
              b"9=169" + SOH_STR + \
              b"35=A" + SOH_STR + \
              b"52=20171213-01:41:08.063" + SOH_STR + \
              b"49=HelloWorld" + SOH_STR + \
              b"56=1234" + SOH_STR + \
              b"34=1" + SOH_STR + \
              b"96=ABC=DE" + SOH_STR + \
              b"98=0" + SOH_STR + \
              b"108=30" + SOH_STR + \
              b"554=HelloWorld" + SOH_STR + \
              b"8013=Y" + SOH_STR + \
              b"\n" + \
              b"8=FIX.4,2" + SOH_STR

        parser = FixParser()
        parser.set_message_per_line()
        parser.append_buffer(raw)
        msg = parser.get_message()

        self.assertIsNotNone(msg)
        return

    def test_eol_is_eom_ends_last_field(self):
        """Test parsing with EOL indicating EOM."""

        raw = b"8=FIX.4.2" + SOH_STR + \
              b"9=169" + SOH_STR + \
              b"35=A" + SOH_STR + \
              b"52=20171213-01:41:08.063" + SOH_STR + \
              b"49=HelloWorld" + SOH_STR + \
              b"56=1234" + SOH_STR + \
              b"34=1" + SOH_STR + \
              b"96=ABC=DE" + SOH_STR + \
              b"98=0" + SOH_STR + \
              b"108=30" + SOH_STR + \
              b"554=HelloWorld" + SOH_STR + \
              b"8013=Y" + b"\n" + \
              b"8=FIX.4,2" + SOH_STR

        parser = FixParser()
        parser.set_message_per_line()
        parser.append_buffer(raw)
        msg = parser.get_message()

        self.assertIsNotNone(msg)
        return

    def test_cme_secdef(self):
        """Test parsing CME's secdef file."""

        raw = "35=d\x015799=00000000\x01980=A\x01779=20180408160519000025\x01" \
              "1180=310\x011300=64\x01462=5\x01207=XCME\x011151=ES\x01" \
              "6937=ES\x0155=ESM9\x0148=736\x0122=8\x01167=FUT\x01" \
              "461=FFIXSX\x01200=201906\x0115=USD\x011142=F\x01562=1\x01" \
              "1140=3000\x01969=25.0000000\x019787=0.0100000\x01996=IPNT\x01" \
              "1147=50.0000000\x011150=263175.0000000\x01731=00000111\x01" \
              "5796=20180406\x011149=275950.0000000\x01" \
              "1148=249950.0000000\x01" \
              "1143=600.0000000\x011146=12.5000000\x019779=N\x01864=2\x01" \
              "865=5\x011145=20180316133000000000\x01865=7\x01" \
              "1145=20190621133000000000\x011141=1\x011022=GBX\x01264=10\x01" \
              "870=1\x01871=24\x01872=00000000000001000010000000001111\x01" \
              "1234=0\x01\n" \
              "35=d\x015799=00000000\x01980=A\x01779=20180408160519000025\x01" \
              "1180=310\x011300=64\x01462=5\x01207=XCME\x011151=ES\x01" \
              "6937=ES\x0155=ESM8-ESZ8\x0148=1691\x0122=8\x01167=FUT\x01" \
              "461=FMIXSX\x01200=201806\x0115=USD\x01762=EQ\x019779=N\x01" \
              "1142=F\x01562=1\x011140=7500\x01969=5.0000000\x01" \
              "9787=0.0100000\x01996=CTRCT\x011150=810.0000000\x01" \
              "731=00000011\x015796=20180406\x011143=150.0000000\x01864=2\x01" \
              "865=5\x011145=20170915133000000000\x01865=7\x01" \
              "1145=20180615133000000000\x011141=1\x011022=GBX\x01264=10\x01" \
              "870=1\x01871=24\x01872=00000000000001000010010000001011\x01" \
              "1234=0\x01555=2\x01602=23252\x01603=8\x01624=2\x01623=1\x01" \
              "602=16114\x01603=8\x01624=1\x01623=1\x01\n" \
              "35=d\x015799=00000000\x01980=A\x01779=20180408160519000025\x01" \
              "1180=310\x011300=64\x01462=5\x01207=XCME\x011151=ES\x01" \
              "6937=ES\x0155=ESU8-ESZ8\x0148=2171\x0122=8\x01167=FUT\x01" \
              "461=FMIXSX\x01200=201809\x0115=USD\x01762=EQ\x019779=N\x01" \
              "1142=F\x01562=1\x011140=7500\x01969=5.0000000\x01" \
              "9787=0.0100000\x01996=CTRCT\x011150=370.0000000\x01" \
              "731=00000011\x015796=20180406\x011143=150.0000000\x01" \
              "864=2\x01865=5\x011145=20170915133000000000\x01865=7\x01" \
              "1145=20180921133000000000\x011141=1\x011022=GBX\x01264=10\x01" \
              "870=1\x01871=24\x01872=00000000000001000010010000001011\x01" \
              "1234=0\x01555=2\x01602=57287\x01603=8\x01624=2\x01623=1\x01" \
              "602=16114\x01603=8\x01624=1\x01623=1\x01\n" \
              "35=d\x015799=00000000\x01980=A\x01779=20180408160519000025\x01" \
              "1180=310\x011300=64\x01462=5\x01207=XCME\x011151=ES\x01" \
              "6937=ES\x0155=ESU8-ESH9\x0148=7293\x0122=8\x01167=FUT\x01" \
              "461=FMIXSX\x01200=201809\x0115=USD\x01762=EQ\x019779=N\x01" \
              "1142=F\x01562=1\x011140=7500\x01969=5.0000000\x01" \
              "9787=0.0100000\x01996=CTRCT\x011150=1040.0000000\x01" \
              "731=00000011\x015796=20180406\x011143=150.0000000\x01" \
              "864=2\x01865=5\x011145=20171215143000000000\x01865=7\x01" \
              "1145=20180921133000000000\x011141=1\x011022=GBX\x01264=10\x01" \
              "870=1\x01871=24\x01872=00000000000001000010010000001011\x01" \
              "1234=0\x01555=2\x01602=57287\x01603=8\x01624=2\x01623=1\x01" \
              "602=18720\x01603=8\x01624=1\x01623=1\x01\n"

        parser = FixParser()
        parser.set_message_per_line(True)
        parser.set_start_with_begin_string(False)
        parser.append_buffer(raw)
        msg = parser.get_message()

        self.assertIsNotNone(msg)
        return

# b"2018-05-06 12:34:56.789 RECV "


if __name__ == "__main__":
    unittest.main()
