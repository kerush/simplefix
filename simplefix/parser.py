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

from .constants import EQUALS_BYTE, SOH_BYTE
from .message import FixMessage, fix_val
from .data import RAW_DATA_TAGS, RAW_LEN_TAGS

CR = b"\r"
LF = b"\n"
CRLF = CR + LF


class FixParser(object):
    """FIX protocol message parser.

    This class translates FIX application messages in raw (wire)
    format into instance of the FixMessage class.

    It does not perform any validation of the fields, their presence
    or absence in a particular message, the data types of fields, or
    the values of enumerations.

    It is suitable for streaming processing, accumulating byte data
    from a network connection, and returning complete messages as they
    are delivered, potentially in multiple fragments."""

    def __init__(self):
        """Constructor."""

        # Internal buffer used to accumulate message data.
        self.buf = b""

        # Parsed "tag=value" pairs, removed from the buffer, but not
        # yet returned as a message.
        self.pairs = []

        # Copy raw field length tags.
        self.raw_len_tags = RAW_LEN_TAGS[:]

        # Copy raw field data tags.
        self.raw_data_tags = RAW_DATA_TAGS[:]

        # Behaviour flags.
        self.raise_exceptions = False
        self.eol_is_eom = False
        self.ignore_leading_text = False
        self.validate_checksum = False
        return

    def set_error_exceptions(self, value=True):
        """Set whether to raise exceptions for parsing errors.

        :param value: If True, raise exceptions for parsing errors.

        If False (the default), parsing errors cause messages to be silently
        discarded.  Otherwise, exceptions will be thrown describing the
        detected issue."""
        pass

    def set_message_per_line(self, value=True):
        """If set, each line of text is treated as a separate message.

        :param value: If True, treat each line as message.

        When parsing log files, it's common to use the end-of-line as a
        message boundary, in some cases omitting the CheckSum(10) field
        as well.  The setting will cause the parser to treat any of CR,
        LF, or CRLF as the message boundary."""
        self.eol_is_eom = value
        return

    def set_ignore_leading_text(self, start="8=FIX."):
        """Ignore any characters prior to the specified start string.

        :param start: Any character prior to this are ignored.

        This is typically useful when parsing a FIX log file, which will
        often have a timestamp and direction prepended to the actual
        message content.

        The default value matches the required first tag-value for
        standard FIX messages."""
        pass

    def set_validate_checksum(self, value=True):
        """Ensure that the FIX checksum value is correct.

        :param value: If True, validate checksun; otherwise ignore it.

        If set, messages must have a CheckSum (10) field as the last
        field in the message, and its value must be a 3-digit decimal
        integer, which will be used to validate the content of the
        message as specified by the FIX standards.

        If set, and validation fails, get_message() will return None or
        throw an exception, depending on the parser configuration."""
        pass

    def add_raw(self, length_tag, value_tag):
        """Define the tags used for a private raw data field.

        :param length_tag: tag number of length field.
        :param value_tag: tag number of value field.

        Data fields are not terminated by the SOH character as is usual for
        FIX, but instead have a second, preceding field that specifies the
        length of the value in bytes.  The parser is initialised with all the
        data fields defined in FIX.5.0, but if your application uses private
        data fields, you can add them here, and the parser will process them
        correctly. """

        self.raw_len_tags.append(length_tag)
        self.raw_data_tags.append(value_tag)
        return

    def remove_raw(self, length_tag, value_tag):
        """Remove the tags for a data type field.

        :param length_tag: tag number of the length field.
        :param value_tag: tag number of the value field.

        You can remove either private or standard data field definitions in
        case a particular application uses them for a field of a different
        type. """

        self.raw_len_tags.remove(length_tag)
        self.raw_data_tags.remove(value_tag)
        return

    def reset(self):
        """Reset the internal parser state.

        This will discard any appended buffer content, and any fields
        parsed so far."""

        self.buf = b""
        self.pairs = []
        return

    def append_buffer(self, buf):
        """Append a byte string to the parser buffer.

        :param buf: byte string to append.

        The parser maintains an internal buffer of bytes to be parsed.
        As raw data is read, it can be appended to this buffer.  Each
        call to get_message() will try to remove the bytes of a
        complete messages from the head of the buffer."""
        self.buf += fix_val(buf)
        return

    def get_buffer(self):
        """Return a reference to the internal buffer."""
        return self.buf

    def get_message(self):
        """Process the accumulated buffer and return the first message.

        If the buffer starts with FIX fields other than BeginString
        (8), these are discarded until the start of a message is
        found.

        If no BeginString (8) field is found, this function returns
        None.  Similarly, if (after a BeginString) no Checksum (10)
        field is found, the function returns None.

        Otherwise, it returns a simplefix.FixMessage instance
        initialised with the fields from the first complete message
        found in the buffer."""

        # Break buffer into tag=value pairs.
        start = 0
        point = 0
        in_tag = True
        raw_len = 0
        tag = 0
        eom = False

        while point < len(self.buf):
            b = self.buf[point]
            if in_tag and b == EQUALS_BYTE:
                tag_string = self.buf[start:point]
                point += 1

                tag = int(tag_string)
                if tag in self.raw_data_tags and raw_len > 0:
                    if raw_len > len(self.buf) - point:
                        break

                    value = self.buf[point:point+raw_len]
                    self.pairs.append((tag, value))
                    self.buf = self.buf[point + raw_len + 1:]
                    point = 0
                    raw_len = 0
                    start = point

                else:
                    in_tag = False
                    start = point

            elif b == SOH_BYTE or (self.eol_is_eom and b in CRLF):
                value = self.buf[start:point]
                self.pairs.append((tag, value))
                self.buf = self.buf[point + 1:]
                point = 0
                start = point
                in_tag = True

                if tag in self.raw_len_tags:
                    raw_len = int(value)

                if self.eol_is_eom and b in CRLF:
                    eom = True
                    break

            elif in_tag and self.eol_is_eom and b in CRLF:
                break

            point += 1


        if len(self.pairs) == 0:
            return None

        # Check first pair is FIX BeginString.
        while self.pairs and self.pairs[0][0] != 8:
            # Discard pairs until we find the beginning of a message.
            self.pairs.pop(0)

        if len(self.pairs) == 0:
            return None

        # Look for end of message.
        if eom:
            index = len(self.pairs) - 1
        else:
            index = 0
            while index < len(self.pairs) and self.pairs[index][0] != 10:
                index += 1

            if index == len(self.pairs):
                return None

        # Extract message.
        m = FixMessage()
        pairs = self.pairs[:index + 1]
        for tag, value in pairs:
            m.append_pair(tag, value)
        self.pairs = self.pairs[index + 1:]

        return m


########################################################################
