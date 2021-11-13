from pwn import *
from ghidra_types import AddrType
import xml.etree.ElementTree as ET


class Decompiler:

    COMMAND_BEG = 2
    COMMAND_END = 3
    QUERY_BEG = 4
    QUERY_END = 5
    COMMAND_RESPONSE_BEG = 6
    COMMAND_RESPONSE_END = 7
    QUERY_RESPONSE_BEG = 8
    QUERY_RESPONSE_END = 9
    EXCEPTION_BEG = 10
    EXCEPTION_END = 11
    BYTE_STREAM_BEG = 12
    BYTE_STREAM_END = 13
    STRING_STREAM_BEG = 14
    STRING_STREAM_END = 15
    WARNING_STREAM_BEG = 16
    WARNING_STREAM_END = 17

    def __init__(self, plugin, debug):
        self.plugin = plugin
        g = os.path.dirname(os.path.realpath(__file__))
        g, _ = os.path.split(g)
        g = os.path.join(g, "bin")
        g = os.path.join(g, "ghidra_dbg")
        self.p = process(g)
        if debug:
            context.log_level = 'DEBUG'
            gdb.attach(self.p)

    def __del__(self):
        self.p.close()

    def _read_to_any_burst(self):
        while True:
            c = self.p.read(1)
            if c == b'\x00':
                break
        while True:
            c = self.p.read(1)
            if c != b'\x00':
                break
        assert c == b'\x01'
        return self.p.read(1)

    def _read_to_buffer(self, buf):
        while True:
            c = self.p.read(1)
            if c == b'\x00':
                break
            buf.extend(c)
        while True:
            c = self.p.read(1)
            if c != b'\x00':
                break
        assert c == b'\x01'
        return self.p.read(1)

    def _read_string_stream(self):
        c = self._read_to_any_burst()
        assert ord(c) == self.STRING_STREAM_BEG
        return self._read_string_stream_no_burst()

    def _read_string_stream_no_burst(self):
        res = b""
        while True:
            c = self.p.read(1)
            if c == b"\x00":
                break
            res += c
        while c == b"\x00":
            c = self.p.read(1)
        assert c == b"\x01"
        c = self.p.read(1)
        assert ord(c) == self.STRING_STREAM_END
        return res.decode('ascii')

    def _read_warning_stream(self):
        c = self._read_to_any_burst()
        assert ord(c) == self.WARNING_STREAM_BEG
        res = b""
        while True:
            c = self.p.read(1)
            if c == b"\x00":
                break
            res += c
        while c == b"\x00":
            c = self.p.read(1)
        assert c == b"\x01"
        c = self.p.read(1)
        assert ord(c) == self.WARNING_STREAM_END
        return res.decode('ascii')

    def _write_burst(self, code):
        self.p.write(b"\x00\x00\x01" + code.to_bytes(1, 'little'))

    def _write_string(self, s):
        self._write_burst(self.STRING_STREAM_BEG)
        self.p.write(s.encode('ascii'))
        self._write_burst(self.STRING_STREAM_END)

    def _write_bytes(self, s):
        self._write_burst(self.BYTE_STREAM_BEG)
        self.p.write(s)
        self._write_burst(self.BYTE_STREAM_END)

    def _get_user_op_name(self):
        op_idx = int(self._read_string_stream())
        c = self._read_to_any_burst()
        assert ord(c) == self.QUERY_END
        self._write_burst(self.QUERY_RESPONSE_BEG)
        if op_idx == len(self.plugin.user_op_names):
            self._write_string("")
        else:
            self._write_string(self.plugin.user_op_names[op_idx])
        self._write_burst(self.QUERY_RESPONSE_END)

    def _get_register(self):
        reg_id = self._read_string_stream()
        c = self._read_to_any_burst()
        assert ord(c) == self.QUERY_END
        self._write_burst(self.QUERY_RESPONSE_BEG)
        self._write_string(
            ET.tostring(self.plugin.get_register(reg_id)).decode('ascii'))
        self._write_burst(self.QUERY_RESPONSE_END)

    def _get_mapped_symbols_xml(self):
        doc = ET.fromstring(self._read_string_stream())
        addr = AddrType.fromxml(doc)
        c = self._read_to_any_burst()
        assert ord(c) == self.QUERY_END
        self._write_burst(self.QUERY_RESPONSE_BEG)
        self._write_string(
            self.plugin.get_mapped_symbol_xml(addr.space, addr.offset))
        self._write_burst(self.QUERY_RESPONSE_END)

    def _get_tracked_registers(self):
        doc = ET.fromstring(self._read_string_stream())
        addr = AddrType.fromxml(doc)
        c = self._read_to_any_burst()
        assert ord(c) == self.QUERY_END
        self._write_burst(self.QUERY_RESPONSE_BEG)
        self._write_string(
            ET.tostring(
                self.plugin.get_tracked_registers(
                    addr.space, addr.offset)).decode('ascii'))
        self._write_burst(self.QUERY_RESPONSE_END)

    def _get_register_name(self):
        doc = ET.fromstring(self._read_string_stream())
        addr = AddrType.fromxml(doc)
        c = self._read_to_any_burst()
        assert ord(c) == self.QUERY_END
        self._write_burst(self.QUERY_RESPONSE_BEG)
        self._write_string(
            self.plugin.get_register_name(addr.space, addr.offset,
                                          int(doc.attrib['size'])))
        self._write_burst(self.QUERY_RESPONSE_END)

    def _get_packed(self):
        doc = ET.fromstring(self._read_string_stream())
        addr = AddrType.fromxml(doc)
        c = self._read_to_any_burst()
        assert ord(c) == self.QUERY_END
        self._write_burst(self.QUERY_RESPONSE_BEG)
        self._write_string(
            self.plugin.get_packed(addr.space, addr.offset).decode('ascii'))
        self._write_burst(self.QUERY_RESPONSE_END)

    def _get_comments(self):
        doc = ET.fromstring(self._read_string_stream())
        addr = AddrType.fromxml(doc)
        flags = int(self._read_string_stream())
        c = self._read_to_any_burst()
        assert ord(c) == self.QUERY_END
        self._write_burst(self.QUERY_RESPONSE_BEG)
        self._write_string(
            self.plugin.get_comments(addr.space, addr.offset, flags))
        self._write_burst(self.QUERY_RESPONSE_END)

    def _get_type(self):
        type_ = self._read_string_stream()
        id_ = self._read_string_stream()
        raise Exception("NYI")

    def _escape_string(self, s, truncated=False):
        # DecompileProcess.java (getStringData)
        sz = len(s) + 1
        sz1 = (sz & 0x3f) + 0x20
        sz >>= 6
        sz2 = (sz & 0x3f) + 0x20

        b = b""
        b += struct.pack("bb", sz1, sz2)
        if truncated:
            b += b"\x01"
        else:
            b += b"\x00"

        for i in s:
            b += struct.pack("bb", ((i >> 4) & 0xf) + 65, (i & 0xf) + 65)
        b += b"AA"  # NULL Terminator

        return b

    def _get_string(self):
        doc = ET.fromstring(self._read_string_stream())
        addr = AddrType.fromxml(doc)
        type_ = self._read_string_stream()
        id_ = self._read_string_stream()
        c = self._read_to_any_burst()
        assert ord(c) == self.QUERY_END
        self._write_burst(self.QUERY_RESPONSE_BEG)
        s = self.plugin.get_string(addr.space, addr.offset,
                                   int(doc.attrib['size']), type_, id_)
        if s is not None:
            self._write_bytes(self._escape_string(s))
        self._write_burst(self.QUERY_RESPONSE_END)

    def _read_response(self):
        res = ""
        wrn = ""
        buf = None

        # wait for a COMMAND_RESPONSE_BEG and subsequent queries
        c = self._read_to_any_burst()
        assert ord(c) == self.COMMAND_RESPONSE_BEG

        # See DecompileProcess::readResponse in the original
        # DecompileProcess.java
        c = self._read_to_any_burst()
        while ord(c) != self.COMMAND_RESPONSE_END:
            if ord(c) == self.QUERY_BEG:
                # handle decompiler queries until we see a STRING_STREAM_BEG
                query = self._read_string_stream()
                if query == "getUserOpName":
                    self._get_user_op_name()
                elif query == "getRegister":
                    self._get_register()
                elif query == "getMappedSymbolsXML":
                    self._get_mapped_symbols_xml()
                elif query == "getTrackedRegisters":
                    self._get_tracked_registers()
                elif query == "getRegisterName":
                    self._get_register_name()
                elif query == "getPacked":
                    self._get_packed()
                elif query == "getComments":
                    self._get_comments()
                elif query == "getType":
                    self._get_type()
                elif query == "getString":
                    self._get_string()
                else:
                    raise Exception("NYI {}".format(query))
            elif ord(c) == self.EXCEPTION_BEG:
                raise Exception("NYI")
                typ = self._read_string_stream()
                msg = self._read_string_stream()
                c = self._read_to_any_burst()
                assert ord(c) == self.EXCEPTION_END
                raise Exception("Decompiler exception {}: {}".format(typ, msg))
            elif ord(c) == self.STRING_STREAM_BEG:
                assert buf is None
                buf = bytearray()
            elif ord(c) == self.STRING_STREAM_END:
                res = buf.decode('ascii')
                buf = None
            elif ord(c) == self.WARNING_STREAM_BEG:
                assert buf is None
                buf = bytearray()
            elif ord(c) == self.WARNING_STREAM_END:
                wrn = buf.decode('ascii')
                buf = None
            else:
                assert False

            if buf is None:
                c = self._read_to_any_burst()
            else:
                c = self._read_to_buffer(buf)

        if wrn != "":
            warn(wrn)

        return res, wrn

    def register_program(self):
        # send arguments
        self._write_burst(self.COMMAND_BEG)
        self._write_string("registerProgram")
        self._write_string(str(self.plugin.pspec))
        self._write_string(str(self.plugin.cspec))
        self._write_string(str(self.plugin.tspec))
        self._write_string(str(self.plugin.coretype))
        self._write_burst(self.COMMAND_END)

        # read rest of the response
        return self._read_response()

    def decompile_at(self, archid, addr):
        # send arguments
        self._write_burst(self.COMMAND_BEG)
        self._write_string("decompileAt")
        self._write_string(str(archid))
        self._write_string(str(addr))
        self._write_burst(self.COMMAND_END)

        # read rest of the response
        return self._read_response()

    def set_action(self, archid, action_string, print_string):

        if action_string != "":
            assert action_string in [
                "decompile", "jumptable", "normalize", "paramid", "register",
                "firstpass"
            ]

        if print_string != "":
            assert print_string in [
                "tree", "notree", "c", "noc", "parammeasures",
                "noparammeasures", "jumpload", "nojumpload"
            ]

        self._write_burst(self.COMMAND_BEG)
        self._write_string("setAction")
        self._write_string(str(archid))
        self._write_string(action_string)
        self._write_string(print_string)
        self._write_burst(self.COMMAND_END)

        # read rest of the response
        return self._read_response()
