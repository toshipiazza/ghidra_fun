from pwn import *
import sys
import wadze
from ghidra import Decompiler
from ghidra_types import *
from pcode import *
import pprint
import random
import string
from multiprocessing import Pool

context.log_level = 'ERROR'

# TODO: f32.const
# TODO: f32.demote_f64
# TODO: f64.const
# TODO: f64.store
# TODO: i32.trunc_f64_s
# TODO: i32.trunc_f64_u
# TODO: i64.reinterpret_f64

from pygments import highlight
from pygments.lexers import XmlLexer, CLexer
from pygments.formatters import Terminal256Formatter

STACK_PTR_IDX = 18
STACK_TOP_IDX = 19


class Wasm:
    def __init__(self, prog):
        # initialize program
        with open(prog, 'rb') as raw:
            raw = raw.read()
        self.wasm_bytes = raw
        self.wasm = wadze.parse_module(self.wasm_bytes)
        self.wasm['code'] = [wadze.parse_code(c) for c in self.wasm['code']]

        # initialize structures required for decompiler
        self.pspec = ProcessorSpec()
        self.coretype = """<coretypes>
          <void/>
          <type name="code" size="1" metatype="code" id="-9223371462259126427"/>
          <type name="bool" size="1" metatype="bool" id="-9151688804115639865"/>
          <type name="char" size="1" metatype="int" char="true" id="-9223091865880322087"/>
          <type name="i8" size="1" metatype="int" id="-9151688846347870363"/>
          <type name="i16" size="2" metatype="int" id="-9185691276929259553"/>
          <type name="i32" size="4" metatype="int" id="-9223370945157383201"/>
          <type name="i64" size="8" metatype="int" id="-9151648190019025561"/>
          <type name="f32" size="4" metatype="float" id="-120139017508053025"/>
          <type name="f64" size="8" metatype="float" id="-6087405195602966429"/>
        </coretypes>"""

        default_proto = Prototype(
            name="__stdcall",
            extrapop=0,
            stackshift=0,
            input=Prototype.Input(pentry=[
                Pentry(minsize=1, maxsize=8, entry=RegisterType(name="a0")),
                Pentry(minsize=1, maxsize=8, entry=RegisterType(name="a1")),
                Pentry(minsize=1, maxsize=8, entry=RegisterType(name="a2")),
                Pentry(minsize=1, maxsize=8, entry=RegisterType(name="a3")),
                Pentry(minsize=1, maxsize=8, entry=RegisterType(name="a4")),
                Pentry(minsize=1, maxsize=8, entry=RegisterType(name="a5")),
            ]),
            output=Prototype.Output(pentry=[
                Pentry(minsize=1, maxsize=8, entry=RegisterType(name="r0")),
            ]),
            unaffected=[
                RegisterType(name="wasm_ptr"),
                RegisterType(name="prog_ptr"),
            ],
            killedbycall=[])
        self.cspec = CompilerSpec(
            stackpointer=CompilerSpec.StackPointer(register="wasm_ptr",
                                                   space="wasm",
                                                   growth="positive"),
            spacebase=[
                CompilerSpec.SpaceBase(name="prog_stack",
                                       register="prog_ptr",
                                       space="data"),
            ],
            deadcodedelay=[
                CompilerSpec.DeadcodeDelay(space="prog_stack", delay=1000)
            ],
            global_=CompilerSpec.Global(memory_tags_type=[
                RangeType(space="data"),
                RangeType(space="code"),
                RangeType(space="global"),
                RangeType(space="prog_stack"),
            ]),
            default_proto=default_proto)

        spaces = [
            OtherSpace(name="OTHER",
                       index=1,
                       size=4,
                       bigendian=False,
                       delay=0,
                       physical=True,
                       global_=True),
            UniqueSpace(name="unique",
                        index=2,
                        size=4,
                        bigendian=False,
                        delay=0,
                        physical=True,
                        global_=False),
            Space(name="code",
                  index=3,
                  size=4,
                  bigendian=False,
                  delay=0,
                  physical=True,
                  global_=True),
            Space(name="wasm",
                  index=4,
                  size=4,
                  bigendian=False,
                  delay=0,
                  physical=True,
                  global_=True),
            Space(name="args",
                  index=5,
                  size=4,
                  bigendian=False,
                  delay=0,
                  physical=True,
                  global_=True),
            Space(name="rets",
                  index=6,
                  size=4,
                  bigendian=False,
                  delay=0,
                  physical=True,
                  global_=True),
            Space(name="data",
                  index=7,
                  size=4,
                  bigendian=False,
                  delay=0,
                  physical=True,
                  global_=True),
            Space(name="regs",
                  index=8,
                  size=4,
                  bigendian=False,
                  delay=0,
                  physical=True,
                  global_=False),
            Space(name="global",
                  index=9,
                  size=4,
                  bigendian=False,
                  delay=0,
                  physical=True,
                  global_=False),
        ]
        self.tspec = SleighSpec(bigendian=False,
                                uniqbase=0x10000000,
                                spaces=SleighSpec.Spaces(defaultspace="data",
                                                         spaces=spaces))

        self.user_op_names = []

        # cache wasm stack
        self.wasm_sp = self._get_wasm_ptr()

    def get_register(self, reg):
        info("get_register {}".format(reg))

        # handle special stack pointers first
        if reg == "wasm_ptr":
            r = AddrType("regs", 0).xml()
            r.attrib['size'] = str(4)
            return r
        if reg == "prog_ptr":
            return self._get_global_offs(STACK_PTR_IDX)
        if reg == "prog_top":
            return self._get_global_offs(STACK_TOP_IDX)
        if reg == "ret_addr":
            r = AddrType("regs", 4).xml()
            r.attrib['size'] = str(4)
            return r

        # handle args and globals
        if reg[0] == "a":
            r = AddrType("args", int(reg[1]) * 8).xml()
            r.attrib['size'] = str(8)
            return r

        if reg[0] == "r":
            r = AddrType("rets", int(reg[1]) * 8).xml()
            r.attrib['size'] = str(8)
            return r

        if reg[0] == 'g':
            return self._get_global_offs(int(reg[1:]))

        raise Exception("NYI")

    def _get_size_type(self, globaltype):
        if isinstance(globaltype, wadze.GlobalType):
            t = globaltype.type
        elif isinstance(globaltype, str):
            t = globaltype
        else:
            raise Exception("NYI")

        if t == "i32":
            return 4
        if t == "i64":
            return 8
        if t == "f32":
            return 4
        if t == "f64":
            return 8
        raise Exception("Type NYI")

    def _get_wasm_ptr(self):
        return VarNode(4, "regs", 0)

    def _get_ret_addr(self):
        return VarNode(4, "regs", 4)

    def _get_global_idx(self, offs, size):
        idx = 0
        while True:
            x = self._get_global_offs(idx)
            if int(x.attrib['offset']) == offs:
                assert int(x.attrib['size']) == size
                return idx
            if int(x.attrib['offset']) > offs:
                break
            idx += 1
        raise Exception("Offs did not correspond to an idx")

    def _get_global_offs(self, global_idx):
        off = 0
        idx = 0

        # all global imports seem to come first, TODO: is this always the case
        for i in self.wasm['import']:
            if isinstance(i, wadze.ImportGlobal):
                if idx == global_idx:
                    r = AddrType("global", off).xml()
                    r.attrib['size'] = str(self._get_size_type(i.globaltype))
                    return r
                idx += 1
                off += self._get_size_type(i.globaltype)

        # next check static globals
        for i in self.wasm['global']:
            if idx == global_idx:
                r = AddrType("global", off).xml()
                r.attrib['size'] = str(self._get_size_type(i.globaltype))
                return r
            idx += 1
            off += self._get_size_type(i.globaltype)

        raise Exception("Global not found")

    def get_mapped_symbol_xml(self, space, offset):
        info("get_mapped_symbol_xml {} {}".format(space, hex(offset)))

        if space == "code":
            """
            Just create a function here.

            This is all guaranteed to be code, and get_mapped_symbol_xml is not
            called when referencing a new function, e.g. by call.

            This invariant is maintained by our pcode lifting.
            """
            function_template = """
            <result id="0x0">
              <mapsym>
                <function id="{id}" name="{name}" size="1">
                  <addr space="code" offset="{offset}"/>
                </function>
                <addr space="code" offset="{offset}" size="1"/>
                <rangelist/>
              </mapsym>
            </result>
            """
            return function_template.format(id=random.randint(0, 0xffffffff),
                                            name=self._get_func_name(offset),
                                            offset=hex(offset))

        if space == "data":
            data = self.wasm['data'][0].values
            # XXX pull this offset out of module
            if offset >= 1024 and len(data) > offset - 1024:
                s = self._check_string(data, offset - 1024)
                if s is not None:
                    strings_template = """
                    <result id="0x0">
                      <mapsym>
                        <symbol name="{}" typelock="true" namelock="true" readonly="true" merge="false" cat="-1">
                          <type name="" metatype="array" size="{}" arraysize="{}">
                            <typeref name="char"/>
                          </type>
                        </symbol>
                        <addr space="data" offset="{}" size="1"/>
                        <rangelist/>
                      </mapsym>
                    </result>
                    """
                    for i in range(len(s)):
                        if chr(i) == ord(b'\''):
                            s[i] = ord('_')
                    s = s.decode('ascii')
                    s = "'{}'".format(s)
                    info("Got string {}".format(s))
                    return strings_template.format(s, len(s), len(s), offset)

        hole_template = """
        <hole readonly="false" volatile="false" space="{space}" first="{a}" last="{a}" />
        """

        return hole_template.format(space=space, a=offset)

    def _check_string(self, data, off):
        r = bytearray()
        idx = 0
        while True:
            c = data[off + idx]
            if c == 0:
                break
            if chr(c) not in string.printable:
                return None
            r += bytearray([c])
            idx += 1
        if len(r) >= 2:
            return r
        else:
            return None

    def get_tracked_registers(self, space, offset):
        info("get_tracked_registers {} {}".format(space, hex(offset)))
        return TrackedPointSet(space=space, offset=offset, addrs=[]).xml()

    def _get_global_vn(self, idx):
        a = self._get_global_offs(idx)
        return VarNode(int(a.attrib['size']), "global",
                       int(a.attrib['offset']))

    def _insert_return(self, pcode, retvals):
        idx = 0
        for i in retvals:
            self._pop_pcode(pcode, self._get_ret(idx, self._get_size_type(i)))
        pcode.append(PcodeOp(CPUI_RETURN, [self._get_ret_addr()], None))

    def _push_pcode(self, pcode, vn):
        pcode.append(
            PcodeOp(CPUI_INT_ADD,
                    [self.wasm_sp, VarNode(4, "constant", 8)], self.wasm_sp))
        pcode.append(
            PcodeOp(CPUI_STORE, [SpaceId("wasm"), self.wasm_sp, vn], None))

    def _pop_pcode(self, pcode, vn):
        if vn is not None:
            pcode.append(
                PcodeOp(CPUI_LOAD, [SpaceId("wasm"), self.wasm_sp], vn))
        pcode.append(
            PcodeOp(CPUI_INT_SUB,
                    [self.wasm_sp, VarNode(4, "constant", 8)], self.wasm_sp))

    def _pcode_block(self, pcode, ops, locals_, retvals, labels):
        for i in ops:
            pcode.extend(self._translate_pcode(i, locals_, retvals, labels))

    def _do_call(self, pcode, op, args, vn):
        idx = len(args.params) - 1
        for a in args.params:
            arg = self._get_arg(idx, self._get_size_type(a))
            self._pop_pcode(pcode, arg)
            idx -= 1
        pcode.append(PcodeOp(op, [vn], None))
        idx = 0
        for a in args.returns:
            arg = self._get_ret(idx, self._get_size_type(a))
            self._push_pcode(pcode, arg)
            idx += 1

    unique_addr = 0

    def _unique_addr(self):
        self.unique_addr += 1
        return self.unique_addr

    def _translate_pcode(self, c, locals_, retvals, labels):
        debug(str(c))

        if c[0] == "global.set":
            pcode = []
            self._pop_pcode(pcode, self._get_global_vn(c[1]))
            return pcode

        if c[0] == "global.get":
            pcode = []
            self._push_pcode(pcode, self._get_global_vn(c[1]))
            return pcode

        if c[0] == "local.set":
            pcode = []
            self._pop_pcode(pcode, locals_[c[1]])
            return pcode

        if c[0] == "local.get":
            pcode = []
            self._push_pcode(pcode, locals_[c[1]])
            return pcode

        if c[0] == "i32.const":
            pcode = []
            self._push_pcode(pcode, VarNode(4, "constant", c[1]))
            return pcode

        if c[0] == "i64.const":
            pcode = []
            self._push_pcode(pcode, VarNode(8, "constant", c[1]))
            return pcode

        if c[0] == "i32.ge_s":
            pcode = []
            a = self._uniq_varnode(4)
            b = self._uniq_varnode(4)
            c = self._uniq_varnode(1)
            self._pop_pcode(pcode, b)
            self._pop_pcode(pcode, a)
            pcode.append(PcodeOp(CPUI_INT_SLESS, [a, b], c))
            pcode.append(
                PcodeOp(CPUI_INT_EQUAL, [c, VarNode(4, "constant", 0)], c))
            self._push_pcode(pcode, c)
            return pcode

        if c[0] == "i32.ge_u":
            pcode = []
            a = self._uniq_varnode(4)
            b = self._uniq_varnode(4)
            c = self._uniq_varnode(1)
            self._pop_pcode(pcode, b)
            self._pop_pcode(pcode, a)
            pcode.append(PcodeOp(CPUI_INT_LESS, [a, b], c))
            pcode.append(
                PcodeOp(CPUI_INT_EQUAL, [c, VarNode(4, "constant", 0)], c))
            self._push_pcode(pcode, c)
            return pcode

        if c[0] == "i32.gt_s":
            pcode = []
            a = self._uniq_varnode(4)
            b = self._uniq_varnode(4)
            c = self._uniq_varnode(1)
            self._pop_pcode(pcode, b)
            self._pop_pcode(pcode, a)
            pcode.append(PcodeOp(CPUI_INT_SLESSEQUAL, [a, b], c))
            pcode.append(
                PcodeOp(CPUI_INT_EQUAL, [c, VarNode(4, "constant", 0)], c))
            self._push_pcode(pcode, c)
            return pcode

        if c[0] == "i64.gt_s":
            pcode = []
            a = self._uniq_varnode(8)
            b = self._uniq_varnode(8)
            c = self._uniq_varnode(1)
            self._pop_pcode(pcode, b)
            self._pop_pcode(pcode, a)
            pcode.append(PcodeOp(CPUI_INT_SLESSEQUAL, [a, b], c))
            pcode.append(
                PcodeOp(CPUI_INT_EQUAL, [c, VarNode(8, "constant", 0)], c))
            self._push_pcode(pcode, c)
            return pcode

        if c[0] == "i32.gt_u":
            pcode = []
            a = self._uniq_varnode(4)
            b = self._uniq_varnode(4)
            c = self._uniq_varnode(1)
            self._pop_pcode(pcode, b)
            self._pop_pcode(pcode, a)
            pcode.append(PcodeOp(CPUI_INT_LESSEQUAL, [a, b], c))
            pcode.append(
                PcodeOp(CPUI_INT_EQUAL, [c, VarNode(4, "constant", 0)], c))
            self._push_pcode(pcode, c)
            return pcode

        if c[0] == "i64.gt_u":
            pcode = []
            a = self._uniq_varnode(8)
            b = self._uniq_varnode(8)
            c = self._uniq_varnode(1)
            self._pop_pcode(pcode, b)
            self._pop_pcode(pcode, a)
            pcode.append(PcodeOp(CPUI_INT_LESSEQUAL, [a, b], c))
            pcode.append(
                PcodeOp(CPUI_INT_EQUAL, [c, VarNode(8, "constant", 0)], c))
            self._push_pcode(pcode, c)
            return pcode

        if c[0] == "i32.lt_s":
            pcode = []
            a = self._uniq_varnode(4)
            b = self._uniq_varnode(4)
            c = self._uniq_varnode(1)
            self._pop_pcode(pcode, b)
            self._pop_pcode(pcode, a)
            pcode.append(PcodeOp(CPUI_INT_SLESS, [a, b], c))
            self._push_pcode(pcode, c)
            return pcode

        if c[0] == "i64.lt_s":
            pcode = []
            a = self._uniq_varnode(8)
            b = self._uniq_varnode(8)
            c = self._uniq_varnode(1)
            self._pop_pcode(pcode, b)
            self._pop_pcode(pcode, a)
            pcode.append(PcodeOp(CPUI_INT_SLESS, [a, b], c))
            self._push_pcode(pcode, c)
            return pcode

        if c[0] == "i32.le_s":
            pcode = []
            a = self._uniq_varnode(4)
            b = self._uniq_varnode(4)
            c = self._uniq_varnode(1)
            self._pop_pcode(pcode, b)
            self._pop_pcode(pcode, a)
            pcode.append(PcodeOp(CPUI_INT_SLESSEQUAL, [a, b], c))
            self._push_pcode(pcode, c)
            return pcode

        if c[0] == "i32.lt_u":
            pcode = []
            a = self._uniq_varnode(4)
            b = self._uniq_varnode(4)
            c = self._uniq_varnode(1)
            self._pop_pcode(pcode, b)
            self._pop_pcode(pcode, a)
            pcode.append(PcodeOp(CPUI_INT_LESS, [a, b], c))
            self._push_pcode(pcode, c)
            return pcode

        if c[0] == "i32.le_u":
            pcode = []
            a = self._uniq_varnode(4)
            b = self._uniq_varnode(4)
            c = self._uniq_varnode(1)
            self._pop_pcode(pcode, b)
            self._pop_pcode(pcode, a)
            pcode.append(PcodeOp(CPUI_INT_LESSEQUAL, [a, b], c))
            self._push_pcode(pcode, c)
            return pcode

        if c[0] == "i32.ne":
            pcode = []
            a = self._uniq_varnode(4)
            b = self._uniq_varnode(4)
            c = self._uniq_varnode(1)
            self._pop_pcode(pcode, a)
            self._pop_pcode(pcode, b)
            pcode.append(PcodeOp(CPUI_INT_NOTEQUAL, [a, b], c))
            self._push_pcode(pcode, c)
            return pcode

        if c[0] == "i32.eq":
            pcode = []
            a = self._uniq_varnode(4)
            b = self._uniq_varnode(4)
            c = self._uniq_varnode(1)
            self._pop_pcode(pcode, a)
            self._pop_pcode(pcode, b)
            pcode.append(PcodeOp(CPUI_INT_EQUAL, [a, b], c))
            self._push_pcode(pcode, c)
            return pcode

        if c[0] == "i64.eq":
            pcode = []
            a = self._uniq_varnode(8)
            b = self._uniq_varnode(8)
            c = self._uniq_varnode(1)
            self._pop_pcode(pcode, a)
            self._pop_pcode(pcode, b)
            pcode.append(PcodeOp(CPUI_INT_EQUAL, [a, b], c))
            self._push_pcode(pcode, c)
            return pcode

        if c[0] == "i64.ne":
            pcode = []
            a = self._uniq_varnode(8)
            b = self._uniq_varnode(8)
            c = self._uniq_varnode(1)
            self._pop_pcode(pcode, a)
            self._pop_pcode(pcode, b)
            pcode.append(PcodeOp(CPUI_INT_NOTEQUAL, [a, b], c))
            self._push_pcode(pcode, c)
            return pcode

        if c[0] == "i32.eqz":
            pcode = []
            a = self._uniq_varnode(4)
            c = self._uniq_varnode(1)
            self._pop_pcode(pcode, a)
            pcode.append(
                PcodeOp(CPUI_INT_EQUAL, [a, VarNode(4, "constant", 0)], c))
            self._push_pcode(pcode, c)
            return pcode

        if c[0] == "i32.add":
            pcode = []
            a = self._uniq_varnode(4)
            b = self._uniq_varnode(4)
            c = self._uniq_varnode(4)
            self._pop_pcode(pcode, a)
            self._pop_pcode(pcode, b)
            pcode.append(PcodeOp(CPUI_INT_ADD, [a, b], c))
            self._push_pcode(pcode, c)
            return pcode

        if c[0] == "i64.add":
            pcode = []
            a = self._uniq_varnode(8)
            b = self._uniq_varnode(8)
            c = self._uniq_varnode(8)
            self._pop_pcode(pcode, a)
            self._pop_pcode(pcode, b)
            pcode.append(PcodeOp(CPUI_INT_ADD, [a, b], c))
            self._push_pcode(pcode, c)
            return pcode

        if c[0] == "i32.shl":
            pcode = []
            a = self._uniq_varnode(4)
            b = self._uniq_varnode(4)
            c = self._uniq_varnode(4)
            self._pop_pcode(pcode, a)
            self._pop_pcode(pcode, b)
            pcode.append(PcodeOp(CPUI_INT_LEFT, [a, b], c))
            self._push_pcode(pcode, c)
            return pcode

        if c[0] == "i64.shl":
            pcode = []
            a = self._uniq_varnode(8)
            b = self._uniq_varnode(8)
            c = self._uniq_varnode(8)
            self._pop_pcode(pcode, a)
            self._pop_pcode(pcode, b)
            pcode.append(PcodeOp(CPUI_INT_LEFT, [a, b], c))
            self._push_pcode(pcode, c)
            return pcode

        if c[0] == "i32.shr_s":
            pcode = []
            a = self._uniq_varnode(4)
            b = self._uniq_varnode(4)
            c = self._uniq_varnode(4)
            self._pop_pcode(pcode, a)
            self._pop_pcode(pcode, b)
            pcode.append(PcodeOp(CPUI_INT_SRIGHT, [a, b], c))
            self._push_pcode(pcode, c)
            return pcode

        if c[0] == "i32.shr_u":
            pcode = []
            a = self._uniq_varnode(4)
            b = self._uniq_varnode(4)
            c = self._uniq_varnode(4)
            self._pop_pcode(pcode, a)
            self._pop_pcode(pcode, b)
            pcode.append(PcodeOp(CPUI_INT_RIGHT, [a, b], c))
            self._push_pcode(pcode, c)
            return pcode

        if c[0] == "i64.shr_u":
            pcode = []
            a = self._uniq_varnode(8)
            b = self._uniq_varnode(8)
            c = self._uniq_varnode(8)
            self._pop_pcode(pcode, a)
            self._pop_pcode(pcode, b)
            pcode.append(PcodeOp(CPUI_INT_RIGHT, [a, b], c))
            self._push_pcode(pcode, c)
            return pcode

        if c[0] == "i32.sub":
            pcode = []
            a = self._uniq_varnode(4)
            b = self._uniq_varnode(4)
            c = self._uniq_varnode(4)
            self._pop_pcode(pcode, b)
            self._pop_pcode(pcode, a)
            pcode.append(PcodeOp(CPUI_INT_SUB, [a, b], c))
            self._push_pcode(pcode, c)
            return pcode

        if c[0] == "i64.sub":
            pcode = []
            a = self._uniq_varnode(8)
            b = self._uniq_varnode(8)
            c = self._uniq_varnode(8)
            self._pop_pcode(pcode, b)
            self._pop_pcode(pcode, a)
            pcode.append(PcodeOp(CPUI_INT_SUB, [a, b], c))
            self._push_pcode(pcode, c)
            return pcode

        if c[0] == "i32.div_s":
            pcode = []
            a = self._uniq_varnode(4)
            b = self._uniq_varnode(4)
            c = self._uniq_varnode(4)
            self._pop_pcode(pcode, b)
            self._pop_pcode(pcode, a)
            pcode.append(PcodeOp(CPUI_INT_SDIV, [a, b], c))
            self._push_pcode(pcode, c)
            return pcode

        if c[0] == "i32.div_u":
            pcode = []
            a = self._uniq_varnode(4)
            b = self._uniq_varnode(4)
            c = self._uniq_varnode(4)
            self._pop_pcode(pcode, b)
            self._pop_pcode(pcode, a)
            pcode.append(PcodeOp(CPUI_INT_DIV, [a, b], c))
            self._push_pcode(pcode, c)
            return pcode

        if c[0] == "i64.div_u":
            pcode = []
            a = self._uniq_varnode(8)
            b = self._uniq_varnode(8)
            c = self._uniq_varnode(8)
            self._pop_pcode(pcode, b)
            self._pop_pcode(pcode, a)
            pcode.append(PcodeOp(CPUI_INT_DIV, [a, b], c))
            self._push_pcode(pcode, c)
            return pcode

        if c[0] == "i32.rem_s":
            pcode = []
            a = self._uniq_varnode(4)
            b = self._uniq_varnode(4)
            c = self._uniq_varnode(4)
            self._pop_pcode(pcode, b)
            self._pop_pcode(pcode, a)
            pcode.append(PcodeOp(CPUI_INT_SREM, [a, b], c))
            self._push_pcode(pcode, c)
            return pcode

        if c[0] == "i32.rem_u":
            pcode = []
            a = self._uniq_varnode(4)
            b = self._uniq_varnode(4)
            c = self._uniq_varnode(4)
            self._pop_pcode(pcode, b)
            self._pop_pcode(pcode, a)
            pcode.append(PcodeOp(CPUI_INT_REM, [a, b], c))
            self._push_pcode(pcode, c)
            return pcode

        if c[0] == "i32.mul":
            pcode = []
            a = self._uniq_varnode(4)
            b = self._uniq_varnode(4)
            c = self._uniq_varnode(4)
            self._pop_pcode(pcode, b)
            self._pop_pcode(pcode, a)
            pcode.append(PcodeOp(CPUI_INT_MULT, [a, b], c))
            self._push_pcode(pcode, c)
            return pcode

        if c[0] == "i64.mul":
            pcode = []
            a = self._uniq_varnode(8)
            b = self._uniq_varnode(8)
            c = self._uniq_varnode(8)
            self._pop_pcode(pcode, b)
            self._pop_pcode(pcode, a)
            pcode.append(PcodeOp(CPUI_INT_MULT, [a, b], c))
            self._push_pcode(pcode, c)
            return pcode

        if c[0] == "i32.and":
            pcode = []
            a = self._uniq_varnode(4)
            b = self._uniq_varnode(4)
            c = self._uniq_varnode(4)
            self._pop_pcode(pcode, a)
            self._pop_pcode(pcode, b)
            pcode.append(PcodeOp(CPUI_INT_AND, [a, b], c))
            self._push_pcode(pcode, c)
            return pcode

        if c[0] == "i64.and":
            pcode = []
            a = self._uniq_varnode(8)
            b = self._uniq_varnode(8)
            c = self._uniq_varnode(8)
            self._pop_pcode(pcode, a)
            self._pop_pcode(pcode, b)
            pcode.append(PcodeOp(CPUI_INT_AND, [a, b], c))
            self._push_pcode(pcode, c)
            return pcode

        if c[0] == "i32.xor":
            pcode = []
            a = self._uniq_varnode(4)
            b = self._uniq_varnode(4)
            c = self._uniq_varnode(4)
            self._pop_pcode(pcode, a)
            self._pop_pcode(pcode, b)
            pcode.append(PcodeOp(CPUI_INT_XOR, [a, b], c))
            self._push_pcode(pcode, c)
            return pcode

        if c[0] == "i32.or":
            pcode = []
            a = self._uniq_varnode(4)
            b = self._uniq_varnode(4)
            c = self._uniq_varnode(4)
            self._pop_pcode(pcode, a)
            self._pop_pcode(pcode, b)
            pcode.append(PcodeOp(CPUI_INT_OR, [a, b], c))
            self._push_pcode(pcode, c)
            return pcode

        if c[0] == "i64.or":
            pcode = []
            a = self._uniq_varnode(8)
            b = self._uniq_varnode(8)
            c = self._uniq_varnode(8)
            self._pop_pcode(pcode, a)
            self._pop_pcode(pcode, b)
            pcode.append(PcodeOp(CPUI_INT_OR, [a, b], c))
            self._push_pcode(pcode, c)
            return pcode

        if c[0] == "drop":
            pcode = []
            self._pop_pcode(pcode, None)
            return pcode

        if c[0] == "nop":
            pcode = []
            return pcode

        if c[0] == "if":
            # assert c[1] is None
            t, f = c[2]

            do_if = Label("do_if", self._unique_addr())
            endbr = Label("endbr", self._unique_addr())
            if_f = Label("if_f_end", self._unique_addr())
            if_t = Label("if_t_end", self._unique_addr())

            pcode = []
            c = self._uniq_varnode(1)
            self._pop_pcode(pcode, c)
            pcode.append(PcodeOp(CPUI_CBRANCH, [do_if, c], None))

            labels.append(if_f)
            self._pcode_block(pcode, f, locals_, retvals, labels)
            pcode.append(if_f)
            labels.pop()

            pcode.append(PcodeOp(CPUI_BRANCH, [endbr, c], None))
            pcode.append(do_if)

            labels.append(if_t)
            self._pcode_block(pcode, t, locals_, retvals, labels)
            pcode.append(if_t)
            labels.pop()

            pcode.append(endbr)
            return pcode

        if c[0] == "br":
            assert c[1] < len(labels)
            pcode = []
            pcode.append(PcodeOp(CPUI_BRANCH, [labels[-c[1] - 1]], None))
            return pcode

        if c[0] == "br_if":
            assert c[1] < len(labels)
            pcode = []
            c = self._uniq_varnode(1)
            self._pop_pcode(pcode, c)
            pcode.append(PcodeOp(CPUI_CBRANCH, [-labels[c[1] - 1], c], None))
            return pcode

        if c[0] == "block":
            b = c[2]
            pcode = []
            l = Label("block", self._unique_addr())
            labels.append(l)
            self._pcode_block(pcode, b, locals_, retvals, labels)
            pcode.append(l)  # jump to end of a block
            labels.pop()
            return pcode

        if c[0] == "loop":
            b = c[2]
            pcode = []
            l = Label("loop", self._unique_addr())
            labels.append(l)
            pcode.append(l)  # jump to top of loop
            self._pcode_block(pcode, b, locals_, retvals, labels)
            labels.pop()
            return pcode

        if c[0] == "call":
            pcode = []
            _, args = self._get_func_idx(c[1])
            self._do_call(pcode, CPUI_CALL, args, VarNode(0, "code", c[1]))
            return pcode

        if c[0] == "call_indirect":
            # local.get of c[2]
            _, args = self._get_func_idx(c[1])
            pcode = []
            c = self._uniq_varnode(4)
            self._pop_pcode(pcode, c)
            self._do_call(pcode, CPUI_CALLIND, args, c)
            return pcode

        if c[0] == "i32.load":
            pcode = []
            c = self._uniq_varnode(4)
            self._pop_pcode(pcode, c)
            pcode.append(PcodeOp(CPUI_LOAD, [SpaceId("data"), c], c))
            self._push_pcode(pcode, c)
            return pcode

        if c[0] == "i64.load":
            pcode = []
            c = self._uniq_varnode(8)
            self._pop_pcode(pcode, c)
            pcode.append(PcodeOp(CPUI_LOAD, [SpaceId("data"), c], c))
            self._push_pcode(pcode, c)
            return pcode

        if c[0] == "i32.load8_s":
            pcode = []
            c = self._uniq_varnode(4)
            d = self._uniq_varnode(1)
            e = self._uniq_varnode(4)
            self._pop_pcode(pcode, c)
            pcode.append(PcodeOp(CPUI_LOAD, [SpaceId("data"), c], d))
            pcode.append(PcodeOp(CPUI_INT_SEXT, [d], e))
            self._push_pcode(pcode, e)
            return pcode

        if c[0] == "i32.load16_s":
            pcode = []
            c = self._uniq_varnode(4)
            d = self._uniq_varnode(2)
            e = self._uniq_varnode(4)
            self._pop_pcode(pcode, c)
            pcode.append(PcodeOp(CPUI_LOAD, [SpaceId("data"), c], d))
            pcode.append(PcodeOp(CPUI_INT_SEXT, [d], e))
            self._push_pcode(pcode, e)
            return pcode

        if c[0] == "unreachable":
            pcode = []
            loop = Label("unreachable", self._unique_addr())
            pcode.append(loop)
            pcode.append(PcodeOp(CPUI_BRANCH, [loop], None))
            return pcode

        if c[0] == "i32.store":
            pcode = []
            c = self._uniq_varnode(4)
            v = self._uniq_varnode(4)
            self._pop_pcode(pcode, v)
            self._pop_pcode(pcode, c)
            pcode.append(PcodeOp(CPUI_STORE, [SpaceId("data"), c, v], None))
            return pcode

        if c[0] == "i32.store16":
            pcode = []
            c = self._uniq_varnode(4)
            v = self._uniq_varnode(4)
            d = self._uniq_varnode(2)
            self._pop_pcode(pcode, v)
            self._pop_pcode(pcode, c)
            pcode.append(
                PcodeOp(CPUI_SUBPIECE, [v, VarNode(4, "constant", 2)], d))
            pcode.append(PcodeOp(CPUI_STORE, [SpaceId("data"), c, d], None))
            return pcode

        if c[0] == "i32.wrap_i64":
            pcode = []
            c = self._uniq_varnode(8)
            d = self._uniq_varnode(4)
            self._pop_pcode(pcode, c)
            pcode.append(
                PcodeOp(CPUI_SUBPIECE, [c, VarNode(4, "constant", 4)], d))
            self._push_pcode(pcode, d)
            return pcode

        if c[0] == "i64.extend_i32_s":
            pcode = []
            c = self._uniq_varnode(4)
            d = self._uniq_varnode(8)
            self._pop_pcode(pcode, c)
            pcode.append(PcodeOp(CPUI_INT_SEXT, [c], d))
            self._push_pcode(pcode, d)
            return pcode

        if c[0] == "i64.extend_i32_u":
            pcode = []
            c = self._uniq_varnode(4)
            d = self._uniq_varnode(8)
            self._pop_pcode(pcode, c)
            pcode.append(PcodeOp(CPUI_INT_ZEXT, [c], d))
            self._push_pcode(pcode, d)
            return pcode

        if c[0] == "i32.store8":
            pcode = []
            c = self._uniq_varnode(4)
            v = self._uniq_varnode(4)
            d = self._uniq_varnode(1)
            self._pop_pcode(pcode, v)
            self._pop_pcode(pcode, c)
            pcode.append(
                PcodeOp(CPUI_SUBPIECE, [v, VarNode(4, "constant", 1)], d))
            pcode.append(PcodeOp(CPUI_STORE, [SpaceId("data"), c, d], None))
            return pcode

        if c[0] == "i64.store":
            pcode = []
            c = self._uniq_varnode(4)
            v = self._uniq_varnode(8)
            self._pop_pcode(pcode, v)
            self._pop_pcode(pcode, c)
            pcode.append(PcodeOp(CPUI_STORE, [SpaceId("data"), c, v], None))
            return pcode

        if c[0] == "return":
            pcode = []
            self._insert_return(pcode, retvals)
            return pcode

        warn("Unimplemented instruction {}".format(c[0]))
        raise Exception("NYI")

    def _get_func_name(self, idx):
        # count the number of function imports; ignore them
        c = 0
        for i in self.wasm['import']:
            if isinstance(i, wadze.ImportFunction):
                if idx == c:
                    return "{}_{}".format(i.module, i.name).replace(" ", "")
                c += 1
        for i in self.wasm['export']:
            if isinstance(i, wadze.ExportFunction):
                if i.ref == idx:
                    return i.name
        return "func_{}".format(hex(idx))

    def _get_func_idx(self, idx):
        # count the number of function imports; ignore them
        c = 0
        for i in self.wasm['import']:
            if isinstance(i, wadze.ImportFunction):
                if idx == c:
                    args = self.wasm['type'][i.typeidx]
                    return None, args
                c += 1
        func = self.wasm['code'][idx - c]
        args = self.wasm['type'][self.wasm['func'][idx - c]]
        return func, args

    def _get_arg(self, idx, size):
        return VarNode(size, "args", idx * 8)

    def _get_ret(self, idx, size):
        return VarNode(size, "rets", idx * 8)

    _uniq_offs = 0

    def _uniq_varnode(self, size):
        node = VarNode(size, "unique", self._uniq_offs)
        self._uniq_offs += size
        return node

    def get_packed(self, space, offset):
        info("get_packed {} {}".format(space, hex(offset)))

        assert space == "code"
        func, args = self._get_func_idx(offset)
        if func is None:
            raise Exception("Can't get code for imported function")

        spaces = {i.name: i.index for i in self.tspec.spaces.spaces}
        spaces['constant'] = 0

        # create all local varnodes
        pcode = []
        locals_ = []
        offs = 0

        # all arguments are treated as local variables so generate loads for
        # those first
        idx = 0
        for a in args.params:
            size = self._get_size_type(a)
            node = self._uniq_varnode(size)
            pcode.append(PcodeOp(CPUI_COPY, [self._get_arg(idx, size)], node))
            locals_.append(node)
            offs += size
            idx += 1

        # local variables are all written before they are read so don't bother
        # generating loads
        for i in func.locals:
            size = self._get_size_type(i)
            node = self._uniq_varnode(size)
            locals_.append(node)
            offs += size

        # generate pcode for each instruction
        try:
            for c in func.instructions:
                pcode.extend(
                    self._translate_pcode(c, locals_, args.returns, []))
        except Exception as e:
            if str(e) != "NYI":
                raise
            return unimplemented("code", 1, offset, spaces)
        if isinstance(pcode[-1], Label) or pcode[-1].op != CPUI_RETURN:
            # XXX: sometimes functions aren't terminated...
            self._insert_return(pcode, args.returns)
        debug(self._debug_pcode(pcode))
        return pack_pcode("code", 1, offset, pcode, spaces)

    def _debug_pcode(self, pcode):
        ret = ""
        for i in pcode:
            ret += "{}\n".format(self._print_opcode(i))
        return ret

    def _print_opcode(self, pcode):
        def _print_varnode(v):
            if v.space == "constant":
                return "{}".format(v.offs)
            return "({}, {}, {})".format(v.size, v.space, v.offs)

        if isinstance(pcode, Label):
            pre = "  "
            tokens = [pcode.label + ":"]
        else:
            pre = "    "
            tokens = []
            if pcode.outref is not None:
                tokens.append(_print_varnode(pcode.outref))
                tokens.append("=")
            tokens.append(op2str[pcode.op])
            for inref in pcode.inrefs:
                if isinstance(inref, VarNode):
                    tokens.append(_print_varnode(inref))
                elif isinstance(inref, Label):
                    tokens.append(inref.label)
        return pre + " ".join(tokens)

    def get_register_name(self, space, offset, size):
        info("get_register_name {} {} {}".format(space, hex(offset), size))

        if space == "global":
            if offset == int(
                    self._get_global_offs(
                        STACK_PTR_IDX).attrib['offset']) and size == 4:
                return "prog_ptr"
            if offset == int(
                    self._get_global_offs(
                        STACK_TOP_IDX).attrib['offset']) and size == 4:
                return "prog_top"
            return "g{}".format(self._get_global_idx(offset, size))

        if space == "regs":
            if offset == 0:
                return "wasm_ptr"
            if offset == 4:
                return "ret_addr"
            raise Exception("NYI")

        return ""

    def get_comments(self, space, offset, flags):
        info("get_comments {} {} {}".format(space, hex(offset), flags))
        return """<commentdb></commentdb>"""

    def get_string(self, space, offs, size, type_, id_):
        assert space == "data"
        assert offs > 1024
        data = self.wasm['data'][0].values
        s = self._check_string(data, offs - 1024)
        assert s is not None
        return s


def print_c(r, color=True):

    # convert to xml
    r = ET.fromstring(r)

    # convert xml to C, by stripping the tags
    f = list(r)[1]
    f = " ".join(
        list(
            map(lambda x: x.text
                if x.text is not None else "", f.getiterator())))

    # run the horribly mangled "C" through clang-format
    p = subprocess.Popen("clang-format",
                         stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE)
    code, _ = p.communicate(f.encode())
    if color:
        return highlight(code, CLexer(), Terminal256Formatter())
    else:
        return code.decode('ascii')


def print_ast_graphviz(h, r):
    from graphviz import Digraph

    r = ET.fromstring(r)
    ast = Ast(r)

    # build graphviz graph
    dot = Digraph()
    dot.attr(dpi="400")
    for i in ast.blocks:
        dot.node(str(i),
                 h._debug_pcode(ast.blocks[i][0]).replace("\n", "\l"),
                 shape="box")
    for i in ast.edges:
        for j, r in ast.edges[i]:
            if r == 1:
                dot.edge(str(i), str(j), color="green")
            else:
                dot.edge(str(i), str(j))
    dot.view(quiet=True, quiet_view=True, cleanup=True, filename=ast.name)


def main():
    w = Wasm(sys.argv[1])
    d = Decompiler(w, debug=len(sys.argv) == 3 and sys.argv[2] == 'd')
    archid, _ = d.register_program()

    interesting_funcs = [
        0x06e,  # infinite do-while looe
        0x06f,  # _htons return value ignored
        0x276,  # getString
        0x106,  # regs
    ]
    for i in interesting_funcs:
        r, _ = d.decompile_at(archid, AddrType(space="code", offset=i))
        print(print_c(r))
        # print_ast_graphviz(w, r)


if __name__ == '__main__':
    main()
