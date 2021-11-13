from typing import Dict, Tuple, List, Union
from dataclasses import dataclass
import xml.etree.ElementTree as ET
import ctypes
import collections


@dataclass
class ProcessorSpec:
    programcounter: str = None

    # TODO: properties
    # TODO: data_space
    # TODO: inferptrbounds
    # TODO: segmented_address
    # TODO: segmentop_type
    # TODO: context_data
    # TODO: volatile
    # TODO: incidentalcopy
    # TODO: jumpassist
    # TODO: register_data
    # TODO: default_symbols
    # TODO: default_memory_blocks

    def xml(self):
        f = ET.Element("processor_spec")
        if self.programcounter is not None:
            e = ET.Element("programcounter",
                           attrib=dict(register=self.programcounter))
            f.append(e)
        return f

    def __str__(self):
        return ET.tostring(self.xml()).decode('ascii')


@dataclass
class RegisterType:
    name: str

    def xml(self):
        return ET.Element("register", attrib=dict(name=self.name))


@dataclass
class AddrType:
    space: str
    offset: int = None
    piece1: int = None
    piece2: int = None
    piece3: int = None
    piece4: int = None

    def xml(self):
        f = ET.Element("addr", attrib=dict(space=self.space))
        if self.offset is not None:
            f.attrib["offset"] = str(self.offset)
        if self.piece1 is not None:
            f.attrib["piece1"] = str(self.piece1)
        if self.piece2 is not None:
            f.attrib["piece2"] = str(self.piece2)
        if self.piece3 is not None:
            f.attrib["piece3"] = str(self.piece3)
        if self.piece4 is not None:
            f.attrib["piece4"] = str(self.piece4)
        return f

    def fromxml(doc):
        assert doc.tag == "addr"
        space = doc.attrib['space']
        offset = None
        piece1 = None
        piece2 = None
        piece3 = None
        piece4 = None
        if "offset" in doc.attrib:
            offset = int(doc.attrib['offset'], 16)
        if "piece1" in doc.attrib:
            piece1 = int(doc.attrib['piece1'], 16)
        if "piece2" in doc.attrib:
            piece2 = int(doc.attrib['piece2'], 16)
        if "piece3" in doc.attrib:
            piece3 = int(doc.attrib['piece3'], 16)
        if "piece4" in doc.attrib:
            piece4 = int(doc.attrib['piece4'], 16)
        if "size" in doc.attrib:
            size = int(doc.attrib['size'], 16)
        return AddrType(
            space=space,
            offset=offset,
            piece1=piece1,
            piece2=piece2,
            piece3=piece3,
            piece4=piece4,
        )

    def __str__(self):
        return ET.tostring(self.xml()).decode('ascii')


@dataclass
class RangeType:
    space: str
    first: int = None
    last: int = None

    def xml(self):
        f = ET.Element("range", attrib=dict(space=self.space))
        f.attrib['space'] = self.space
        if self.first is not None and self.last is not None:
            f.attrib['first'] = str(self.first)
            f.attrib['last'] = str(self.last)
        return f


@dataclass
class Pentry:
    entry: Union[RegisterType, AddrType]
    maxsize: int = None
    minsize: int = None
    align: int = None
    metatype: str = None
    extension: str = None

    # TODO trial

    def xml(self):
        f = ET.Element("pentry")
        if self.minsize is not None:
            f.attrib['minsize'] = str(self.minsize)
        if self.maxsize is not None:
            f.attrib['maxsize'] = str(self.maxsize)
        if self.align is not None:
            f.attrib['align'] = str(self.align)
        if self.metatype is not None:
            f.attrib['metatype'] = self.metatype
        if self.extension is not None:
            f.attrib['extension'] = self.extension
        f.append(self.entry.xml())
        return f


@dataclass
class VarnodeType:
    space: str
    offset: int
    size: int

    def xml(self):
        return ET.Element("varnode",
                          attrib=dict(space=self.space,
                                      offset=str(self.offset),
                                      size=str(self.size)))


@dataclass
class Prototype:
    @dataclass
    class Input:
        pentry: List[Pentry]

        # TODO: pointermax
        # TODO: thisbeforetpointer
        # TODO: killedbycall

        def xml(self):
            f = ET.Element("input")
            for i in self.pentry:
                f.append(i.xml())
            return f

    @dataclass
    class Output:
        pentry: List[Pentry]

        # TODO: killedbycall

        def xml(self):
            f = ET.Element("output")
            for i in self.pentry:
                f.append(i.xml())
            return f

    extrapop: int
    stackshift: int
    name: int
    input: Input
    output: Output
    unaffected: List[Union[RegisterType, VarnodeType]] = None
    killedbycall: List[Union[RegisterType, VarnodeType]] = None
    likelytrash: List[Union[RegisterType, VarnodeType]] = None

    # TODO: pcode
    # TODO: localrange
    # TODO: type_
    # TODO: strategy
    # TODO: hasthis
    # TODO: constructor
    # TODO: returnaddress

    def xml(self):
        f = ET.Element("prototype",
                       attrib=dict(extrapop=str(self.extrapop),
                                   stackshift=str(self.stackshift),
                                   name=self.name))
        f.append(self.input.xml())
        f.append(self.output.xml())
        if self.unaffected is not None:
            e = ET.Element("unaffected")
            for i in self.unaffected:
                e.append(i.xml())
            f.append(e)
        if self.killedbycall is not None:
            e = ET.Element("killedbycall")
            for i in self.killedbycall:
                e.append(i.xml())
            f.append(e)
        if self.likelytrash is not None:
            e = ET.Element("likelytrash")
            for i in self.likelytrash:
                e.append(i.xml())
            f.append(e)
        return f


@dataclass
class CompilerSpec:
    @dataclass
    class StackPointer:
        register: str
        space: str
        growth: str = None
        reversejustify: bool = None

        def xml(self):
            f = ET.Element("stackpointer")
            f.attrib['register'] = self.register
            f.attrib['space'] = self.space
            if self.growth is not None:
                f.attrib['growth'] = self.growth
            if self.reversejustify is not None:
                f.attrib['reversejustify'] = self.growth
            return f

    @dataclass
    class SpaceBase:
        name: str
        register: str
        space: str

        def xml(self):
            f = ET.Element("spacebase")
            f.attrib['name'] = self.name
            f.attrib['register'] = self.register
            f.attrib['space'] = self.space
            return f

    @dataclass
    class Global:
        memory_tags_type: List[Union[RegisterType, RangeType]]

        def xml(self):
            f = ET.Element("global")
            for i in self.memory_tags_type:
                f.append(i.xml())
            return f

    @dataclass
    class DeadcodeDelay:
        space: str
        delay: int

        def xml(self):
            return ET.Element("deadcodedelay",
                              attrib=dict(space=self.space,
                                          delay=str(self.delay)))

    default_proto: Prototype
    prototype: List[Prototype] = None
    stackpointer: StackPointer = None
    spacebase: List[SpaceBase] = None
    global_: Global = None
    deadcodedelay: List[DeadcodeDelay] = None

    # TODO: properties_type
    # TODO: data_organization
    # TODO: callfixup
    # TODO: callotherfixup
    # TODO: context_data
    # TODO: enum
    # TODO: prefersplit
    # TODO: aggressivetrim
    # TODO: nohighptr
    # TODO: returnaddress
    # TODO: funcptr
    # TODO: inferptrbounds
    # TODO: segmentop_type
    # TODO: resolveprototype
    # TODO: eval_current_prototype
    # TODO: eval_called_prototype

    def xml(self):
        f = ET.Element("compiler_spec")
        if self.stackpointer is not None:
            f.append(self.stackpointer.xml())
        if self.global_ is not None:
            f.append(self.global_.xml())
        if self.default_proto is not None:
            e = ET.Element("default_proto")
            e.append(self.default_proto.xml())
            f.append(e)
        if self.spacebase is not None:
            for i in self.spacebase:
                f.append(i.xml())
        if self.prototype is not None:
            e = ET.Element("prototypes")
            for i in self.prototype:
                e.append(i.xml())
            f.append(e)
        if self.deadcodedelay is not None:
            for i in self.deadcodedelay:
                f.append(i.xml())
        return f

    def __str__(self):
        return ET.tostring(self.xml()).decode('ascii')


@dataclass
class Space:
    name: str
    index: int
    size: int
    bigendian: bool
    delay: int
    physical: bool
    global_: bool

    def xml(self):
        f = ET.Element("space",
                       attrib=dict(
                           name=self.name,
                           index=str(self.index),
                           size=str(self.size),
                           bigendian=str(self.bigendian).lower(),
                           delay=str(self.delay),
                           physical=str(self.physical).lower(),
                       ))
        f.attrib['global'] = str(self.global_).lower()
        return f


@dataclass
class OtherSpace(Space):
    def xml(self):
        f = ET.Element("space_other",
                       attrib=dict(
                           name=self.name,
                           index=str(self.index),
                           size=str(self.size),
                           bigendian=str(self.bigendian).lower(),
                           delay=str(self.delay),
                           physical=str(self.physical).lower(),
                       ))
        f.attrib['global'] = str(self.global_).lower()
        return f


@dataclass
class UniqueSpace(Space):
    def xml(self):
        f = ET.Element("space_unique",
                       attrib=dict(
                           name=self.name,
                           index=str(self.index),
                           size=str(self.size),
                           bigendian=str(self.bigendian).lower(),
                           delay=str(self.delay),
                           physical=str(self.physical).lower(),
                       ))
        f.attrib['global'] = str(self.global_).lower()
        return f


@dataclass
class SleighSpec:
    @dataclass
    class Spaces:
        defaultspace: str
        spaces: List[Union[Space, OtherSpace, UniqueSpace]]

        def xml(self):
            f = ET.Element("spaces",
                           attrib=dict(defaultspace=self.defaultspace))
            for i in self.spaces:
                f.append(i.xml())
            return f

    bigendian: bool
    uniqbase: int
    spaces: Spaces

    def xml(self):
        f = ET.Element("sleigh",
                       attrib=dict(bigendian=str(self.bigendian),
                                   uniqbase=hex(self.uniqbase)))
        f.append(self.spaces.xml())
        return f

    def __str__(self):
        return ET.tostring(self.xml()).decode('ascii')


@dataclass
class TrackedPointSet:
    space: str
    offset: int
    addrs: List[Tuple[AddrType, int, int]]

    def xml(self):
        f = ET.Element("tracked_pointset",
                       attrib=dict(space=self.space, offset=str(self.offset)))
        for (a, s, v) in self.addrs:
            r = a.xml()
            r.attrib['size'] = str(s)
            r.attrib['val'] = str(v)
            f.append(r)
        return f


@dataclass
class Label:
    name: str
    addr: int

    def __post_init__(self):
        self.label = "{}_{}".format(self.name, hex(self.addr))


@dataclass
class SpaceId:
    space: str


@dataclass
class VarNode:
    size: int
    space: str
    offs: int

    def __post_init__(self):
        self.offs = ctypes.c_uint(self.offs).value

    def __str__(self):
        return "({}, {}, {})".format(self.space, hex(self.offs),
                                     hex(self.size))

    def __hash__(self):
        return hash(self.size) ^ hash(self.space) ^ hash(self.offs)


@dataclass
class PcodeOp:
    op: int
    inrefs: List[Union[SpaceId, VarNode, Label]]
    outref: VarNode = None


class Ast:
    def __init__(self, r):
        funcs = r.findall("function")
        self.name = funcs[0].attrib['name']
        addrs = r.findall("function/ast/varnodes/addr")
        self.vn = dict()
        for i in addrs:
            space = i.attrib['space']
            ref = int(i.attrib['ref'], 16)
            offs = int(i.attrib['offset'], 16)
            size = int(i.attrib['size'])
            if space == "const":
                space = "constant"
            self.vn[ref] = VarNode(size, space, offs)

        def xml2opnd(r):
            if r.tag == "void":
                return None
            if r.tag == "addr":
                return self.vn[int(r.attrib['ref'], 16)]
            if r.tag == "spaceid":
                return SpaceId(r.attrib["name"])
            if r.tag == "iop":
                return VarNode(0, "iop", int(r.attrib['value'], 16))
            raise Exception("NYI tag {}".format(ET.tostring(r)))

        self.blocks = dict()
        block = r.findall("function/ast/block")
        for i in block:
            pcode = []
            for ops in i.findall("op"):
                op = int(ops.attrib['code'])
                opnd = list(ops)
                seqnum = (opnd[0].attrib['offset'], opnd[0].attrib['space'],
                          opnd[0].attrib['uniq'])
                outref = xml2opnd(opnd[1])
                inrefs = list(map(xml2opnd, opnd[2:]))
                pcode.append(PcodeOp(op, inrefs, outref))
            self.blocks[int(i.attrib['index'])] = (pcode, seqnum)

        self.edges = collections.defaultdict(lambda: set())
        edges = r.findall("function/ast/blockedge")
        for i in edges:
            idx = int(i.attrib['index'])
            for j in i.findall("edge"):
                end = int(j.attrib['end'])
                rev = int(j.attrib['rev'])
                self.edges[end].add((idx, rev))
