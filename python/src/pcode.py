from typing import List, Union
from dataclasses import dataclass
import struct
import ctypes
from ghidra_types import *

CPUI_COPY = 1
CPUI_LOAD = 2
CPUI_STORE = 3
CPUI_BRANCH = 4
CPUI_CBRANCH = 5
CPUI_BRANCHIND = 6
CPUI_CALL = 7
CPUI_CALLIND = 8
CPUI_CALLOTHER = 9
CPUI_RETURN = 10
CPUI_INT_EQUAL = 11
CPUI_INT_NOTEQUAL = 12
CPUI_INT_SLESS = 13
CPUI_INT_SLESSEQUAL = 14
CPUI_INT_LESS = 15
CPUI_INT_LESSEQUAL = 16
CPUI_INT_ZEXT = 17
CPUI_INT_SEXT = 18
CPUI_INT_ADD = 19
CPUI_INT_SUB = 20
CPUI_INT_CARRY = 21
CPUI_INT_SCARRY = 22
CPUI_INT_SBORROW = 23
CPUI_INT_2COMP = 24
CPUI_INT_NEGATE = 25
CPUI_INT_XOR = 26
CPUI_INT_AND = 27
CPUI_INT_OR = 28
CPUI_INT_LEFT = 29
CPUI_INT_RIGHT = 30
CPUI_INT_SRIGHT = 31
CPUI_INT_MULT = 32
CPUI_INT_DIV = 33
CPUI_INT_SDIV = 34
CPUI_INT_REM = 35
CPUI_INT_SREM = 36
CPUI_BOOL_NEGATE = 37
CPUI_BOOL_XOR = 38
CPUI_BOOL_AND = 39
CPUI_BOOL_OR = 40
CPUI_FLOAT_EQUAL = 41
CPUI_FLOAT_NOTEQUAL = 42
CPUI_FLOAT_LESS = 43
CPUI_FLOAT_LESSEQUAL = 44
CPUI_FLOAT_NAN = 46
CPUI_FLOAT_ADD = 47
CPUI_FLOAT_DIV = 48
CPUI_FLOAT_MULT = 49
CPUI_FLOAT_SUB = 50
CPUI_FLOAT_NEG = 51
CPUI_FLOAT_ABS = 52
CPUI_FLOAT_SQRT = 53
CPUI_FLOAT_INT2FLOAT = 54
CPUI_FLOAT_FLOAT2FLOAT = 55
CPUI_FLOAT_TRUNC = 56
CPUI_FLOAT_CEIL = 57
CPUI_FLOAT_FLOOR = 58
CPUI_FLOAT_ROUND = 59
CPUI_MULTIEQUAL = 60
CPUI_INDIRECT = 61
CPUI_PIECE = 62
CPUI_SUBPIECE = 63
CPUI_CAST = 64
CPUI_PTRADD = 65
CPUI_PTRSUB = 66
CPUI_SEGMENTOP = 67
CPUI_CPOOLREF = 68
CPUI_NEW = 69
CPUI_INSERT = 70
CPUI_EXTRACT = 71
CPUI_POPCOUNT = 72

op2str = {
    1: "COPY",
    2: "LOAD",
    3: "STORE",
    4: "BRANCH",
    5: "CBRANCH",
    6: "BRANCHIND",
    7: "CALL",
    8: "CALLIND",
    9: "CALLOTHER",
    10: "RETURN",
    11: "INT_EQUAL",
    12: "INT_NOTEQUAL",
    13: "INT_SLESS",
    14: "INT_SLESSEQUAL",
    15: "INT_LESS",
    16: "INT_LESSEQUAL",
    17: "INT_ZEXT",
    18: "INT_SEXT",
    19: "INT_ADD",
    20: "INT_SUB",
    21: "INT_CARRY",
    22: "INT_SCARRY",
    23: "INT_SBORROW",
    24: "INT_2COMP",
    25: "INT_NEGATE",
    26: "INT_XOR",
    27: "INT_AND",
    28: "INT_OR",
    29: "INT_LEFT",
    30: "INT_RIGHT",
    31: "INT_SRIGHT",
    32: "INT_MULT",
    33: "INT_DIV",
    34: "INT_SDIV",
    35: "INT_REM",
    36: "INT_SREM",
    37: "BOOL_NEGATE",
    38: "BOOL_XOR",
    39: "BOOL_AND",
    40: "BOOL_OR",
    41: "FLOAT_EQUAL",
    42: "FLOAT_NOTEQUAL",
    43: "FLOAT_LESS",
    44: "FLOAT_LESSEQUAL",
    46: "FLOAT_NAN",
    47: "FLOAT_ADD",
    48: "FLOAT_DIV",
    49: "FLOAT_MULT",
    50: "FLOAT_SUB",
    51: "FLOAT_NEG",
    52: "FLOAT_ABS",
    53: "FLOAT_SQRT",
    54: "FLOAT_INT2FLOAT",
    55: "FLOAT_FLOAT2FLOAT",
    56: "FLOAT_TRUNC",
    57: "FLOAT_CEIL",
    58: "FLOAT_FLOOR",
    59: "FLOAT_ROUND",
    60: "MULTIEQUAL",
    61: "INDIRECT",
    62: "PIECE",
    63: "SUBPIECE",
    64: "CAST",
    65: "PTRADD",
    66: "PTRSUB",
    67: "SEGMENTOP",
    68: "CPOOLREF",
    69: "NEW",
    70: "INSERT",
    71: "EXTRACT",
    72: "POPCOUNT",
}


unimpl_tag = 0x20
inst_tag = 0x21
op_tag = 0x22
void_tag = 0x23
spaceid_tag = 0x24
addrsz_tag = 0x25
end_tag = 0x60


def pack_offs(offs):
    r = b""
    # every 6 bits maps to one byte
    while offs > 0:
        bits = offs & 0b111111
        offs >>= 6
        r += struct.pack("b", bits + 0x20)
    r += struct.pack("b", end_tag)
    return r


def pack_size(offs):
    r = b""
    # every 6 bits maps to one byte
    for _ in range(4):
        bits = offs & 0b111111
        offs >>= 6
        r += struct.pack("b", bits + 0x20)
    return r


def pack_varnode_data(v, space_map, pcode=None, i=None):
    r = b""
    if isinstance(v, VarNode):
        r += struct.pack("b", addrsz_tag)
        r += struct.pack("b", space_map[v.space] + 0x20)  # space index
        r += pack_offs(v.offs)  # offset
        r += struct.pack("b", v.size + 0x20)  # size
    elif isinstance(v, SpaceId):
        r += struct.pack("b", spaceid_tag)
        r += struct.pack("b", space_map[v.space] + 0x20)  # space index
    elif isinstance(v, Label):
        # turn label into a constant offset for BRANCH
        idx = 0
        for j in range(len(pcode)):
            if isinstance(pcode[j], Label):
                if pcode[j].label == v.label:
                    # idx - i represents the offset from the current instruction
                    # to the desired label, noting that labels don't take up any
                    # space
                    r += pack_varnode_data(VarNode(4, "constant", idx - i),
                                           space_map)
                    break
            else:
                idx += 1
        else:
            raise Exception("Couldn't relativize label {}".format(str(v)))
    else:
        raise Exception("NYI")
    return r


def pack_pcode(space, offset1, offset2, pcode, space_map):

    r = b""
    r += struct.pack("b", inst_tag)  # tag
    r += pack_offs(offset1)  # pcode offset1
    r += struct.pack("b", space_map[space] + 0x20)  # space index
    r += pack_offs(offset2)  # pcode offset2

    idx = 0
    for p in pcode:
        if isinstance(p, Label):
            continue
        r += struct.pack("b", op_tag)  # tag
        r += struct.pack("b", p.op + 0x20)  # opcode
        # output varnode
        if p.outref is None:
            r += struct.pack("b", void_tag)
        else:
            r += pack_varnode_data(p.outref, space_map)
        # input varnodes
        for i in p.inrefs:
            r += pack_varnode_data(i, space_map, pcode, idx)
        # end opcode
        r += struct.pack("b", end_tag)
        idx += 1
    r += struct.pack("b", end_tag)

    # prepend size and return
    return pack_size(len(r)) + r


def unimplemented(space, offset1, offset2, space_map):

    r = b""
    r += struct.pack("b", unimpl_tag)  # tag
    r += pack_offs(offset1)  # pcode offset1

    # prepend size and return
    return pack_size(len(r)) + r
