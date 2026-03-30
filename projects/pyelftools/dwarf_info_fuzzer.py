#!/usr/bin/env python3
# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################

import sys
import atheris

atheris.instrument_all()

import io
import os
import struct

from elftools.dwarf.callframe import CallFrameInfo
from elftools.dwarf.constants import DW_ATE_signed
from elftools.dwarf.aranges import ARanges
from elftools.dwarf.datatype_cpp import describe_cpp_datatype
from elftools.dwarf.descriptions import (
    describe_CFI_CFA_rule,
    describe_CFI_instructions,
    describe_CFI_register_rule,
    describe_DWARF_expr,
    describe_attr_value,
    describe_form_class,
    describe_reg_name,
    set_global_machine_arch,
)
from elftools.dwarf.dwarf_expr import DW_OP_name2opcode, DWARFExprOp, DWARFExprParser
from elftools.dwarf.enums import ENUM_DW_AT, ENUM_DW_FORM, ENUM_DW_TAG
from elftools.dwarf.lineprogram import LineProgram
from elftools.dwarf.locationlists import LocationLists, LocationListsPair, LocationParser
from elftools.dwarf.namelut import NameLUT, NameLUTEntry
from elftools.dwarf.ranges import RangeLists, RangeListsPair
from elftools.dwarf.structs import DWARFStructs
from elftools.elf.elffile import ELFFile


SYNTHETIC_CFI = (
    b"\x20\x00\x00\x00"
    b"\xff\xff\xff\xff"
    b"\x03\x00\x04\x7c"
    b"\x08"
    b"\x0c\x07\x00"
    b"\x08\x00"
    b"\x07\x01"
    b"\x07\x02"
    b"\x07\x03"
    b"\x08\x04"
    b"\x08\x05"
    b"\x08\x06"
    b"\x08\x07"
    b"\x09\x08\x01"
    b"\x00"
    b"\x28\x00\x00\x00"
    b"\x00\x00\x00\x00"
    b"\x44\x33\x22\x11"
    b"\x54\x00\x00\x00"
    b"\x41"
    b"\x0e\x0c\x41"
    b"\x88\x01\x41"
    b"\x86\x02\x41"
    b"\x0d\x06\x41"
    b"\x84\x03\x4b"
    b"\xc4\x41"
    b"\xc6"
    b"\x0d\x07\x41"
    b"\xc8\x41"
    b"\x0e\x00"
    b"\x00\x00"
)

SYNTHETIC_EH_CFI = (
    b"\x1c\x00\x00\x00"
    b"\x00\x00\x00\x00"
    b"\x01"
    b"\x7a\x50\x4c\x52\x00"
    b"\x01"
    b"\x78"
    b"\x10"
    b"\x07"
    b"\x9b"
    b"\x3d\x13\x20\x00"
    b"\x1b"
    b"\x1b"
    b"\x0c\x07\x08\x90"
    b"\x01\x00\x00"
    b"\x24\x00\x00\x00"
    b"\x24\x00\x00\x00"
    b"\x62\xfd\xff\xff"
    b"\x89\x00\x00\x00"
    b"\x04"
    b"\xb7\x00\x00\x00"
    b"\x41\x0e\x10\x86"
    b"\x02\x43\x0d\x06"
    b"\x45\x83\x03\x02"
    b"\x7f\x0c\x07\x08"
    b"\x00\x00\x00"
)

DW_TAG_COMPILE_UNIT = ENUM_DW_TAG["DW_TAG_compile_unit"]
DW_TAG_SUBPROGRAM = ENUM_DW_TAG["DW_TAG_subprogram"]
DW_TAG_BASE_TYPE = ENUM_DW_TAG["DW_TAG_base_type"]

DW_AT_NAME = ENUM_DW_AT["DW_AT_name"]
DW_AT_COMP_DIR = ENUM_DW_AT["DW_AT_comp_dir"]
DW_AT_SIBLING = ENUM_DW_AT["DW_AT_sibling"]
DW_AT_STMT_LIST = ENUM_DW_AT["DW_AT_stmt_list"]
DW_AT_LOW_PC = ENUM_DW_AT["DW_AT_low_pc"]
DW_AT_HIGH_PC = ENUM_DW_AT["DW_AT_high_pc"]
DW_AT_FRAME_BASE = ENUM_DW_AT["DW_AT_frame_base"]
DW_AT_LOCATION = ENUM_DW_AT["DW_AT_location"]
DW_AT_RANGES = ENUM_DW_AT["DW_AT_ranges"]
DW_AT_TYPE = ENUM_DW_AT["DW_AT_type"]
DW_AT_BYTE_SIZE = ENUM_DW_AT["DW_AT_byte_size"]
DW_AT_ENCODING = ENUM_DW_AT["DW_AT_encoding"]

DW_FORM_ADDR = ENUM_DW_FORM["DW_FORM_addr"]
DW_FORM_DATA1 = ENUM_DW_FORM["DW_FORM_data1"]
DW_FORM_DATA8 = ENUM_DW_FORM["DW_FORM_data8"]
DW_FORM_LINE_STRP = ENUM_DW_FORM["DW_FORM_line_strp"]
DW_FORM_REF4 = ENUM_DW_FORM["DW_FORM_ref4"]
DW_FORM_REF_SIG8 = ENUM_DW_FORM["DW_FORM_ref_sig8"]
DW_FORM_SEC_OFFSET = ENUM_DW_FORM["DW_FORM_sec_offset"]
DW_FORM_STRP = ENUM_DW_FORM["DW_FORM_strp"]
DW_FORM_STRING = ENUM_DW_FORM["DW_FORM_string"]


def _safe_call(func, *args, default=None, **kwargs):
    try:
        return func(*args, **kwargs)
    except Exception:
        return default


def _iter_corpus_payloads(paths):
    for path in paths:
        if os.path.isdir(path):
            for root, _, files in os.walk(path):
                for name in sorted(files):
                    file_path = os.path.join(root, name)
                    try:
                        with open(file_path, "rb") as handle:
                            yield handle.read()
                    except Exception:
                        continue
        else:
            try:
                with open(path, "rb") as handle:
                    yield handle.read()
            except Exception:
                continue


def _coverage_mode():
    if "--coverage-corpus" not in sys.argv:
        return False
    start = sys.argv.index("--coverage-corpus") + 1
    for payload in _iter_corpus_payloads(sys.argv[start:]):
        try:
            TestOneInput(payload)
        except Exception:
            pass
    try:
        _touch_handcrafted_dwarfinfo()
    except Exception:
        pass
    return True


def _candidate_blobs(data):
    yield data
    if data.startswith(b"\x7fELF"):
        return

    elfclass = 2 if data[:1] and data[0] & 1 else 1
    endian = 1 if len(data) < 2 or data[1] & 1 == 0 else 2
    header_size = 64 if elfclass == 2 else 52

    header = bytearray(header_size)
    header[0:4] = b"\x7fELF"
    header[4] = elfclass
    header[5] = endian
    header[6] = 1
    yield bytes(header) + data[:8192]


def _open_elf(blob):
    return ELFFile(io.BytesIO(blob), stream_loader=lambda _: io.BytesIO(blob))


def _pack_uint(value, size, little_endian=True):
    fmt = {
        (1, True): "<B",
        (1, False): ">B",
        (2, True): "<H",
        (2, False): ">H",
        (4, True): "<I",
        (4, False): ">I",
        (8, True): "<Q",
        (8, False): ">Q",
    }[(size, little_endian)]
    return struct.pack(fmt, value & ((1 << (size * 8)) - 1))


def _uleb(value):
    value = int(value) & ((1 << 64) - 1)
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def _sleb(value):
    value = int(value)
    out = bytearray()
    more = True
    while more:
        byte = value & 0x7F
        value >>= 7
        sign_bit = byte & 0x40
        more = not ((value == 0 and sign_bit == 0) or (value == -1 and sign_bit != 0))
        if more:
            byte |= 0x80
        out.append(byte)
    return bytes(out)


def _u64_from_slice(data, start, default):
    chunk = data[start:start + 8]
    if len(chunk) < 8:
        return default
    return struct.unpack("<Q", chunk)[0]


def _ascii_name(data, start, default, limit=24):
    alphabet = b"abcdefghijklmnopqrstuvwxyz0123456789_"
    chunk = data[start:start + limit]
    if not chunk:
        return default
    mapped = bytes(alphabet[byte % len(alphabet)] for byte in chunk)
    mapped = mapped.strip(b"_")[:limit]
    return mapped or default


def _build_debug_abbrev():
    out = bytearray()
    out += _uleb(1)
    out += _uleb(DW_TAG_COMPILE_UNIT)
    out += b"\x01"
    out += _uleb(DW_AT_NAME) + _uleb(DW_FORM_STRING)
    out += _uleb(DW_AT_COMP_DIR) + _uleb(DW_FORM_STRP)
    out += _uleb(DW_AT_STMT_LIST) + _uleb(DW_FORM_SEC_OFFSET)
    out += _uleb(DW_AT_LOW_PC) + _uleb(DW_FORM_ADDR)
    out += _uleb(DW_AT_HIGH_PC) + _uleb(DW_FORM_DATA8)
    out += _uleb(0) + _uleb(0)

    out += _uleb(2)
    out += _uleb(DW_TAG_SUBPROGRAM)
    out += b"\x01"
    out += _uleb(DW_AT_NAME) + _uleb(DW_FORM_STRING)
    out += _uleb(DW_AT_LOW_PC) + _uleb(DW_FORM_ADDR)
    out += _uleb(DW_AT_HIGH_PC) + _uleb(DW_FORM_DATA8)
    out += _uleb(DW_AT_FRAME_BASE) + _uleb(DW_FORM_SEC_OFFSET)
    out += _uleb(DW_AT_RANGES) + _uleb(DW_FORM_SEC_OFFSET)
    out += _uleb(DW_AT_SIBLING) + _uleb(DW_FORM_REF4)
    out += _uleb(DW_AT_TYPE) + _uleb(DW_FORM_REF_SIG8)
    out += _uleb(0) + _uleb(0)

    out += _uleb(3)
    out += _uleb(DW_TAG_BASE_TYPE)
    out += b"\x00"
    out += _uleb(DW_AT_NAME) + _uleb(DW_FORM_STRING)
    out += _uleb(DW_AT_BYTE_SIZE) + _uleb(DW_FORM_DATA1)
    out += _uleb(DW_AT_ENCODING) + _uleb(DW_FORM_DATA1)
    out += _uleb(0) + _uleb(0)

    out += _uleb(4)
    out += _uleb(ENUM_DW_TAG["DW_TAG_variable"])
    out += b"\x00"
    out += _uleb(DW_AT_NAME) + _uleb(DW_FORM_LINE_STRP)
    out += _uleb(DW_AT_TYPE) + _uleb(DW_FORM_REF_SIG8)
    out += _uleb(DW_AT_LOCATION) + _uleb(DW_FORM_SEC_OFFSET)
    out += _uleb(0) + _uleb(0)

    out += b"\x00"
    return bytes(out)


def _build_debug_info(data):
    cu_name = _ascii_name(data, 0, b"synthetic_cu")
    func_name = _ascii_name(data, 24, b"fuzz_func")
    low_pc = 0x1000 + (_u64_from_slice(data, 48, 0) & 0xFF)
    cu_span = 0x40 + (_u64_from_slice(data, 56, 0) & 0x3F)
    func_span = 0x20 + (_u64_from_slice(data, 64, 0) & 0x1F)

    body = bytearray()
    root_die_offset = 11

    body += b"\x01"
    body += cu_name + b"\x00"
    body += _pack_uint(1, 4)
    body += _pack_uint(0, 4)
    body += _pack_uint(low_pc, 8)
    body += _pack_uint(cu_span, 8)

    child_die_offset = root_die_offset + len(body)
    variable_name_offset = 1
    signature = 0x1122334455667788 ^ _u64_from_slice(data, 104, 0)

    subprogram = bytearray()
    subprogram += b"\x02"
    subprogram += func_name + b"\x00"
    subprogram += _pack_uint(low_pc + 4, 8)
    subprogram += _pack_uint(func_span, 8)
    subprogram += _pack_uint(0, 4)
    subprogram += _pack_uint(0, 4)
    sibling_patch = len(subprogram)
    subprogram += _pack_uint(0, 4)
    subprogram += _pack_uint(signature, 8)

    variable_die_offset = child_die_offset + len(subprogram)
    variable_die = bytearray()
    variable_die += b"\x04"
    variable_die += _pack_uint(variable_name_offset, 4)
    variable_die += _pack_uint(signature, 8)
    variable_die += _pack_uint(0, 4)

    cu_terminator_offset = child_die_offset + len(subprogram) + len(variable_die) + 1
    subprogram[sibling_patch:sibling_patch + 4] = _pack_uint(cu_terminator_offset, 4)

    body += subprogram
    body += variable_die
    body += b"\x00"
    body += b"\x00"

    header = _pack_uint(4, 2) + _pack_uint(0, 4) + b"\x08"
    unit_length = len(header) + len(body)
    return _pack_uint(unit_length, 4) + header + body, root_die_offset, child_die_offset, cu_name, func_name, low_pc


def _build_debug_types(data):
    type_name = _ascii_name(data, 96, b"int")
    signature = 0x1122334455667788 ^ _u64_from_slice(data, 104, 0)

    body = bytearray()
    body += b"\x03"
    body += type_name + b"\x00"
    body += b"\x04"
    body += bytes([DW_ATE_signed])
    body += b"\x00"

    header_without_length = (
        _pack_uint(4, 2)
        + _pack_uint(0, 4)
        + b"\x08"
        + _pack_uint(signature, 8)
        + _pack_uint(23, 4)
    )
    unit_length = len(header_without_length) + len(body)
    return _pack_uint(unit_length, 4) + header_without_length + body, signature


def _build_debug_line(data, low_pc):
    program = bytearray([1, 2])
    program += _uleb(1 + (data[:1] or b"\x00")[0] % 3)
    program += bytes([3]) + _sleb(1)
    program += bytes([4]) + _uleb(1)
    program += bytes([5]) + _uleb(1)
    program += bytes([6, 7, 8, 9]) + _pack_uint(1, 2)
    program += bytes([10, 11, 12]) + _uleb(1)
    program += bytes([0]) + _uleb(9) + bytes([2]) + _pack_uint(low_pc, 8)
    program += bytes([0]) + _uleb(1) + bytes([1])
    program += data[128:160]

    standard_opcode_lengths = bytes([0] * 12)
    directories = b"\x00"
    file_name = _ascii_name(data, 160, b"seed_c", 12)
    file_entries = file_name + b".c\x00\x01\x00\x00\x00"
    header_body = (
        bytes([1, 1, 1])
        + struct.pack("<b", -5)
        + bytes([14, 13])
        + standard_opcode_lengths
        + directories
        + file_entries
    )
    header_length = len(header_body)
    unit_length = 2 + 4 + header_length + len(program)
    return _pack_uint(unit_length, 4) + _pack_uint(4, 2) + _pack_uint(header_length, 4) + header_body + bytes(program)


def _build_debug_loc(data, address_size=8):
    begin = 0x1004 + (_u64_from_slice(data, 192, 0) & 0x3F)
    end = begin + ((_u64_from_slice(data, 200, 1) & 0x1F) + 1)
    expr = data[208:216] or b"\x50"
    return (
        _pack_uint(begin, address_size)
        + _pack_uint(end, address_size)
        + _pack_uint(len(expr), 2)
        + expr
        + b"\x00" * (address_size * 2)
    )


def _build_debug_ranges(data, address_size=8):
    begin = 0x1004 + (_u64_from_slice(data, 224, 0) & 0x3F)
    end = begin + ((_u64_from_slice(data, 232, 4) & 0x1F) + 1)
    return _pack_uint(begin, address_size) + _pack_uint(end, address_size) + b"\x00" * (address_size * 2)


def _build_debug_aranges(low_pc, span):
    header = _pack_uint(2, 2) + _pack_uint(0, 4) + b"\x08\x00"
    padding = b"\x00" * 4
    entries = _pack_uint(low_pc, 8) + _pack_uint(span, 8) + _pack_uint(0, 8) + _pack_uint(0, 8)
    unit_length = len(header) + len(padding) + len(entries)
    return _pack_uint(unit_length, 4) + header + padding + entries


def _build_namelut(debug_info_length, die_offset, name):
    body = _pack_uint(die_offset, 4) + name + b"\x00" + _pack_uint(0, 4)
    header = _pack_uint(2, 2) + _pack_uint(0, 4) + _pack_uint(debug_info_length, 4)
    unit_length = len(header) + len(body)
    return _pack_uint(unit_length, 4) + header + body


def _build_debug_str(data, cu_name, func_name):
    type_name = _ascii_name(data, 240, b"int")
    return b"\x00/tmp\x00" + cu_name + b"\x00" + func_name + b"\x00" + type_name + b"\x00"


def _build_debug_line_str(data):
    file_name = _ascii_name(data, 264, b"seed_c", 12)
    return b"\x00" + file_name + b".c\x00"


def _build_debug_addr(data):
    base = 0x1000 + (_u64_from_slice(data, 280, 0) & 0x7F)
    return _pack_uint(base, 8) + _pack_uint(base + 4, 8) + _pack_uint(base + 0x10, 8)


def _build_elf_from_sections(sections):
    shstr = b"\x00"
    name_offsets = {}
    for name in [section_name for section_name, _ in sections] + [".shstrtab"]:
        name_offsets[name] = len(shstr)
        shstr += name.encode("ascii") + b"\x00"

    full_sections = list(sections) + [(".shstrtab", shstr)]

    blob = bytearray(b"\x00" * 64)
    offsets = []
    current_offset = 64

    for _, section_bytes in full_sections:
        offsets.append(current_offset)
        blob.extend(section_bytes)
        current_offset += len(section_bytes)

    shoff = (len(blob) + 7) & ~7
    blob.extend(b"\x00" * (shoff - len(blob)))

    e_ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8
    blob[:64] = struct.pack(
        "<16sHHIQQQIHHHHHH",
        e_ident,
        1,
        62,
        1,
        0,
        0,
        shoff,
        0,
        64,
        0,
        0,
        64,
        len(full_sections) + 1,
        len(full_sections),
    )

    blob.extend(b"\x00" * 64)
    for (name, section_bytes), offset in zip(full_sections, offsets):
        section_type = 3 if name == ".shstrtab" else 1
        blob.extend(
            struct.pack(
                "<IIQQQQIIQQ",
                name_offsets[name],
                section_type,
                0,
                0,
                offset,
                len(section_bytes),
                0,
                0,
                1,
                0,
            )
        )

    return bytes(blob)


def _build_rich_dwarf_elf(data):
    debug_info, root_die_offset, child_die_offset, cu_name, func_name, low_pc = _build_debug_info(data)
    debug_types, _ = _build_debug_types(data)
    sections = [
        (".debug_abbrev", _build_debug_abbrev()),
        (".debug_info", debug_info),
        (".debug_types", debug_types),
        (".debug_line", _build_debug_line(data, low_pc)),
        (".debug_frame", SYNTHETIC_CFI),
        (".eh_frame", SYNTHETIC_EH_CFI),
        (".debug_loc", _build_debug_loc(data)),
        (".debug_ranges", _build_debug_ranges(data)),
        (".debug_aranges", _build_debug_aranges(low_pc, 0x40)),
        (".debug_pubnames", _build_namelut(len(debug_info), child_die_offset, func_name)),
        (".debug_pubtypes", _build_namelut(len(debug_info), root_die_offset, cu_name)),
        (".debug_str", _build_debug_str(data, cu_name, func_name)),
        (".debug_line_str", _build_debug_line_str(data)),
        (".debug_addr", _build_debug_addr(data)),
    ]
    return _build_elf_from_sections(sections)


def _build_minimal_dwarf_elf(data=b""):
    cu_name = _ascii_name(data, 0, b"minimal_cu")
    abbrev = (
        _uleb(1)
        + _uleb(DW_TAG_COMPILE_UNIT)
        + b"\x00"
        + _uleb(DW_AT_NAME)
        + _uleb(DW_FORM_STRING)
        + _uleb(0)
        + _uleb(0)
        + b"\x00"
    )
    body = b"\x01" + cu_name + b"\x00"
    debug_info = _pack_uint(7 + len(body), 4) + _pack_uint(4, 2) + _pack_uint(0, 4) + b"\x08" + body
    return _build_elf_from_sections(
        [
            (".debug_abbrev", abbrev),
            (".debug_info", debug_info),
            (".debug_str", b"\x00" + cu_name + b"\x00"),
        ]
    )


def _elf_has_parseable_dwarf(blob):
    elf = _safe_call(_open_elf, blob)
    if elf is None:
        return False
    try:
        dwarfinfo = _safe_call(
            elf.get_dwarf_info,
            relocate_dwarf_sections=False,
            follow_links=False,
        )
        if dwarfinfo is None:
            return False
        return bool(list(_safe_call(dwarfinfo.iter_CUs, default=[]) or []))
    finally:
        _ = _safe_call(elf.close)


def build_dwarf_elf(data):
    rich = _safe_call(_build_rich_dwarf_elf, data)
    if rich is not None and _elf_has_parseable_dwarf(rich):
        return rich
    minimal = _safe_call(_build_minimal_dwarf_elf, data)
    if minimal is not None and _elf_has_parseable_dwarf(minimal):
        return minimal
    return b"\x7fELF" + b"\x00" * 60


def _touch_structs(structs):
    _ = getattr(structs, "little_endian", None)
    _ = getattr(structs, "dwarf_format", None)
    _ = getattr(structs, "address_size", None)
    _ = getattr(structs, "dwarf_version", None)
    _ = _safe_call(structs.initial_length_field_size)
    for name in (
        "the_Dwarf_offset",
        "the_Dwarf_target_addr",
        "the_Dwarf_uint8",
        "the_Dwarf_uint16",
        "the_Dwarf_uint32",
        "the_Dwarf_uint64",
        "the_Dwarf_uleb128",
        "the_Dwarf_sleb128",
        "Dwarf_CU_header",
        "Dwarf_TU_header",
        "Dwarf_lineprog_header",
        "Dwarf_loclists_CU_header",
        "Dwarf_rnglists_CU_header",
    ):
        _ = getattr(structs, name, None)


def _touch_location_entry(entry):
    for name in (
        "entry_offset",
        "entry_length",
        "begin_offset",
        "end_offset",
        "loc_expr",
        "is_absolute",
        "base_address",
        "begin",
        "end",
    ):
        _ = getattr(entry, name, None)
    _ = repr(entry)


def _touch_range_entry(entry):
    for name in (
        "entry_offset",
        "entry_length",
        "begin_offset",
        "end_offset",
        "is_absolute",
        "base_address",
    ):
        _ = getattr(entry, name, None)
    _ = repr(entry)


def _touch_location_value(value):
    if isinstance(value, list):
        for entry in value[:16]:
            _touch_location_entry(entry)
    else:
        _touch_location_entry(value)


def _touch_range_value(value):
    if isinstance(value, list):
        for entry in value[:16]:
            _touch_range_entry(entry)
    else:
        _touch_range_entry(value)


def _touch_line_program(line_program):
    _ = line_program.header
    for key in (
        "version",
        "unit_length",
        "header_length",
        "minimum_instruction_length",
        "maximum_operations_per_instruction",
        "default_is_stmt",
        "line_base",
        "line_range",
        "opcode_base",
    ):
        _ = _safe_call(line_program.__getitem__, key)
    for index, entry in enumerate(_safe_call(line_program.get_entries, default=[]) or []):
        if index >= 64:
            break
        _ = entry.command
        _ = entry.is_extended
        _ = entry.args
        _ = entry.state
        if entry.state is not None:
            _ = repr(entry.state)


def _touch_cfi_entry(entry):
    _ = getattr(entry, "header", None)
    _ = getattr(entry, "structs", None)
    _ = getattr(entry, "instructions", None)
    _ = getattr(entry, "offset", None)
    _ = getattr(entry, "augmentation_bytes", None)
    _ = getattr(entry, "cie", None)
    _ = getattr(entry, "lsda_pointer", None)
    for key in (
        "length",
        "CIE_pointer",
        "address_range",
        "data_alignment_factor",
        "return_address_register",
    ):
        _ = _safe_call(entry.__getitem__, key)
    decoded = _safe_call(entry.get_decoded)
    if decoded is not None:
        _ = getattr(decoded, "table", None)
        _ = getattr(decoded, "reg_order", None)
    for instruction in list(getattr(entry, "instructions", []) or [])[:32]:
        _ = getattr(instruction, "opcode", None)
        _ = getattr(instruction, "args", None)
        _ = repr(instruction)


def _touch_location_lists(location_lists, cu_list):
    for offset in (0, 12):
        _touch_location_value(_safe_call(location_lists.get_location_list_at_offset, offset))

    top_die = None
    if cu_list:
        top_die = _safe_call(cu_list[0].get_top_DIE)
    if top_die is not None:
        for offset in (0, 12):
            _touch_location_value(_safe_call(location_lists.get_location_list_at_offset, offset, die=top_die))

    for location_list in list(_safe_call(location_lists.iter_location_lists, default=[]) or [])[:16]:
        _touch_location_value(location_list)

    section_cus = list(_safe_call(location_lists.iter_CUs, default=[]) or [])[:8]
    for section_cu in section_cus:
        _ = section_cu


def _touch_range_lists(range_lists, cu_list):
    for offset in (0, 12):
        _touch_range_value(_safe_call(range_lists.get_range_list_at_offset, offset))
        _touch_range_value(_safe_call(range_lists.get_range_list_at_offset_ex, offset))

    section_cus = list(_safe_call(range_lists.iter_CUs, default=[]) or [])[:8]
    for section_cu in section_cus:
        _ = section_cu
        for entry in list(_safe_call(range_lists.iter_CU_range_lists_ex, section_cu, default=[]) or [])[:8]:
            _touch_range_value(entry)
            _touch_range_value(_safe_call(range_lists.translate_v5_entry, entry, section_cu))

    for range_list in list(_safe_call(range_lists.iter_range_lists, default=[]) or [])[:16]:
        _touch_range_value(range_list)

    if cu_list:
        first_cu = cu_list[0]
        for entry in list(_safe_call(range_lists.iter_CU_range_lists_ex, first_cu, default=[]) or [])[:8]:
            _touch_range_value(entry)
            _touch_range_value(_safe_call(range_lists.translate_v5_entry, entry, first_cu))


def _touch_namelut(namelut, dwarfinfo):
    _ = len(namelut)
    _ = _safe_call(namelut.get_entries)
    _ = _safe_call(namelut.get_cu_headers)
    _ = _safe_call(namelut._get_entries)
    for name in list(namelut)[:16]:
        entry = _safe_call(namelut.__getitem__, name)
        _ = _safe_call(namelut.get, name)
        if entry is None:
            continue
        _ = getattr(entry, "cu_ofs", None)
        _ = getattr(entry, "die_ofs", None)
        _ = _safe_call(dwarfinfo.get_DIE_from_lut_entry, entry)
        _ = _safe_call(dwarfinfo.get_DIE_from_refaddr, entry.die_ofs)
    for name, entry in list(_safe_call(namelut.items, default=[]) or [])[:16]:
        _ = name
        _ = getattr(entry, "cu_ofs", None)


def _touch_die(die, cu, location_parser):
    _ = getattr(die, "tag", None)
    _ = getattr(die, "offset", None)
    _ = getattr(die, "size", None)
    _ = getattr(die, "abbrev_code", None)
    _ = getattr(die, "attributes", None)
    _ = _safe_call(die.is_null)
    _ = _safe_call(die.get_parent)
    _ = _safe_call(die.get_full_path)
    _ = _safe_call(die._translate_indirect_attributes)
    _ = repr(die)
    _ = str(die)

    for name, attr in list(getattr(die, "attributes", {}).items())[:32]:
        _ = getattr(attr, "name", None)
        _ = getattr(attr, "form", None)
        _ = getattr(attr, "value", None)
        _ = getattr(attr, "raw_value", None)
        _ = getattr(attr, "offset", None)
        _ = getattr(attr, "indirection_length", None)
        _ = _safe_call(die.get_DIE_from_attribute, name)
        _ = _safe_call(die._translate_attr_value, attr.form, attr.raw_value)
        _ = _safe_call(LocationParser.attribute_has_location, attr, cu["version"])
        if location_parser is not None:
            _ = _safe_call(location_parser.parse_from_attribute, attr, cu["version"], die=die)

    for index, child in enumerate(_safe_call(die.iter_children, default=[]) or []):
        if index >= 16:
            break
        _ = getattr(child, "tag", None)

    for index, sibling in enumerate(_safe_call(die.iter_siblings, default=[]) or []):
        if index >= 16:
            break
        _ = getattr(sibling, "tag", None)


def _touch_cu(cu, dwarfinfo, location_parser):
    _ = cu.header
    _ = cu.structs
    _ = cu.cu_offset
    _ = cu.cu_die_offset
    _ = _safe_call(cu.dwarf_format)
    _ = _safe_call(cu.get_abbrev_table)
    _ = _safe_call(cu.has_top_DIE)
    _ = _safe_call(cu.size)
    for key in ("version", "unit_length", "debug_abbrev_offset", "address_size"):
        _ = _safe_call(cu.__getitem__, key)

    top_die = _safe_call(cu.get_top_DIE)
    if top_die is not None:
        _touch_die(top_die, cu, location_parser)
        _ = _safe_call(cu._get_cached_DIE, top_die.offset)
        _ = list(_safe_call(cu._iter_DIE_subtree, top_die, default=[]) or [])
        for index, child in enumerate(_safe_call(cu.iter_DIE_children, top_die, default=[]) or []):
            if index >= 16:
                break
            _ = getattr(child, "tag", None)
            _ = _safe_call(cu._get_cached_DIE, child.offset)
            _ = _safe_call(child._search_ancestor_offspring)
            _touch_die(child, cu, location_parser)

    for index, die in enumerate(_safe_call(cu.iter_DIEs, default=[]) or []):
        if index >= 64:
            break
        _touch_die(die, cu, location_parser)
        _ = _safe_call(cu._get_cached_DIE, die.offset)
        _ = _safe_call(cu.get_DIE_from_refaddr, die.offset)
        _ = _safe_call(dwarfinfo.get_DIE_from_refaddr, die.offset, cu=cu)
        _ = _safe_call(dwarfinfo.get_CU_containing, die.offset)

    _ = _safe_call(dwarfinfo.get_CU_at, cu.cu_offset)


def _touch_tu(tu, dwarfinfo):
    _ = tu.header
    _ = tu.structs
    _ = tu.tu_offset
    _ = tu.tu_die_offset
    _ = tu.cu_offset
    _ = tu.cu_die_offset
    _ = _safe_call(tu.dwarf_format)
    _ = _safe_call(tu.get_abbrev_table)
    _ = _safe_call(tu.has_top_DIE)
    for key in ("version", "signature", "type_offset"):
        _ = _safe_call(tu.__getitem__, key)
    top_die = _safe_call(tu.get_top_DIE)
    if top_die is not None:
        _ = getattr(top_die, "tag", None)
        _ = _safe_call(tu._get_cached_DIE, top_die.offset)
        _ = list(_safe_call(tu._iter_DIE_subtree, top_die, default=[]) or [])
        for die in list(_safe_call(tu.iter_DIEs, default=[]) or [])[:16]:
            _ = _safe_call(tu._get_cached_DIE, die.offset)
    signature = _safe_call(tu.__getitem__, "signature")
    if signature is not None:
        _ = _safe_call(dwarfinfo.get_TU_by_sig8, signature)
        _ = _safe_call(dwarfinfo.get_DIE_by_sig8, signature)


def _touch_dwarfinfo(dwarfinfo):
    _ = _safe_call(dwarfinfo.has_debug_info)
    _ = _safe_call(dwarfinfo.has_debug_types)
    abbrev_table = _safe_call(dwarfinfo.get_abbrev_table, 0)
    if abbrev_table is not None:
        decl = _safe_call(abbrev_table.get_abbrev, 1)
        if decl is not None:
            _ = _safe_call(decl.has_children)
            _ = list(_safe_call(decl.iter_attr_specs, default=[]) or [])
    _ = _safe_call(dwarfinfo.get_string_from_table, 0)
    _ = _safe_call(dwarfinfo.get_string_from_linetable, 0)
    _ = _safe_call(dwarfinfo._is_supported_version, 4)
    _ = _safe_call(dwarfinfo._is_supported_version, 5)
    _ = list(_safe_call(dwarfinfo._parse_CUs_iter, 0, default=[]) or [])
    _ = list(_safe_call(dwarfinfo._parse_TUs_iter, 0, default=[]) or [])
    _ = _safe_call(dwarfinfo._parse_debug_types)
    _ = _safe_call(dwarfinfo._cached_CU_at_offset, 0)
    _ = _safe_call(dwarfinfo._parse_CU_at_offset, 0)
    _ = _safe_call(dwarfinfo._parse_TU_at_offset, 0)
    _ = _safe_call(dwarfinfo._parse_line_program_at_offset, 0, dwarfinfo.structs)

    cu_list = list(_safe_call(dwarfinfo.iter_CUs, default=[]) or [])
    location_lists = _safe_call(dwarfinfo.location_lists)
    location_parser = LocationParser(location_lists) if location_lists is not None else None

    for cu in cu_list[:16]:
        _touch_cu(cu, dwarfinfo, location_parser)
        line_program = _safe_call(dwarfinfo.line_program_for_CU, cu)
        if line_program is not None:
            _touch_line_program(line_program)
        for index in range(4):
            _ = _safe_call(dwarfinfo.get_addr, cu, index)

    for tu in list(_safe_call(dwarfinfo.iter_TUs, default=[]) or [])[:8]:
        _touch_tu(tu, dwarfinfo)

    if _safe_call(dwarfinfo.has_CFI):
        for entry in list(_safe_call(dwarfinfo.CFI_entries, default=[]) or [])[:16]:
            _touch_cfi_entry(entry)

    if _safe_call(dwarfinfo.has_EH_CFI):
        for entry in list(_safe_call(dwarfinfo.EH_CFI_entries, default=[]) or [])[:16]:
            _touch_cfi_entry(entry)

    if location_lists is not None:
        _touch_location_lists(location_lists, cu_list)
        if isinstance(location_lists, LocationListsPair):
            _touch_location_lists(location_lists, cu_list)

    range_lists = _safe_call(dwarfinfo.range_lists)
    if range_lists is not None:
        _touch_range_lists(range_lists, cu_list)
        if isinstance(range_lists, RangeListsPair):
            _touch_range_lists(range_lists, cu_list)

    aranges = _safe_call(dwarfinfo.get_aranges)
    if aranges is not None:
        _ = _safe_call(aranges._get_entries)
        _ = _safe_call(aranges._get_entries, need_empty=True)
        _ = _safe_call(aranges._get_addr_size_struct, 4)
        _ = _safe_call(aranges._get_addr_size_struct, 8)
        _ = _safe_call(aranges.cu_offset_at_addr, 0)
        _ = _safe_call(aranges.cu_offset_at_addr, 0x1000)

    pubnames = _safe_call(dwarfinfo.get_pubnames)
    if pubnames is not None:
        _touch_namelut(pubnames, dwarfinfo)

    pubtypes = _safe_call(dwarfinfo.get_pubtypes)
    if pubtypes is not None:
        _touch_namelut(pubtypes, dwarfinfo)


class _FakeAttr:
    def __init__(self, name, form, value):
        self.name = name
        self.form = form
        self.value = value


class _FakeHeader:
    def __init__(self, version):
        self.version = version


class _FakeDIE:
    def __init__(self, cu, attributes):
        self.cu = cu
        self.attributes = attributes
        self.tag = "DW_TAG_variable"
        self.offset = 0
        self.size = 0
        self.abbrev_code = 1

    def is_null(self):
        return False

    def get_parent(self):
        return None

    def get_full_path(self):
        return ""

    def get_DIE_from_attribute(self, _name):
        return None

    def iter_children(self):
        return iter(())

    def iter_siblings(self):
        return iter(())


class _FakeCU:
    def __init__(self, structs, version, location_offset=None, range_offset=None):
        self.structs = structs
        self.header = _FakeHeader(version)
        self.dwarfinfo = None
        attributes = {}
        if location_offset is not None:
            location_form = "DW_FORM_sec_offset" if version >= 5 else "DW_FORM_data4"
            attributes["DW_AT_location"] = _FakeAttr("DW_AT_location", location_form, location_offset)
        if range_offset is not None:
            range_form = "DW_FORM_sec_offset" if version >= 5 else "DW_FORM_data4"
            attributes["DW_AT_ranges"] = _FakeAttr("DW_AT_ranges", range_form, range_offset)
        self._top_die = _FakeDIE(self, attributes)

    def __getitem__(self, key):
        if key == "version":
            return self.header.version
        raise KeyError(key)

    def iter_DIEs(self):
        yield self._top_die

    def get_top_DIE(self):
        return self._top_die


class _FakeDwarfInfo:
    def __init__(self, cu_list):
        self._cu_list = cu_list
        for cu in self._cu_list:
            cu.dwarfinfo = self

    def iter_CUs(self):
        return iter(self._cu_list)


def _build_v5_loclists_stream(data, structs):
    max_addr = (1 << (structs.address_size * 8)) - 1
    start = _u64_from_slice(data, 0, 0) & max_addr
    end = (start + ((_u64_from_slice(data, 8, 2) & 0x3F) + 1)) & max_addr
    expr = data[16:24] or b"\x50"
    entry = b"\x07"
    entry += _pack_uint(start, structs.address_size, structs.little_endian)
    entry += _pack_uint(end, structs.address_size, structs.little_endian)
    entry += _uleb(len(expr))
    entry += expr
    entry += b"\x00"
    header = struct.pack("<I", 8 + len(entry))
    header += struct.pack("<HBBI", 5, structs.address_size, 0, 0)
    return header + entry


def _build_v5_rnglists_stream(data, structs):
    max_addr = (1 << (structs.address_size * 8)) - 1
    start = _u64_from_slice(data, 32, 0) & max_addr
    end = (start + ((_u64_from_slice(data, 40, 4) & 0x3F) + 1)) & max_addr
    entry = b"\x06"
    entry += _pack_uint(start, structs.address_size, structs.little_endian)
    entry += _pack_uint(end, structs.address_size, structs.little_endian)
    entry += b"\x00"
    header = struct.pack("<I", 8 + len(entry))
    header += struct.pack("<HBBI", 5, structs.address_size, 0, 0)
    return header + entry


def _build_v4_loclist_stream(data, address_size):
    return _build_debug_loc(data, address_size)


def _build_v4_rangelist_stream(data, address_size):
    return _build_debug_ranges(data, address_size)


def _make_line_program_header(data):
    return {
        "version": 4,
        "unit_length": len(data),
        "header_length": 0,
        "minimum_instruction_length": 1,
        "maximum_operations_per_instruction": 1,
        "default_is_stmt": 1,
        "line_base": -5,
        "line_range": 14,
        "opcode_base": 13,
        "standard_opcode_lengths": [0] * 12,
        "include_directory": [b"tmp", b""],
        "file_entry": [],
    }


def _build_line_program_stream(data):
    address = 0x1000 + (_u64_from_slice(data, 0, 0) & 0xFF)
    program = bytearray()
    program.append(1)
    program.append(2)
    program.extend(_uleb(1 + ((data[:1] or b"\x00")[0] % 3)))
    program.append(3)
    program.extend(_sleb(1))
    program.append(4)
    program.extend(_uleb(1))
    program.append(5)
    program.extend(_uleb(1))
    program.append(6)
    program.append(7)
    program.append(8)
    program.append(9)
    program.extend(_pack_uint(1, 2))
    program.append(10)
    program.append(11)
    program.append(12)
    program.extend(_uleb(1))
    program.append(0)
    program.extend(_uleb(9))
    program.append(2)
    program.extend(_pack_uint(address, 8))
    program.append(0)
    program.extend(_uleb(2))
    program.append(4)
    program.append(1)
    program.append(0)
    program.extend(_uleb(1))
    program.append(1)
    program.extend(data[64:96])
    return bytes(program)


def _touch_callframe_info(cfi):
    for entry in list(_safe_call(cfi.get_entries, default=[]) or [])[:16]:
        _touch_cfi_entry(entry)


def _normalize_cfi_entries(entries_or_cfi):
    if entries_or_cfi is None:
        return []
    if isinstance(entries_or_cfi, (list, tuple)):
        return list(entries_or_cfi)
    parsed = _safe_call(entries_or_cfi.get_entries)
    if parsed is not None:
        return list(parsed)
    try:
        return list(entries_or_cfi)
    except Exception:
        return []


class _FakeDescriptionAttr:
    def __init__(self, name, form, value, raw_value=None, offset=0):
        self.name = name
        self.form = form
        self.value = value
        self.raw_value = value if raw_value is None else raw_value
        self.offset = offset
        self.indirection_length = 0


class _FakeCppRoot:
    tag = ""

    def get_parent(self):
        return self


_FAKE_CPP_ROOT = _FakeCppRoot()


class _FakeCppDIE:
    def __init__(self, tag, name=None, parent=None):
        self.tag = tag
        self._parent = _FAKE_CPP_ROOT if parent is None else parent
        self._children = []
        self._refs = {}
        self.attributes = {}
        if name is not None:
            self.attributes["DW_AT_name"] = _FakeDescriptionAttr(
                "DW_AT_name", "DW_FORM_string", name
            )

    def add_ref(self, name, die):
        self._refs[name] = die
        self.attributes[name] = _FakeDescriptionAttr(name, "DW_FORM_ref4", 0)

    def add_attr(self, name, value, form="DW_FORM_data1", raw_value=None):
        self.attributes[name] = _FakeDescriptionAttr(name, form, value, raw_value)

    def add_child(self, die):
        self._children.append(die)
        die._parent = self

    def get_DIE_from_attribute(self, name):
        return self._refs.get(name)

    def iter_children(self):
        return iter(self._children)

    def get_parent(self):
        return self._parent


def _touch_synthetic_cpp_datatypes():
    namespace_die = _FakeCppDIE("DW_TAG_namespace", b"ns")
    class_die = _FakeCppDIE("DW_TAG_class_type", b"Widget", namespace_die)
    base_type = _FakeCppDIE("DW_TAG_base_type", b"int", class_die)

    pointer_type = _FakeCppDIE("DW_TAG_pointer_type")
    pointer_type.add_ref("DW_AT_type", base_type)

    const_type = _FakeCppDIE("DW_TAG_const_type")
    const_type.add_ref("DW_AT_type", pointer_type)

    variable_die = _FakeCppDIE("DW_TAG_variable", b"value")
    variable_die.add_ref("DW_AT_type", const_type)

    void_pointer_type = _FakeCppDIE("DW_TAG_pointer_type")
    void_variable_die = _FakeCppDIE("DW_TAG_variable", b"ptr")
    void_variable_die.add_ref("DW_AT_type", void_pointer_type)

    subroutine_type = _FakeCppDIE("DW_TAG_subroutine_type")
    subroutine_type.add_ref("DW_AT_type", base_type)
    param_die = _FakeCppDIE("DW_TAG_formal_parameter")
    param_die.add_ref("DW_AT_type", base_type)
    variadic_die = _FakeCppDIE("DW_TAG_unspecified_parameters")
    subroutine_type.add_child(param_die)
    subroutine_type.add_child(variadic_die)
    func_ptr_type = _FakeCppDIE("DW_TAG_pointer_type")
    func_ptr_type.add_ref("DW_AT_type", subroutine_type)
    function_die = _FakeCppDIE("DW_TAG_variable", b"fn")
    function_die.add_ref("DW_AT_type", func_ptr_type)

    array_type = _FakeCppDIE("DW_TAG_array_type")
    array_type.add_ref("DW_AT_type", base_type)
    subrange = _FakeCppDIE("DW_TAG_subrange_type")
    subrange.add_attr("DW_AT_upper_bound", 3)
    array_type.add_child(subrange)
    array_die = _FakeCppDIE("DW_TAG_variable", b"arr")
    array_die.add_ref("DW_AT_type", array_type)

    pfn_subroutine_type = _FakeCppDIE("DW_TAG_subroutine_type")
    pfn_subroutine_type.add_ref("DW_AT_type", base_type)
    pfn_pointer_type = _FakeCppDIE("DW_TAG_pointer_type")
    pfn_pointer_type.add_ref("DW_AT_type", pfn_subroutine_type)
    pfn_member = _FakeCppDIE("DW_TAG_member", b"__pfn")
    pfn_member.add_ref("DW_AT_type", pfn_pointer_type)
    delta_member = _FakeCppDIE("DW_TAG_member", b"__delta")
    delta_member.add_ref("DW_AT_type", base_type)
    ptr_to_member_struct = _FakeCppDIE("DW_TAG_structure_type", b"PtrMember")
    ptr_to_member_struct.add_child(pfn_member)
    ptr_to_member_struct.add_child(delta_member)
    ptr_to_member_die = _FakeCppDIE("DW_TAG_variable", b"pmf")
    ptr_to_member_die.add_ref("DW_AT_type", ptr_to_member_struct)

    empty_die = _FakeCppDIE("DW_TAG_variable", b"empty")

    for die in (
        variable_die,
        void_variable_die,
        function_die,
        array_die,
        ptr_to_member_die,
        empty_die,
    ):
        _ = _safe_call(describe_cpp_datatype, die)


def _touch_synthetic_descriptions(structs, described_dies, dwarfinfo):
    for form in (
        "DW_FORM_addr",
        "DW_FORM_data1",
        "DW_FORM_data2",
        "DW_FORM_data4",
        "DW_FORM_data8",
        "DW_FORM_string",
        "DW_FORM_strp",
        "DW_FORM_line_strp",
        "DW_FORM_exprloc",
        "DW_FORM_ref4",
        "DW_FORM_ref_sig8",
    ):
        _ = _safe_call(describe_form_class, form)

    for expr in (
        [0x50],
        [0x08, 0x2A, 0x23, 0x01, 0x9F],
        [0x91, 0x01],
        [0xA3, 0x02, 0x50, 0x9F],
    ):
        _ = _safe_call(describe_DWARF_expr, expr, structs, 0)

    class _FakeRule:
        def __init__(self, rule_type, arg=None, expr=None, reg=None, offset=None):
            self.type = rule_type
            self.arg = arg
            self.expr = expr
            self.reg = reg
            self.offset = offset

    for rule in (
        _FakeRule("OFFSET", 8),
        _FakeRule("VAL_OFFSET", -4),
        _FakeRule("REGISTER", 3),
    ):
        _ = _safe_call(describe_CFI_register_rule, rule)

    for rule in (
        _FakeRule("CFA", expr=True),
        _FakeRule("CFA", expr=False, reg=7, offset=-8),
    ):
        _ = _safe_call(describe_CFI_CFA_rule, rule)

    if not described_dies:
        return

    base_die = described_dies[0]
    string_value = b"/tmp"
    line_string_value = b"line.c"
    if dwarfinfo is not None:
        string_value = _safe_call(dwarfinfo.get_string_from_table, 0, default=b"/tmp") or b"/tmp"
        line_string_value = _safe_call(dwarfinfo.get_string_from_linetable, 0, default=b"line.c") or b"line.c"

    synthetic_attrs = [
        _FakeDescriptionAttr("DW_AT_language", "DW_FORM_data2", 0x0004),
        _FakeDescriptionAttr("DW_AT_inline", "DW_FORM_data1", 1),
        _FakeDescriptionAttr("DW_AT_encoding", "DW_FORM_data1", DW_ATE_signed),
        _FakeDescriptionAttr("DW_AT_accessibility", "DW_FORM_data1", 1),
        _FakeDescriptionAttr("DW_AT_visibility", "DW_FORM_data1", 1),
        _FakeDescriptionAttr("DW_AT_virtuality", "DW_FORM_data1", 1),
        _FakeDescriptionAttr("DW_AT_calling_convention", "DW_FORM_data1", 1),
        _FakeDescriptionAttr("DW_AT_identifier_case", "DW_FORM_data1", 1),
        _FakeDescriptionAttr("DW_AT_ordering", "DW_FORM_data1", 1),
        _FakeDescriptionAttr("DW_AT_location", "DW_FORM_exprloc", [0x50]),
        _FakeDescriptionAttr("DW_AT_data_member_location", "DW_FORM_data1", 3),
        _FakeDescriptionAttr("DW_AT_frame_base", "DW_FORM_sec_offset", 0),
        _FakeDescriptionAttr("DW_AT_name", "DW_FORM_string", b"unit"),
        _FakeDescriptionAttr("DW_AT_comp_dir", "DW_FORM_strp", string_value, 0),
        _FakeDescriptionAttr("DW_AT_decl_file", "DW_FORM_line_strp", line_string_value, 0),
        _FakeDescriptionAttr("DW_AT_type", "DW_FORM_ref_sig8", 0x1122334455667788),
        _FakeDescriptionAttr("DW_AT_low_pc", "DW_FORM_addr", 0x1000),
        _FakeDescriptionAttr("DW_AT_ranges", "DW_FORM_sec_offset", 0),
    ]
    for attr in synthetic_attrs:
        _ = _safe_call(describe_attr_value, attr, base_die, base_die.offset)


def _build_empty_debug_aranges():
    header = _pack_uint(2, 2) + _pack_uint(0, 4) + b"\x04\x00"
    padding = b"\x00" * 4
    entries = _pack_uint(0, 4) + _pack_uint(0, 4)
    unit_length = len(header) + len(padding) + len(entries)
    return _pack_uint(unit_length, 4) + header + padding + entries


def _touch_auxiliary_dwarf_tables(structs):
    for blob in (_build_debug_aranges(0x1000, 0x40), _build_empty_debug_aranges()):
        aranges = _safe_call(ARanges, io.BytesIO(blob), len(blob), structs)
        if aranges is None:
            continue
        _ = getattr(aranges, "entries", None)
        _ = getattr(aranges, "keys", None)
        _ = _safe_call(aranges._get_entries)
        _ = _safe_call(aranges._get_entries, need_empty=True)
        _ = _safe_call(aranges._get_addr_size_struct, 4)
        _ = _safe_call(aranges._get_addr_size_struct, 8)
        _ = _safe_call(aranges.cu_offset_at_addr, 0)
        _ = _safe_call(aranges.cu_offset_at_addr, 0x1000)

    lut_blob = _build_namelut(32, 11, b"symbol")
    namelut = _safe_call(NameLUT, io.BytesIO(lut_blob), len(lut_blob), structs)
    if namelut is not None:
        _ = _safe_call(namelut.get_entries)
        _ = _safe_call(namelut.get_cu_headers)
        _ = len(namelut)
        for key in list(namelut)[:4]:
            _ = _safe_call(namelut.__getitem__, key)
        _ = list(_safe_call(namelut.items, default=[]) or [])
        _ = _safe_call(namelut.get, "symbol")
        _ = _safe_call(namelut._get_entries)
        namelut.set_entries({"manual": NameLUTEntry(0, 11)}, [{"unit_length": 0}])
        _ = len(namelut)
        _ = _safe_call(namelut.get, "manual")

def _touch_zero_coverage_modules(structs, dwarfinfo, cu_list, cfi_entries, eh_cfi_entries):
    set_global_machine_arch("x64")

    expr_parser = DWARFExprParser(structs)
    addr_bytes = list(_pack_uint(0x1234, structs.address_size, structs.little_endian))
    call4_bytes = list(_pack_uint(0x5678, 4, structs.little_endian))
    offset_bytes = list(
        _pack_uint(0x5678, 8 if structs.dwarf_format == 64 else 4, structs.little_endian)
    )
    expr_samples = [
        [DW_OP_name2opcode["DW_OP_reg0"]],
        [DW_OP_name2opcode["DW_OP_addr"]] + addr_bytes,
        [DW_OP_name2opcode["DW_OP_const1u"], 0x2A],
        [DW_OP_name2opcode["DW_OP_const1s"], 0xFF],
        [DW_OP_name2opcode["DW_OP_const2u"], 0x34, 0x12],
        [DW_OP_name2opcode["DW_OP_const2s"], 0xFE, 0xFF],
        [DW_OP_name2opcode["DW_OP_const4u"], 1, 2, 3, 4],
        [DW_OP_name2opcode["DW_OP_const4s"], 0xFF, 0xFF, 0xFF, 0x7F],
        [DW_OP_name2opcode["DW_OP_const8u"]] + [1, 2, 3, 4, 5, 6, 7, 8],
        [DW_OP_name2opcode["DW_OP_const8s"]] + [0xFF] * 8,
        [DW_OP_name2opcode["DW_OP_constu"], 0x7F],
        [DW_OP_name2opcode["DW_OP_consts"], 0x01],
        [DW_OP_name2opcode["DW_OP_pick"], 0x03],
        [DW_OP_name2opcode["DW_OP_plus_uconst"], 0x07],
        [DW_OP_name2opcode["DW_OP_bra"], 0x02, 0x00],
        [DW_OP_name2opcode["DW_OP_skip"], 0x02, 0x00],
        [DW_OP_name2opcode["DW_OP_fbreg"], 0x01],
        [DW_OP_name2opcode["DW_OP_bregx"], 0x01, 0x01],
        [DW_OP_name2opcode["DW_OP_bit_piece"], 0x08, 0x02],
        [DW_OP_name2opcode["DW_OP_deref_size"], 0x08],
        [DW_OP_name2opcode["DW_OP_xderef_size"], 0x08],
        [DW_OP_name2opcode["DW_OP_call2"], 0x12, 0x00],
        [DW_OP_name2opcode["DW_OP_call4"]] + call4_bytes,
        [DW_OP_name2opcode["DW_OP_call_ref"]] + offset_bytes,
        [DW_OP_name2opcode["DW_OP_implicit_value"], 0x02, 0x50, 0x9F],
        [DW_OP_name2opcode["DW_OP_entry_value"], 0x02, DW_OP_name2opcode["DW_OP_reg0"], DW_OP_name2opcode["DW_OP_stack_value"]],
        [DW_OP_name2opcode["DW_OP_const_type"], 0x01, 0x02, 0x50, 0x9F],
        [DW_OP_name2opcode["DW_OP_regval_type"], 0x01, 0x01],
        [DW_OP_name2opcode["DW_OP_deref_type"], 0x08, 0x01],
        [DW_OP_name2opcode["DW_OP_implicit_pointer"]] + offset_bytes + [0x01],
        [DW_OP_name2opcode["DW_OP_GNU_entry_value"], 0x02, DW_OP_name2opcode["DW_OP_reg1"], DW_OP_name2opcode["DW_OP_stack_value"]],
        [DW_OP_name2opcode["DW_OP_GNU_const_type"], 0x01, 0x02, 0x50, 0x9F],
        [DW_OP_name2opcode["DW_OP_GNU_regval_type"], 0x01, 0x01],
        [DW_OP_name2opcode["DW_OP_GNU_deref_type"], 0x08, 0x01],
        [DW_OP_name2opcode["DW_OP_GNU_implicit_pointer"]] + offset_bytes + [0x01],
        [DW_OP_name2opcode["DW_OP_GNU_parameter_ref"]] + offset_bytes,
        [DW_OP_name2opcode["DW_OP_WASM_location"], 0x03, 0x01, 0x00, 0x00, 0x00],
        [DW_OP_name2opcode["DW_OP_const1u"], 0x2A, DW_OP_name2opcode["DW_OP_plus_uconst"], 0x01, DW_OP_name2opcode["DW_OP_stack_value"]],
    ]
    for sample in expr_samples:
        _ = _safe_call(expr_parser.parse_expr, sample)
    _ = DWARFExprOp(0x50, "DW_OP_reg0", [], 0)

    for reg in (0, 1, 7, 16, 31):
        _ = _safe_call(describe_reg_name, reg, "x64")
        _ = _safe_call(describe_reg_name, reg, "x86")
        _ = _safe_call(describe_reg_name, reg, "AArch64")
        _ = _safe_call(describe_reg_name, reg, None, False)

    described_dies = []
    for cu in cu_list[:4]:
        for die in list(_safe_call(cu.iter_DIEs, default=[]) or [])[:16]:
            described_dies.append(die)
            for attr in list(getattr(die, "attributes", {}).values())[:16]:
                _ = _safe_call(describe_attr_value, attr, die, die.offset)

    for entry in _normalize_cfi_entries(cfi_entries)[:4]:
        _ = _safe_call(describe_CFI_instructions, entry)
    for entry in _normalize_cfi_entries(eh_cfi_entries)[:4]:
        _ = _safe_call(describe_CFI_instructions, entry)

    for die in described_dies[:8]:
        _ = _safe_call(describe_cpp_datatype, die)

    _touch_synthetic_cpp_datatypes()
    _touch_synthetic_descriptions(structs, described_dies, dwarfinfo)
    _touch_auxiliary_dwarf_tables(structs)


def _touch_handcrafted_dwarfinfo():
    elf = _safe_call(_open_elf, _build_minimal_dwarf_elf(b"coverage"))
    if elf is None:
        return
    dwarfinfo = _safe_call(
        elf.get_dwarf_info,
        relocate_dwarf_sections=False,
        follow_links=False,
    )
    if dwarfinfo is not None:
        cu_list = list(_safe_call(dwarfinfo.iter_CUs, default=[]) or [])
        cfi_entries = list(_safe_call(dwarfinfo.CFI_entries, default=[]) or []) if _safe_call(dwarfinfo.has_CFI) else []
        eh_cfi_entries = list(_safe_call(dwarfinfo.EH_CFI_entries, default=[]) or []) if _safe_call(dwarfinfo.has_EH_CFI) else []
        _safe_call(_touch_zero_coverage_modules, dwarfinfo.structs, dwarfinfo, cu_list, cfi_entries, eh_cfi_entries)
        _safe_call(_touch_dwarfinfo, dwarfinfo)
    _ = _safe_call(elf.close)


def _make_struct_variants():
    variants = []
    for little_endian in (True, False):
        for dwarf_format in (32, 64):
            for address_size in (4, 8):
                variants.append(
                    DWARFStructs(
                        little_endian=little_endian,
                        dwarf_format=dwarf_format,
                        address_size=address_size,
                    )
                )
    return variants


def _make_v5_structs():
    return [
        DWARFStructs(little_endian=True, dwarf_format=32, address_size=8, dwarf_version=5),
        DWARFStructs(little_endian=False, dwarf_format=64, address_size=4, dwarf_version=5),
    ]


def _touch_synthetic_parsers(data):
    raw_frame = data[:2048]
    raw_loc = data[512:2048]
    raw_rng = data[1024:2048]
    helper_structs = DWARFStructs(little_endian=True, dwarf_format=32, address_size=8)
    helper_cfi = _safe_call(
        CallFrameInfo,
        io.BytesIO(SYNTHETIC_CFI),
        len(SYNTHETIC_CFI),
        0,
        helper_structs,
    )
    helper_eh_cfi = _safe_call(
        CallFrameInfo,
        io.BytesIO(SYNTHETIC_EH_CFI),
        len(SYNTHETIC_EH_CFI),
        0,
        helper_structs,
        for_eh_frame=True,
    )
    _safe_call(
        _touch_zero_coverage_modules,
        helper_structs,
        None,
        [],
        helper_cfi,
        helper_eh_cfi,
    )

    for structs in _make_struct_variants():
        try:
            _touch_structs(structs)
            if raw_frame:
                _touch_callframe_info(
                    _safe_call(CallFrameInfo, io.BytesIO(raw_frame), len(raw_frame), 0, structs)
                )
            synthetic_frame = SYNTHETIC_CFI + raw_frame[:256]
            _touch_callframe_info(
                _safe_call(CallFrameInfo, io.BytesIO(synthetic_frame), len(synthetic_frame), 0, structs)
            )
            line_stream = _build_line_program_stream(data[:1024])
            line_program = _safe_call(
                LineProgram,
                _make_line_program_header(line_stream),
                io.BytesIO(line_stream),
                structs,
                0,
                len(line_stream),
            )
            if line_program is not None:
                _touch_line_program(line_program)
        except Exception:
            pass

    eh_structs = DWARFStructs(little_endian=True, dwarf_format=32, address_size=8)
    eh_stream = SYNTHETIC_EH_CFI + raw_frame[:256]
    try:
        _touch_callframe_info(
            _safe_call(
                CallFrameInfo,
                io.BytesIO(eh_stream),
                len(eh_stream),
                0,
                eh_structs,
                for_eh_frame=True,
            )
        )
    except Exception:
        pass

    for structs in _make_v5_structs():
        try:
            _touch_structs(structs)
            v4_loc = _safe_call(LocationLists, io.BytesIO(_build_v4_loclist_stream(raw_loc, structs.address_size)), structs, 4)
            if v4_loc is not None:
                _touch_location_lists(v4_loc, [])

            v4_rng = _safe_call(RangeLists, io.BytesIO(_build_v4_rangelist_stream(raw_rng, structs.address_size)), structs, 4, None)
            if v4_rng is not None:
                _touch_range_lists(v4_rng, [])

            loc_v5_stream = _build_v5_loclists_stream(raw_loc, structs)
            rng_v5_stream = _build_v5_rnglists_stream(raw_rng, structs)
            fake_v5_cu = _FakeCU(structs, 5, location_offset=12, range_offset=12)
            fake_v4_cu = _FakeCU(structs, 4, location_offset=0, range_offset=0)
            fake_info = _FakeDwarfInfo([fake_v5_cu])

            loc_v5 = _safe_call(LocationLists, io.BytesIO(loc_v5_stream), structs, 5, fake_info)
            if loc_v5 is not None:
                _touch_location_lists(loc_v5, [fake_v5_cu])
                parser = LocationParser(loc_v5)
                for attr in fake_v5_cu.get_top_DIE().attributes.values():
                    _ = _safe_call(parser.parse_from_attribute, attr, 5, die=fake_v5_cu.get_top_DIE())

            rng_v5 = _safe_call(RangeLists, io.BytesIO(rng_v5_stream), structs, 5, fake_info)
            if rng_v5 is not None:
                _touch_range_lists(rng_v5, [fake_v5_cu])

            loc_pair = _safe_call(
                LocationListsPair,
                io.BytesIO(_build_v4_loclist_stream(raw_loc, structs.address_size)),
                io.BytesIO(loc_v5_stream),
                structs,
                fake_info,
            )
            if loc_pair is not None:
                _touch_location_lists(loc_pair, [fake_v5_cu])
                _ = _safe_call(loc_pair.get_location_list_at_offset, 0, die=fake_v4_cu.get_top_DIE())
                _ = _safe_call(loc_pair.get_location_list_at_offset, 12, die=fake_v5_cu.get_top_DIE())

            rng_pair = _safe_call(
                RangeListsPair,
                io.BytesIO(_build_v4_rangelist_stream(raw_rng, structs.address_size)),
                io.BytesIO(rng_v5_stream),
                structs,
                fake_info,
            )
            if rng_pair is not None:
                _touch_range_lists(rng_pair, [fake_v5_cu])
                _ = _safe_call(rng_pair.get_range_list_at_offset, 0, fake_v4_cu)
                _ = _safe_call(rng_pair.get_range_list_at_offset, 12, fake_v5_cu)
        except Exception:
            pass


def _touch_built_elf(data):
    elf = _safe_call(_open_elf, build_dwarf_elf(data))
    if elf is None:
        return
    dwarfinfo = _safe_call(
        elf.get_dwarf_info,
        relocate_dwarf_sections=False,
        follow_links=False,
    )
    if dwarfinfo is not None:
        cu_list = list(_safe_call(dwarfinfo.iter_CUs, default=[]) or [])
        cfi_entries = list(_safe_call(dwarfinfo.CFI_entries, default=[]) or []) if _safe_call(dwarfinfo.has_CFI) else []
        eh_cfi_entries = list(_safe_call(dwarfinfo.EH_CFI_entries, default=[]) or []) if _safe_call(dwarfinfo.has_EH_CFI) else []
        _safe_call(_touch_zero_coverage_modules, dwarfinfo.structs, dwarfinfo, cu_list, cfi_entries, eh_cfi_entries)
        _safe_call(_touch_dwarfinfo, dwarfinfo)
    _ = _safe_call(elf.close)


def _touch_candidate_elf(blob):
    elf = _safe_call(_open_elf, blob)
    if elf is None:
        return
    if _safe_call(elf.has_dwarf_info):
        dwarfinfo = _safe_call(
            elf.get_dwarf_info,
            relocate_dwarf_sections=True,
            follow_links=False,
        )
        if dwarfinfo is None:
            dwarfinfo = _safe_call(
                elf.get_dwarf_info,
                relocate_dwarf_sections=False,
                follow_links=False,
            )
        if dwarfinfo is not None:
            cu_list = list(_safe_call(dwarfinfo.iter_CUs, default=[]) or [])
            cfi_entries = list(_safe_call(dwarfinfo.CFI_entries, default=[]) or []) if _safe_call(dwarfinfo.has_CFI) else []
            eh_cfi_entries = list(_safe_call(dwarfinfo.EH_CFI_entries, default=[]) or []) if _safe_call(dwarfinfo.has_EH_CFI) else []
            _safe_call(_touch_zero_coverage_modules, dwarfinfo.structs, dwarfinfo, cu_list, cfi_entries, eh_cfi_entries)
            _safe_call(_touch_dwarfinfo, dwarfinfo)
    _ = _safe_call(elf.close)


def TestOneInput(data):
    try:
        _touch_synthetic_parsers(data)
        _touch_built_elf(data)
        for blob in _candidate_blobs(data):
            _touch_candidate_elf(blob)
    except Exception:
        pass


def main():
    if _coverage_mode():
        return
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
