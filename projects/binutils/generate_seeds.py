#!/usr/bin/env python3
# Copyright 2026 Google LLC
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
# Generates structured seed corpora for the binutils OSS-Fuzz fuzz targets,
# built from scratch (no cross-toolchain). The historical general_seeds.zip is
# x86-dominated and ships only fully-linked binaries, leaving the per-arch BFD
# ELF backends, the DWARF readers, ELF metadata paths, and the unseeded
# fuzz_as/fuzz_dlltool harnesses dark. This script emits, under seeds/<group>/:
#
#   elf_reloc/  relocatable ELF across ~50 architectures, each .rela/.rel
#               spanning the arch's reloc types  -> elfNN-<arch>.c howtos
#   dwarf/      ELF with a wide set of .debug_* sections (v4/v5)  -> dwarf.c
#   elf_meta/   object attributes, notes, symbol versioning, .dynamic
#   archive/    ar archives wrapping the above
#   gas/        i386 assembly (.s)        -> fuzz_as
#   dlltool/    module-definition (.def)  -> fuzz_dlltool
#
# Usage: generate_seeds.py <fuzz-corpus-root>

import os
import struct
import sys


# ──────────────────────────────────────────────────────────────────────────
#  ELF constants
# ──────────────────────────────────────────────────────────────────────────
ELFCLASS32, ELFCLASS64 = 1, 2
ELFDATA2LSB, ELFDATA2MSB = 1, 2
ET_REL = 1
EV_CURRENT = 1

SHT_PROGBITS = 1
SHT_SYMTAB = 2
SHT_STRTAB = 3
SHT_RELA = 4
SHT_NOBITS = 8
SHT_REL = 9

SHF_WRITE = 0x1
SHF_ALLOC = 0x2
SHF_EXECINSTR = 0x4

STB_GLOBAL = 1
STT_NOTYPE, STT_OBJECT, STT_FUNC, STT_SECTION = 0, 1, 2, 3

# EM_*, ELF class, ELF data (endianness), and the highest relocation type
# number worth emitting for each architecture (from include/elf/<arch>.h).
# Format: name -> (e_machine, elfclass, data, use_rela, max_reloc, e_flags)
ARCHES = {
    "riscv64":      (243, ELFCLASS64, ELFDATA2LSB, True,  65,  0),
    "riscv32":      (243, ELFCLASS32, ELFDATA2LSB, True,  65,  0),
    "loongarch64":  (258, ELFCLASS64, ELFDATA2LSB, True,  130, 0),
    "loongarch32":  (258, ELFCLASS32, ELFDATA2LSB, True,  130, 0),
    "csky":         (252, ELFCLASS32, ELFDATA2LSB, True,  64,  0),
    "aarch64":      (183, ELFCLASS64, ELFDATA2LSB, True,  600, 0),
    "ppc64":        (21,  ELFCLASS64, ELFDATA2LSB, True,  254, 0),
    "ppc":          (20,  ELFCLASS32, ELFDATA2MSB, True,  255, 0),
    "mips":         (8,   ELFCLASS32, ELFDATA2MSB, False, 254, 0),
    "mips64":       (8,   ELFCLASS64, ELFDATA2MSB, True,  254, 0),
    "arm":          (40,  ELFCLASS32, ELFDATA2LSB, False, 255, 0),
    "s390":         (22,  ELFCLASS64, ELFDATA2MSB, True,  90,  0),
    "sparc":        (2,   ELFCLASS32, ELFDATA2MSB, True,  252, 0),
    "sparcv9":      (43,  ELFCLASS64, ELFDATA2MSB, True,  252, 0),
    "sh":           (42,  ELFCLASS32, ELFDATA2LSB, True,  255, 0),
    "m68k":         (4,   ELFCLASS32, ELFDATA2MSB, True,  68,  0),
    "microblaze":   (189, ELFCLASS32, ELFDATA2MSB, True,  33,  0),
    # Additional architectures whose BFD ELF backends are fully dark (0%) or
    # near-dark in the production OSS-Fuzz coverage report, simply because the
    # corpus contains no object of that machine type.  e_machine + endianness
    # must match the canonical target or BFD will not select the backend.
    "pru":          (144, ELFCLASS32, ELFDATA2LSB, True,  40,  0),
    "ip2k":         (101, ELFCLASS32, ELFDATA2MSB, True,  14,  0),
    "fr30":         (84,  ELFCLASS32, ELFDATA2MSB, True,  12,  0),
    "m68hc11":      (70,  ELFCLASS32, ELFDATA2MSB, True,  24,  0),
    "xstormy16":    (0xad45, ELFCLASS32, ELFDATA2LSB, True, 129, 0),
    "epiphany":     (0x1223, ELFCLASS32, ELFDATA2LSB, True, 16, 0),
    "ft32":         (222, ELFCLASS32, ELFDATA2LSB, True,  14,  0),
    "moxie":        (223, ELFCLASS32, ELFDATA2MSB, True,  4,   0),
    "rx":           (173, ELFCLASS32, ELFDATA2LSB, True,  40,  0),
    "rl78":         (197, ELFCLASS32, ELFDATA2LSB, True,  40,  0),
    "mn10300":      (89,  ELFCLASS32, ELFDATA2LSB, True,  36,  0),
    "cr16":         (177, ELFCLASS32, ELFDATA2LSB, True,  32,  0),
    "crx":          (114, ELFCLASS32, ELFDATA2LSB, True,  20,  0),
    "mep":          (0xF00D, ELFCLASS32, ELFDATA2MSB, True, 24, 0),
    "nds32":        (167, ELFCLASS32, ELFDATA2LSB, True,  60,  0),
    "or1k":         (92,  ELFCLASS32, ELFDATA2MSB, True,  56,  0),
    "m32r":         (88,  ELFCLASS32, ELFDATA2MSB, True,  50,  0),
    "tilegx":       (191, ELFCLASS64, ELFDATA2LSB, True,  130, 0),
    "tilepro":      (188, ELFCLASS32, ELFDATA2LSB, True,  90,  0),
    "metag":        (174, ELFCLASS32, ELFDATA2LSB, True,  62,  0),
    "vax":          (75,  ELFCLASS32, ELFDATA2LSB, True,  12,  0),
    "frv":          (0x5441, ELFCLASS32, ELFDATA2MSB, True, 60, 0),
    # Iteration 3: further dark ELF backends (elf32-xtensa.c 6893 lines @0%,
    # elf32/64-kvx.c, elf32-arc.c, elf32-v850.c, elf32-score.c, ...).
    "xtensa":       (94,  ELFCLASS32, ELFDATA2LSB, True,  60,  0),
    "arc":          (93,  ELFCLASS32, ELFDATA2LSB, True,  60,  0),  # EM_ARC_COMPACT
    "avr":          (83,  ELFCLASS32, ELFDATA2LSB, True,  40,  0),
    "cris":         (76,  ELFCLASS32, ELFDATA2LSB, True,  40,  0),
    "d10v":         (85,  ELFCLASS32, ELFDATA2MSB, True,  20,  0),
    "h8300":        (46,  ELFCLASS32, ELFDATA2MSB, True,  30,  0),
    "iq2000":       (0xFEBA, ELFCLASS32, ELFDATA2MSB, True, 20, 0),
    "kvx":          (256, ELFCLASS64, ELFDATA2LSB, True,  100, 0),
    "lm32":         (138, ELFCLASS32, ELFDATA2MSB, True,  30,  0),
    "m32c":         (120, ELFCLASS32, ELFDATA2LSB, True,  30,  0),
    "msp430":       (105, ELFCLASS32, ELFDATA2LSB, True,  40,  0),
    "mt":           (0x2530, ELFCLASS32, ELFDATA2MSB, True, 12, 0),
    "score":        (135, ELFCLASS32, ELFDATA2LSB, True,  40,  0),
    "v850":         (87,  ELFCLASS32, ELFDATA2LSB, True,  40,  0),
    "bpf":          (247, ELFCLASS64, ELFDATA2LSB, True,  12,  0),
    # Matching seeds for the arch-targeted readelf fuzzers (mmix, big-endian
    # arm); csky and little-endian arm are already covered above.
    "mmix":         (80,  ELFCLASS64, ELFDATA2MSB, True,  40,  0),
    "armbe":        (40,  ELFCLASS32, ELFDATA2MSB, False, 255, 0),
}


class StringTable:
    """An ELF string table: index 0 is the empty string."""

    def __init__(self):
        self.buf = bytearray(b"\x00")
        self.offsets = {"": 0}

    def add(self, s):
        if s in self.offsets:
            return self.offsets[s]
        off = len(self.buf)
        self.offsets[s] = off
        self.buf += s.encode() + b"\x00"
        return off

    def bytes(self):
        return bytes(self.buf)


class ElfObject:
    """Builds a minimal but structurally valid ET_REL ELF object.

    Sections are appended in order; offsets and the section header table are
    laid out by build().  Section index 0 is the reserved SHN_UNDEF entry.
    """

    def __init__(self, e_machine, elfclass=ELFCLASS64, data=ELFDATA2LSB,
                 e_flags=0):
        self.machine = e_machine
        self.elfclass = elfclass
        self.data = data
        self.e_flags = e_flags
        self.end = "<" if data == ELFDATA2LSB else ">"
        self.is64 = elfclass == ELFCLASS64
        self.shstrtab = StringTable()
        # Each section: dict(name, type, flags, link, info, addralign,
        #                    entsize, data)
        self.sections = [dict(name="", type=0, flags=0, link=0, info=0,
                              addralign=0, entsize=0, data=b"")]

    def add_section(self, name, stype, data=b"", flags=0, link=0, info=0,
                    addralign=1, entsize=0):
        self.shstrtab.add(name)
        self.sections.append(dict(name=name, type=stype, flags=flags,
                                   link=link, info=info, addralign=addralign,
                                   entsize=entsize, data=bytes(data)))
        return len(self.sections) - 1

    def section_index(self, name):
        for i, s in enumerate(self.sections):
            if s["name"] == name:
                return i
        return 0

    def build(self):
        e = self.end
        # Append the section-header string table as the final section.
        shstr_idx = len(self.sections)
        self.shstrtab.add(".shstrtab")
        self.sections.append(dict(name=".shstrtab", type=SHT_STRTAB,
                                   flags=0, link=0, info=0, addralign=1,
                                   entsize=0, data=self.shstrtab.bytes()))

        ehsize = 64 if self.is64 else 52
        shentsize = 64 if self.is64 else 40

        # Lay out section payloads after the ELF header.
        offset = ehsize
        for s in self.sections:
            if s["type"] == 0 or s["type"] == SHT_NOBITS:
                s["offset"] = 0 if s["type"] == 0 else offset
                continue
            align = max(s["addralign"], 1)
            if offset % align:
                offset += align - (offset % align)
            s["offset"] = offset
            offset += len(s["data"])

        # Section header table goes after all payloads, 8-byte aligned.
        if offset % 8:
            offset += 8 - (offset % 8)
        shoff = offset

        # ELF header.
        ident = bytearray(16)
        ident[0:4] = b"\x7fELF"
        ident[4] = self.elfclass
        ident[5] = self.data
        ident[6] = EV_CURRENT
        out = bytearray(ident)
        if self.is64:
            out += struct.pack(e + "HHIQQQIHHHHHH",
                               ET_REL, self.machine, EV_CURRENT,
                               0, 0, shoff, self.e_flags,
                               ehsize, 0, 0, shentsize,
                               len(self.sections), shstr_idx)
        else:
            out += struct.pack(e + "HHIIIIIHHHHHH",
                               ET_REL, self.machine, EV_CURRENT,
                               0, 0, shoff, self.e_flags,
                               ehsize, 0, 0, shentsize,
                               len(self.sections), shstr_idx)

        # Section payloads.
        for s in self.sections:
            if s["type"] == 0 or s["type"] == SHT_NOBITS:
                continue
            while len(out) < s["offset"]:
                out += b"\x00"
            out += s["data"]

        # Section header table.
        while len(out) < shoff:
            out += b"\x00"
        for s in self.sections:
            name_off = self.shstrtab.offsets[s["name"]]
            size = 0 if s["type"] == 0 else len(s["data"])
            if self.is64:
                out += struct.pack(e + "IIQQQQIIQQ",
                                   name_off, s["type"], s["flags"], 0,
                                   s["offset"], size, s["link"], s["info"],
                                   s["addralign"], s["entsize"])
            else:
                out += struct.pack(e + "IIIIIIIIII",
                                   name_off, s["type"], s["flags"], 0,
                                   s["offset"], size, s["link"], s["info"],
                                   s["addralign"], s["entsize"])
        return bytes(out)

    # ── symbol / relocation helpers ──────────────────────────────────────

    def sym(self, name_off, info, shndx, value=0, size=0):
        e = self.end
        if self.is64:
            return struct.pack(e + "IBBHQQ", name_off, info, 0, shndx,
                               value, size)
        return struct.pack(e + "IIIBBH", name_off, value, size, info, 0,
                           shndx)

    def r_info(self, symidx, rtype):
        if self.is64:
            return (symidx << 32) | (rtype & 0xffffffff)
        return (symidx << 8) | (rtype & 0xff)

    def rela(self, offset, symidx, rtype, addend=0):
        e = self.end
        if self.is64:
            return struct.pack(e + "QQq", offset, self.r_info(symidx, rtype),
                               addend)
        return struct.pack(e + "IIi", offset, self.r_info(symidx, rtype),
                           addend)

    def rel(self, offset, symidx, rtype):
        e = self.end
        if self.is64:
            return struct.pack(e + "QQ", offset, self.r_info(symidx, rtype))
        return struct.pack(e + "II", offset, self.r_info(symidx, rtype))


# ──────────────────────────────────────────────────────────────────────────
#  Multi-architecture relocatable objects
# ──────────────────────────────────────────────────────────────────────────
def make_reloc_object(arch):
    """A relocatable ELF object whose relocation section spans the
    architecture's reloc type range, exercising elfNN-<arch>.c howto lookups
    and the generic reloc readers in objdump/readelf."""
    machine, elfclass, data, use_rela, max_reloc, eflags = ARCHES[arch]
    obj = ElfObject(machine, elfclass, data, eflags)

    # .text with a little content for relocs to point at.
    text = obj.add_section(".text", SHT_PROGBITS, b"\x00" * 256,
                           flags=SHF_ALLOC | SHF_EXECINSTR, addralign=4)
    obj.add_section(".data", SHT_PROGBITS, b"\x00" * 64,
                    flags=SHF_ALLOC | SHF_WRITE, addralign=4)

    # Symbol + string tables: one section symbol, a few named globals.
    strtab = StringTable()
    syms = [obj.sym(0, 0, 0)]                              # null symbol
    syms.append(obj.sym(0, (STB_GLOBAL << 4) | STT_SECTION, text))
    names = ["foo", "bar", "_start", "data_sym"]
    first_global = len(syms)
    for n in names:
        no = strtab.add(n)
        syms.append(obj.sym(no, (STB_GLOBAL << 4) | STT_FUNC, text, 0, 4))
    strtab_idx = obj.add_section(".strtab", SHT_STRTAB, strtab.bytes())
    symtab_idx = obj.add_section(
        ".symtab", SHT_SYMTAB, b"".join(syms), link=strtab_idx,
        info=first_global, addralign=8,
        entsize=24 if obj.is64 else 16)

    # Relocation section spanning the architecture's reloc types.
    nsyms = len(syms)
    entries = []
    off = 0
    for rtype in range(0, max_reloc + 1):
        symidx = 1 + (rtype % (nsyms - 1)) if nsyms > 1 else 0
        if use_rela:
            entries.append(obj.rela(off % 256, symidx, rtype, addend=rtype))
        else:
            entries.append(obj.rel(off % 256, symidx, rtype))
        off += 4
    if use_rela:
        obj.add_section(".rela.text", SHT_RELA, b"".join(entries),
                        link=symtab_idx, info=text, addralign=8,
                        entsize=24 if obj.is64 else 12)
    else:
        obj.add_section(".rel.text", SHT_REL, b"".join(entries),
                        link=symtab_idx, info=text, addralign=4,
                        entsize=16 if obj.is64 else 8)
    return obj.build()


# ──────────────────────────────────────────────────────────────────────────
#  DWARF debug information
# ──────────────────────────────────────────────────────────────────────────
def _uleb(v):
    out = bytearray()
    while True:
        b = v & 0x7f
        v >>= 7
        if v:
            out.append(b | 0x80)
        else:
            out.append(b)
            break
    return bytes(out)


# DWARF constants
DW_TAG_compile_unit = 0x11
DW_TAG_subprogram = 0x2e
DW_TAG_base_type = 0x24
DW_TAG_variable = 0x34
DW_CHILDREN_yes, DW_CHILDREN_no = 1, 0
DW_AT_name = 0x03
DW_AT_producer = 0x25
DW_AT_language = 0x13
DW_AT_low_pc = 0x11
DW_AT_high_pc = 0x12
DW_AT_comp_dir = 0x1b
DW_AT_stmt_list = 0x10
DW_AT_byte_size = 0x0b
DW_AT_encoding = 0x3e
DW_AT_type = 0x49
DW_FORM_addr = 0x01
DW_FORM_data1 = 0x0b
DW_FORM_data2 = 0x05
DW_FORM_data4 = 0x06
DW_FORM_string = 0x08
DW_FORM_strp = 0x0e
DW_FORM_ref4 = 0x13
DW_FORM_sec_offset = 0x17


def make_dwarf_object(version=4, is64=True):
    """ELF object with hand-built DWARF .debug_* sections, exercising the
    DWARF readers in binutils/dwarf.c and bfd/dwarf2.c."""
    machine = 62 if is64 else 3            # x86-64 / i386 host arches
    elfclass = ELFCLASS64 if is64 else ELFCLASS32
    obj = ElfObject(machine, elfclass, ELFDATA2LSB)
    obj.add_section(".text", SHT_PROGBITS, b"\x90" * 64,
                    flags=SHF_ALLOC | SHF_EXECINSTR, addralign=16)

    dstr = StringTable()
    p_off = dstr.add("GNU C generated-seed " + str(version))
    n_off = dstr.add("seed.c")
    cd_off = dstr.add("/seed")

    # .debug_abbrev: one CU abbrev (code 1) + one base_type (code 2).
    abbrev = bytearray()
    abbrev += _uleb(1) + _uleb(DW_TAG_compile_unit) + bytes([DW_CHILDREN_yes])
    for at, form in [(DW_AT_producer, DW_FORM_strp),
                     (DW_AT_language, DW_FORM_data2),
                     (DW_AT_name, DW_FORM_strp),
                     (DW_AT_comp_dir, DW_FORM_strp),
                     (DW_AT_low_pc, DW_FORM_addr),
                     (DW_AT_high_pc, DW_FORM_data4),
                     (DW_AT_stmt_list, DW_FORM_sec_offset)]:
        abbrev += _uleb(at) + _uleb(form)
    abbrev += _uleb(0) + _uleb(0)
    abbrev += _uleb(2) + _uleb(DW_TAG_base_type) + bytes([DW_CHILDREN_no])
    for at, form in [(DW_AT_byte_size, DW_FORM_data1),
                     (DW_AT_encoding, DW_FORM_data1),
                     (DW_AT_name, DW_FORM_string)]:
        abbrev += _uleb(at) + _uleb(form)
    abbrev += _uleb(0) + _uleb(0)
    abbrev += _uleb(0)        # end of abbrev table

    addr_size = 8 if is64 else 4
    # .debug_info CU body (after the unit-length + header fields).
    body = bytearray()
    body += _uleb(1)                                  # abbrev code 1 (CU)
    body += struct.pack("<I", p_off)                  # producer (strp)
    body += struct.pack("<H", 0x0c)                   # language = C99
    body += struct.pack("<I", n_off)                  # name (strp)
    body += struct.pack("<I", cd_off)                 # comp_dir (strp)
    body += struct.pack("<Q" if is64 else "<I", 0)    # low_pc
    body += struct.pack("<I", 64)                     # high_pc (data4)
    body += struct.pack("<I", 0)                      # stmt_list -> .debug_line
    body += _uleb(2)                                  # abbrev code 2 (base)
    body += bytes([4, 5]) + b"int\x00"                # byte_size, enc, name
    body += _uleb(0)                                  # end of children

    info = bytearray()
    if version >= 5:
        # DWARF5 CU header: unit_length, version, unit_type, addr_size,
        # debug_abbrev_offset.
        hdr = struct.pack("<HBBI", version, 0x01, addr_size, 0)
    else:
        # DWARF<=4 CU header: unit_length, version, debug_abbrev_offset,
        # addr_size.
        hdr = struct.pack("<HIB", version, 0, addr_size)
    unit = hdr + bytes(body)
    info += struct.pack("<I", len(unit)) + unit

    # .debug_line: minimal v4/v5 line program header + a couple opcodes.
    line = _make_debug_line(version)

    obj.add_section(".debug_abbrev", SHT_PROGBITS, bytes(abbrev))
    obj.add_section(".debug_info", SHT_PROGBITS, bytes(info))
    obj.add_section(".debug_str", SHT_PROGBITS, dstr.bytes())
    obj.add_section(".debug_line", SHT_PROGBITS, line)

    # objdump's dwarf_select_sections_all() dumps each section independently,
    # so every one drives its own display_debug_* reader in dwarf.c.
    for name, data in _extra_dwarf_sections(version, is64):
        obj.add_section(name, SHT_PROGBITS, data)
    return obj.build()


def _sleb(v):
    out = bytearray()
    more = True
    while more:
        b = v & 0x7f
        v >>= 7
        if (v == 0 and not (b & 0x40)) or (v == -1 and (b & 0x40)):
            more = False
        else:
            b |= 0x80
        out.append(b)
    return bytes(out)


def _extra_dwarf_sections(version, is64):
    """A wide set of minimal-but-parseable DWARF sections, one per
    display_debug_* reader in dwarf.c (a tolerant dumper)."""
    asz = 8 if is64 else 4
    A = (lambda v: struct.pack("<Q", v)) if is64 else (lambda v: struct.pack("<I", v))
    out = []

    # .debug_aranges: header + a couple address/length pairs, 0,0 terminator.
    ar = bytearray()
    arbody = struct.pack("<HIBB", 2, 0, asz, 0)        # ver, info_off, asz, seg
    pad = (len(arbody) + 4) % (2 * asz)
    if pad:
        arbody += b"\x00" * (2 * asz - pad)
    arbody += A(0x1000) + A(0x40) + A(0) + A(0)
    ar += struct.pack("<I", len(arbody)) + arbody
    out.append((".debug_aranges", bytes(ar)))

    # .debug_pubnames / .debug_pubtypes: header + entries + 0 terminator.
    def pub(gnu):
        body = struct.pack("<HII", version if version < 5 else 2, 0, 64)
        for off, nm in ((0x1a, "foo"), (0x2b, "int")):
            body += struct.pack("<I", off)
            if gnu:
                body += bytes([0x30])           # GNU kind/flag byte
            body += nm.encode() + b"\x00"
        body += struct.pack("<I", 0)
        return struct.pack("<I", len(body)) + bytes(body)
    out.append((".debug_pubnames", pub(False)))
    out.append((".debug_pubtypes", pub(False)))
    out.append((".debug_gnu_pubnames", pub(True)))
    out.append((".debug_gnu_pubtypes", pub(True)))

    # .debug_ranges (DWARF<5): base-address selection + range + terminator.
    rng = bytearray()
    rng += A(0xffffffffffffffff if is64 else 0xffffffff) + A(0x1000)  # base sel
    rng += A(0x10) + A(0x20)                                          # range
    rng += A(0) + A(0)                                                # end
    out.append((".debug_ranges", bytes(rng)))

    # .debug_rnglists (DWARF5): unit header + DW_RLE ops + end_of_list.
    rl = bytearray()
    rlbody = struct.pack("<HBBI", 5, asz, 0, 0)        # ver, asz, seg, off_cnt
    rlbody += bytes([0x07]) + A(0x1000) + _uleb(0x40)  # DW_RLE_start_length
    rlbody += bytes([0x04]) + _uleb(0x10) + _uleb(0x20)  # DW_RLE_offset_pair
    rlbody += bytes([0x00])                            # DW_RLE_end_of_list
    rl += struct.pack("<I", len(rlbody)) + rlbody
    out.append((".debug_rnglists", bytes(rl)))

    # .debug_loc (DWARF<5): location list (addr pair + 2-byte expr) + end.
    loc = bytearray()
    loc += A(0x1000) + A(0x1010) + struct.pack("<H", 2) + bytes([0x03, 0x00])
    loc += A(0) + A(0)
    out.append((".debug_loc", bytes(loc)))

    # .debug_loclists (DWARF5): unit header + DW_LLE ops + end_of_list.
    ll = bytearray()
    llbody = struct.pack("<HBBI", 5, asz, 0, 0)
    expr = bytes([0x03]) + A(0x2000)                   # DW_OP_addr <addr>
    llbody += bytes([0x08]) + A(0x1000) + _uleb(0x40)  # DW_LLE_start_length
    llbody += _uleb(len(expr)) + expr
    llbody += bytes([0x00])                            # DW_LLE_end_of_list
    ll += struct.pack("<I", len(llbody)) + llbody
    out.append((".debug_loclists", bytes(ll)))

    # .debug_str_offsets (DWARF5): header + offset array.
    so = bytearray()
    sobody = struct.pack("<HH", 5, 0) + struct.pack("<III", 0, 4, 8)
    so += struct.pack("<I", len(sobody)) + sobody
    out.append((".debug_str_offsets", bytes(so)))

    # .debug_addr (DWARF5): header + address array.
    ad = bytearray()
    adbody = struct.pack("<HBB", 5, asz, 0) + A(0x1000) + A(0x2000)
    ad += struct.pack("<I", len(adbody)) + adbody
    out.append((".debug_addr", bytes(ad)))

    # .debug_line_str: plain string table (DWARF5).
    out.append((".debug_line_str", b"\x00seed.c\x00/seed\x00"))

    # .debug_frame: a CIE followed by an FDE.
    cie_body = bytes([version if version >= 3 else 1]) + b"\x00"   # ver, aug
    if version >= 4:
        cie_body = bytes([4]) + b"\x00" + bytes([asz, 0])         # +asz,seg
    cie_body += _uleb(1) + _sleb(-4) + _uleb(0)        # caf, daf, ret_reg
    cie_body += bytes([0x0c, 0x07, 0x00])              # DW_CFA_def_cfa r7,0
    cie = struct.pack("<II", len(cie_body) + 4, 0xffffffff) + cie_body
    fde_body = A(0x1000) + A(0x40) + bytes([0x0e, 0x10])  # loc,range,def_cfa_off
    fde = struct.pack("<II", len(fde_body) + 4, 0) + fde_body
    out.append((".debug_frame", bytes(cie) + bytes(fde)))

    # .debug_macro (DWARF5): header + DW_MACRO_define/undef + end (0).
    mc = bytearray()
    mc += struct.pack("<HB", 5, 0)                     # version, flags
    mc += bytes([0x01]) + _uleb(1) + b"FOO 1\x00"      # DW_MACRO_define
    mc += bytes([0x02]) + _uleb(1) + b"BAR\x00"        # DW_MACRO_undef
    mc += bytes([0x00])                                # end
    out.append((".debug_macro", bytes(mc)))

    # .debug_macinfo (DWARF<5): DW_MACINFO_define/undef + end (0).
    mi = bytearray()
    mi += bytes([0x01]) + _uleb(1) + b"FOO 1\x00"      # DW_MACINFO_define
    mi += bytes([0x02]) + _uleb(2) + b"BAR\x00"        # DW_MACINFO_undef
    mi += bytes([0x00])
    out.append((".debug_macinfo", bytes(mi)))

    # .debug_types (DWARF4 type unit): like a CU but with type sig + offset.
    if version == 4:
        tbody = bytearray()
        tbody += struct.pack("<HIB", 4, 0, asz)        # ver, abbrev_off, asz
        tbody += struct.pack("<Q", 0x1122334455667788)  # type signature
        tbody += struct.pack("<I", 0x18)               # type DIE offset
        tbody += _uleb(0)                              # empty DIE tree
        ti = struct.pack("<I", len(tbody)) + bytes(tbody)
        out.append((".debug_types", ti))

    return out


def _make_debug_line(version):
    """A small but structurally valid .debug_line program."""
    # Standard opcode lengths for opcode base 13.
    std_opcode_lengths = bytes([0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1])
    if version >= 5:
        # v5 directory/file tables use entry-format descriptors.
        dir_fmt = _uleb(1) + _uleb(1) + _uleb(DW_FORM_string)   # DW_LNCT_path
        dirs = _uleb(1) + b"/seed\x00"
        file_fmt = (_uleb(2) + _uleb(1) + _uleb(DW_FORM_string)
                    + _uleb(2) + _uleb(DW_FORM_data1))         # path, dir idx
        files = _uleb(1) + b"seed.c\x00" + _uleb(0)
        pre = struct.pack("<HBB", version, 8, 0)               # ver, addr, seg
    else:
        dir_fmt = dirs = file_fmt = files = b""
        pre = struct.pack("<H", version)

    prologue = bytearray()
    prologue += bytes([1, 1])                       # min_inst_len, max_ops
    prologue += bytes([1])                          # default_is_stmt
    prologue += struct.pack("<b", -5)               # line_base
    prologue += bytes([14])                         # line_range
    prologue += bytes([13])                         # opcode_base
    prologue += std_opcode_lengths
    if version >= 5:
        prologue += dir_fmt + dirs + file_fmt + files
    else:
        prologue += b"\x00"                         # end of include_dirs
        prologue += b"seed.c\x00" + _uleb(0) + _uleb(0) + _uleb(0)
        prologue += b"\x00"                         # end of file_names

    # A tiny line-number program: set address, advance line, copy, end seq.
    prog = bytearray()
    prog += bytes([0, 9, 2]) + struct.pack("<Q", 0)  # ext: DW_LNE_set_address
    prog += bytes([1])                               # DW_LNS_copy
    prog += bytes([0, 1, 1])                          # ext: DW_LNE_end_sequence

    body = pre + struct.pack("<I", len(prologue)) + bytes(prologue) + bytes(prog)
    return struct.pack("<I", len(body)) + bytes(body)


# ──────────────────────────────────────────────────────────────────────────
#  ELF metadata sections  (iteration 2)
# ──────────────────────────────────────────────────────────────────────────
# Object attributes, notes, symbol versioning and .dynamic, which readelf
# (do_arch/do_version/do_notes/do_dynamic) walks but the corpus rarely carries.
SHT_HASH = 5
SHT_NOTE = 7
SHT_DYNAMIC_T = 6
SHT_DYNSYM = 11
SHT_GNU_ATTRIBUTES = 0x6ffffff5
SHT_GNU_HASH = 0x6ffffff6
SHT_GNU_verdef = 0x6ffffffd
SHT_GNU_verneed = 0x6ffffffe
SHT_GNU_versym = 0x6fffffff


def _obj_attributes(vendor):
    """A SHT_GNU_ATTRIBUTES section payload: 'A' + one vendor subsection with
    a Tag_File sub-subsection carrying a string and several integer tags."""
    data = bytearray()
    data += _uleb(4) + b"cortex-seed\x00"       # tag 4 (string convention)
    data += _uleb(5) + b"7-A\x00"                # tag 5 (string convention)
    for tag, val in [(6, 10), (7, 65), (8, 1), (9, 2), (10, 3), (18, 4),
                     (20, 1), (21, 1), (24, 1), (28, 1)]:
        data += _uleb(tag) + _uleb(val)
    sub = bytearray()
    sub += bytes([1])                            # Tag_File
    sub += struct.pack("<I", 4 + 1 + len(data))  # sub-subsection size
    sub += bytes(data)
    vend = vendor.encode() + b"\x00"
    subsection = struct.pack("<I", 4 + len(vend) + len(sub)) + vend + bytes(sub)
    return b"A" + subsection


def _notes():
    """A SHT_NOTE payload with build-id, ABI-tag and GNU property notes."""
    def note(name, ntype, desc):
        nm = name.encode() + b"\x00"
        nm += b"\x00" * ((-len(nm)) % 4)
        d = desc + b"\x00" * ((-len(desc)) % 4)
        return struct.pack("<III", len(name) + 1, len(desc), ntype) + nm + d
    out = bytearray()
    out += note("GNU", 3, b"\x01\x02\x03\x04" * 5)          # NT_GNU_BUILD_ID
    out += note("GNU", 1, struct.pack("<IIII", 0, 3, 2, 0))  # NT_GNU_ABI_TAG
    # NT_GNU_PROPERTY_TYPE_0: pr_type, pr_datasz, data (x86 feature_1 = 8 bytes)
    prop = struct.pack("<II", 0xc0000002, 4) + struct.pack("<I", 0x3)
    prop += b"\x00" * ((-len(prop)) % 8)
    out += note("GNU", 5, prop)
    return bytes(out)


def _versioning(strtab, dynsym_names):
    """Build .gnu.version (versym), .gnu.version_d (verdef) and
    .gnu.version_r (verneed) payloads referencing strings in strtab."""
    # versym: one 2-byte index per dynamic symbol.
    versym = b"".join(struct.pack("<H", i % 3) for i in range(dynsym_names))

    # verdef: one base definition (VER_DEF version 1).
    name_off = strtab.add("VERS_1.0")
    aux = struct.pack("<II", name_off, 0)          # vda_name, vda_next
    verdef = struct.pack("<HHHHII", 1, 1, 1, 1, 0x0c, 20) + aux  # vd_* + aux

    # verneed: one needed entry referencing a file + one aux.
    file_off = strtab.add("libseed.so.1")
    vn_name = strtab.add("GLIBC_2.0")
    vnaux = struct.pack("<IBBHII", 0x0d1f, 0, 1, 0, vn_name, 0)
    verneed = struct.pack("<HHIII", 1, 1, file_off, 16, 0) + vnaux
    return versym, bytes(verdef), bytes(verneed)


def make_elf_meta_object(machine, elfclass=ELFCLASS64, data=ELFDATA2LSB,
                         vendor="gnu"):
    """ELF object carrying object attributes, notes, a dynamic symbol table
    and symbol-versioning sections, exercising readelf's metadata readers and
    bfd/elf-attrs.c."""
    obj = ElfObject(machine, elfclass, data)
    obj.add_section(".text", SHT_PROGBITS, b"\x00" * 32,
                    flags=SHF_ALLOC | SHF_EXECINSTR, addralign=4)

    sec_name = ".ARM.attributes" if vendor == "aeabi" else ".gnu.attributes"
    obj.add_section(sec_name, SHT_GNU_ATTRIBUTES, _obj_attributes(vendor))
    obj.add_section(".note.gnu", SHT_NOTE, _notes(), flags=SHF_ALLOC,
                    addralign=4)

    # Dynamic string + symbol tables for versioning to reference.
    dstr = StringTable()
    dnames = ["", "dynfoo", "dynbar", "weaksym"]
    dsyms = b"".join(
        obj.sym(dstr.add(n), (STB_GLOBAL << 4) | STT_FUNC, 1, 0, 4)
        for n in dnames)
    dynstr_idx = obj.add_section(".dynstr", SHT_STRTAB, dstr.bytes(),
                                 flags=SHF_ALLOC)
    obj.add_section(".dynsym", SHT_DYNSYM, dsyms, link=dynstr_idx, info=1,
                    flags=SHF_ALLOC, addralign=8,
                    entsize=24 if obj.is64 else 16)

    versym, verdef, verneed = _versioning(dstr, len(dnames))
    obj.add_section(".gnu.version", SHT_GNU_versym, versym, link=dynstr_idx,
                    flags=SHF_ALLOC, addralign=2, entsize=2)
    obj.add_section(".gnu.version_d", SHT_GNU_verdef, verdef, link=dynstr_idx,
                    info=1, flags=SHF_ALLOC, addralign=4)
    obj.add_section(".gnu.version_r", SHT_GNU_verneed, verneed,
                    link=dynstr_idx, info=1, flags=SHF_ALLOC, addralign=4)

    # .dynamic with a handful of tags.
    dyn = bytearray()
    W = (lambda a, b: struct.pack("<QQ", a, b)) if obj.is64 else (
        lambda a, b: struct.pack("<II", a, b))
    for tag, val in [(4, 0), (5, 0), (6, 0), (10, dstr.add("x")), (11, 24),
                     (0x6ffffef5, 0), (0x6ffffffe, 0), (0x6fffffff, 1),
                     (0x6ffffff0, 0), (0, 0)]:
        dyn += W(tag, val)
    obj.add_section(".dynamic", SHT_DYNAMIC_T, bytes(dyn), link=dynstr_idx,
                    flags=SHF_ALLOC | SHF_WRITE, addralign=8,
                    entsize=16 if obj.is64 else 8)
    return obj.build()


# ──────────────────────────────────────────────────────────────────────────
#  Text seeds for fuzz_as and fuzz_dlltool, which ship with no seed corpus
# ──────────────────────────────────────────────────────────────────────────

def make_gas_asm_seed():
    """A broad i386 (AT&T) assembly source exercising many gas directives,
    expression forms, macros, conditionals and a spread of instructions."""
    return (
        "\t.file \"seed.c\"\n"
        "\t.intel_syntax noprefix\n"
        "\t.att_syntax prefix\n"
        "\t.set ZERO, 0\n"
        "\t.equ ONE, ZERO + 1\n"
        "\t.equiv TWO, ONE + ONE\n"
        "\t.macro PUSHALL a, b=4\n"
        "\tpush \\a\n"
        "\t.long \\b\n"
        "\t.endm\n"
        "\t.section .rodata\n"
        "msg:\t.ascii \"hello\"\n"
        "\t.asciz \"world\"\n"
        "\t.string \"str\"\n"
        "\t.byte 1, 2, 3, 0x7f\n"
        "\t.word 0x1234\n"
        "\t.long 0x12345678\n"
        "\t.quad 0x1122334455667788\n"
        "\t.float 1.5\n"
        "\t.double 3.14159\n"
        "\t.align 16\n"
        "\t.p2align 4, 0x90\n"
        "\t.skip 8, 0\n"
        "\t.space 4\n"
        "\t.comm globalbuf, 32, 8\n"
        "\t.lcomm localbuf, 16\n"
        "\t.text\n"
        "\t.globl _start\n"
        "\t.type _start, @function\n"
        "_start:\n"
        "\t.cfi_startproc\n"
        "\tpush %ebp\n"
        "\t.cfi_def_cfa_offset 8\n"
        "\tmov %esp, %ebp\n"
        "\tlea 8(%ebp,%eax,4), %ecx\n"
        "\tadd $ONE, %eax\n"
        "\tsub $0x10, %esp\n"
        "\tmovl $msg, (%esp)\n"
        "\timul $3, %ebx, %edx\n"
        "\txor %eax, %eax\n"
        "\ttest %eax, %eax\n"
        "\t.if ONE > ZERO\n"
        "\tjne .L1\n"
        "\t.else\n"
        "\tje .L1\n"
        "\t.endif\n"
        "\tPUSHALL %edx, TWO\n"
        "\t.rept 3\n"
        "\tnop\n"
        "\t.endr\n"
        "\tpaddd %xmm0, %xmm1\n"
        "\tmovaps %xmm2, %xmm3\n"
        "\trep movsb\n"
        "\tlock incl (%eax)\n"
        ".L1:\n"
        "\tleave\n"
        "\tret\n"
        "\t.cfi_endproc\n"
        "\t.size _start, .-_start\n"
    ).encode()


def make_def_seed():
    """A Windows module-definition (.def) file exercising the dlltool def
    grammar (LIBRARY/EXPORTS/IMPORTS/SECTIONS/... in binutils/defparse.y)."""
    return (
        "LIBRARY \"seed.dll\" BASE=0x10000000\n"
        "EXPORTS\n"
        "  AddNumbers @1\n"
        "  SubNumbers @2 NONAME\n"
        "  GetData = internal_get_data\n"
        "  globalState @4 DATA\n"
        "  PrivateFn @5 PRIVATE\n"
        "  ColdFn @6 == realname\n"
        "IMPORTS\n"
        "  helper = other.dll.helper_impl\n"
        "  by_ord = other.dll.7\n"
        "SECTIONS\n"
        "  .text EXECUTE READ\n"
        "  .data READ WRITE\n"
        "  .shared SHARED\n"
        "DESCRIPTION \"seed module-definition file\"\n"
        "STACKSIZE 0x100000, 0x1000\n"
        "HEAPSIZE 0x100000, 0x1000\n"
        "VERSION 1.2\n"
    ).encode()


# ──────────────────────────────────────────────────────────────────────────
#  Separate-debug-file links  (for fuzz_dwarf, which only loads these)
# ──────────────────────────────────────────────────────────────────────────
def make_debuglink_object():
    """ELF object carrying .gnu_debuglink, .gnu_debugaltlink and .debug_sup,
    the sections fuzz_dwarf's load_separate_debug_files actually parses."""
    obj = ElfObject(62, ELFCLASS64, ELFDATA2LSB)        # x86-64 host
    obj.add_section(".text", SHT_PROGBITS, b"\x00" * 16,
                    flags=SHF_ALLOC | SHF_EXECINSTR, addralign=4)

    name = b"seed.debug\x00"
    link = name + b"\x00" * ((-len(name)) % 4) + b"\x01\x02\x03\x04"  # +CRC32
    obj.add_section(".gnu_debuglink", SHT_PROGBITS, link)

    altname = b"seed.alt.debug\x00"
    obj.add_section(".gnu_debugaltlink", SHT_PROGBITS,
                    altname + b"\x11" * 20)              # filename + build-id

    sup = struct.pack("<HB", 5, 0) + b"seed.sup\x00" + _uleb(4) + b"\xaa" * 4
    obj.add_section(".debug_sup", SHT_PROGBITS, sup)
    return obj.build()


# ──────────────────────────────────────────────────────────────────────────
#  ar archives
# ──────────────────────────────────────────────────────────────────────────
def make_archive(members):
    """A classic System V ar archive wrapping (name, data) members."""
    out = bytearray(b"!<arch>\n")
    for name, data in members:
        nm = (name + "/")[:16].ljust(16)
        hdr = "%s%-12d%-6d%-6d%-8s%-10d`\n" % (nm, 0, 0, 0, "100644",
                                               len(data))
        out += hdr.encode()
        out += data
        if len(data) % 2:
            out += b"\n"
    return bytes(out)


# ──────────────────────────────────────────────────────────────────────────
#  Driver
# ──────────────────────────────────────────────────────────────────────────
def write(path, data):
    with open(path, "wb") as f:
        f.write(data)


def main(root):
    seeds = os.path.join(root, "seeds")

    reloc_dir = os.path.join(seeds, "elf_reloc")
    os.makedirs(reloc_dir, exist_ok=True)
    for arch in ARCHES:
        write(os.path.join(reloc_dir, "reloc-%s.o" % arch),
              make_reloc_object(arch))

    dwarf_dir = os.path.join(seeds, "dwarf")
    os.makedirs(dwarf_dir, exist_ok=True)
    for ver in (4, 5):
        for bits, is64 in (("64", True), ("32", False)):
            write(os.path.join(dwarf_dir, "dwarf%d-%s.o" % (ver, bits)),
                  make_dwarf_object(ver, is64))

    meta_dir = os.path.join(seeds, "elf_meta")
    os.makedirs(meta_dir, exist_ok=True)
    write(os.path.join(meta_dir, "meta-gnu-x86_64.o"),
          make_elf_meta_object(62, ELFCLASS64, ELFDATA2LSB, "gnu"))
    write(os.path.join(meta_dir, "meta-aeabi-arm.o"),
          make_elf_meta_object(40, ELFCLASS32, ELFDATA2LSB, "aeabi"))
    write(os.path.join(meta_dir, "meta-gnu-aarch64.o"),
          make_elf_meta_object(183, ELFCLASS64, ELFDATA2LSB, "gnu"))

    # Text seeds for the otherwise-unseeded fuzz_as and fuzz_dlltool harnesses.
    gas_dir = os.path.join(seeds, "gas")
    os.makedirs(gas_dir, exist_ok=True)
    write(os.path.join(gas_dir, "seed.s"), make_gas_asm_seed())

    def_dir = os.path.join(seeds, "dlltool")
    os.makedirs(def_dir, exist_ok=True)
    write(os.path.join(def_dir, "seed.def"), make_def_seed())

    # Separate-debug-link seed for fuzz_dwarf.
    dl_dir = os.path.join(seeds, "debuglink")
    os.makedirs(dl_dir, exist_ok=True)
    write(os.path.join(dl_dir, "debuglink.o"), make_debuglink_object())

    arc_dir = os.path.join(seeds, "archive")
    os.makedirs(arc_dir, exist_ok=True)
    members = [("reloc-%s.o" % a, make_reloc_object(a))
               for a in ("riscv64", "aarch64", "ppc64")]
    members.append(("dwarf4.o", make_dwarf_object(4, True)))
    write(os.path.join(arc_dir, "multiarch.a"), make_archive(members))

    n = (len(os.listdir(reloc_dir)) + len(os.listdir(dwarf_dir))
         + len(os.listdir(arc_dir)))
    print("generate_seeds.py: wrote %d seeds under %s" % (n, seeds))


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.stderr.write("usage: generate_seeds.py <fuzz-corpus-root>\n")
        sys.exit(1)
    main(sys.argv[1])
