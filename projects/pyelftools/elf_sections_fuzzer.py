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
################################################################################

import sys
import atheris

atheris.instrument_all()

import io
import os
import re

from elftools.common.exceptions import ELFError, ELFParseError
from elftools.elf.dynamic import DynamicSection, DynamicSegment, DynamicTag
from elftools.elf.elffile import ELFFile
from elftools.elf.hash import ELFHashSection, GNUHashSection
from elftools.elf.relocation import (
    RelocationHandler,
    RelocationSection,
    RelrRelocationSection,
)
from elftools.elf.sections import (
    ARMAttributesSection,
    NoteSection,
    StringTableSection,
    SymbolTableSection,
)
from elftools.elf.segments import InterpSegment, NoteSegment


COMMON_NAMES = [
    "",
    ".ARM.attributes",
    ".dynamic",
    ".dynstr",
    ".dynsym",
    ".eh_frame",
    ".gnu.hash",
    ".hash",
    ".note",
    ".note.gnu.property",
    ".rel.text",
    ".rela.dyn",
    ".relr.dyn",
    ".strtab",
    ".symtab",
    ".text",
    "abort",
    "caller",
    "exit",
    "main",
    "printf",
]


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


def _iter_names(data):
    seen = set()
    for name in COMMON_NAMES:
        seen.add(name)
        yield name

    for match in re.findall(rb"[A-Za-z0-9_.$@/-]{1,32}", data[:4096]):
        try:
            name = match.decode("utf-8", "ignore")
        except Exception:
            continue
        if not name or name in seen:
            continue
        seen.add(name)
        yield name
        if len(seen) >= 48:
            break


def _open_elf(blob):
    return ELFFile(io.BytesIO(blob), stream_loader=lambda _: io.BytesIO(blob))


def _touch_dynamic_tag(tag):
    _ = tag.entry
    _ = _safe_call(tag.__getitem__, "d_tag")
    _ = _safe_call(tag.__getitem__, "d_val")
    _ = repr(tag)
    _ = str(tag)
    for attr_name in ("needed", "rpath", "runpath", "soname", "sunw_filter"):
        _ = getattr(tag, attr_name, None)


def _touch_relocation(relocation):
    _ = relocation.entry
    _ = _safe_call(relocation.is_RELA)
    _ = _safe_call(relocation.__getitem__, "r_offset")
    _ = _safe_call(relocation.__getitem__, "r_info")
    _ = repr(relocation)
    _ = str(relocation)


def _touch_relocation_table(table):
    _ = _safe_call(table.is_RELA)
    count = _safe_call(table.num_relocations, default=0) or 0
    for index in range(min(count, 16)):
        relocation = _safe_call(table.get_relocation, index)
        if relocation is not None:
            _touch_relocation(relocation)
    for index, relocation in enumerate(_safe_call(table.iter_relocations, default=[]) or []):
        if index >= 16:
            break
        _touch_relocation(relocation)


def _touch_symbol(symbol):
    _ = getattr(symbol, "name", None)
    _ = getattr(symbol, "entry", None)
    _ = _safe_call(symbol.__getitem__, "st_name")
    _ = _safe_call(symbol.__getitem__, "st_value")


def _touch_dynamic(container, names):
    _safe_call(DynamicTag, "", None)
    _ = _safe_call(container.num_tags)
    for tag_name in (
        "DT_HASH",
        "DT_GNU_HASH",
        "DT_JMPREL",
        "DT_NEEDED",
        "DT_NULL",
        "DT_PLTGOT",
        "DT_REL",
        "DT_RELA",
        "DT_RELR",
        "DT_STRTAB",
    ):
        _ = _safe_call(container.get_table_offset, tag_name)
        for tag in _safe_call(container.iter_tags, tag_name, default=[]) or []:
            _touch_dynamic_tag(tag)

    count = _safe_call(container.num_tags, default=0) or 0
    for index in range(min(count, 16)):
        tag = _safe_call(container.get_tag, index)
        if tag is not None:
            _touch_dynamic_tag(tag)

    for index, tag in enumerate(_safe_call(container.iter_tags, default=[]) or []):
        if index >= 32:
            break
        _touch_dynamic_tag(tag)

    relocation_tables = _safe_call(container.get_relocation_tables, default={}) or {}
    for table in relocation_tables.values():
        _touch_relocation_table(table)

    if isinstance(container, DynamicSegment):
        _ = _safe_call(container.num_symbols)
        for index in range(8):
            symbol = _safe_call(container.get_symbol, index)
            if symbol is not None:
                _touch_symbol(symbol)
        for name in names[:8]:
            symbols = _safe_call(container.get_symbol_by_name, name, default=[]) or []
            for symbol in list(symbols)[:4]:
                _touch_symbol(symbol)
        for index, symbol in enumerate(_safe_call(container.iter_symbols, default=[]) or []):
            if index >= 32:
                break
            _touch_symbol(symbol)


def _touch_hash_section(section, names):
    _ = _safe_call(section.get_number_of_symbols)
    for name in names[:12]:
        symbol = _safe_call(section.get_symbol, name)
        if symbol is not None:
            _touch_symbol(symbol)


def _touch_arm_attributes(section):
    _ = section.num_subsections
    for subsection in list(section.subsections)[:8]:
        _ = subsection.header
        _ = _safe_call(subsection.__getitem__, "vendor_name")
        _ = subsection.num_subsubsections
        _ = repr(subsection)
        for subsubsection in list(subsection.subsubsections)[:8]:
            _ = subsubsection.header
            _ = subsubsection.num_attributes
            _ = repr(subsubsection)
            for attribute in list(subsubsection.attributes)[:16]:
                _ = getattr(attribute, "tag", None)
                _ = getattr(attribute, "value", None)
                _ = repr(attribute)
            for attribute in _safe_call(subsubsection.iter_attributes, "TAG_CPU_ARCH", default=[]) or []:
                _ = getattr(attribute, "value", None)

    for subsection in _safe_call(section.iter_subsections, "aeabi", default=[]) or []:
        _ = subsection.header


def _touch_section(section, elf, names):
    _ = section.name
    _ = section.header
    _ = section.compressed
    _ = section.data_size
    _ = section.data_alignment
    _ = _safe_call(section.data)
    _ = _safe_call(section.is_null)
    _ = _safe_call(section.__getitem__, "sh_type")
    _ = _safe_call(hash, section)
    _ = section == section

    if isinstance(section, StringTableSection):
        for offset in (0, 1, _safe_call(section.__getitem__, "sh_name", default=0) or 0):
            _ = _safe_call(section.get_string, int(offset))

    if isinstance(section, SymbolTableSection):
        count = _safe_call(section.num_symbols, default=0) or 0
        for index in range(min(count, 16)):
            symbol = _safe_call(section.get_symbol, index)
            if symbol is not None:
                _touch_symbol(symbol)
        for name in names[:8]:
            symbols = _safe_call(section.get_symbol_by_name, name, default=[]) or []
            for symbol in list(symbols)[:4]:
                _touch_symbol(symbol)
        for index, symbol in enumerate(_safe_call(section.iter_symbols, default=[]) or []):
            if index >= 32:
                break
            _touch_symbol(symbol)

    if isinstance(section, DynamicSection):
        _touch_dynamic(section, names)

    if isinstance(section, RelocationSection):
        _touch_relocation_table(section)
    elif isinstance(section, RelrRelocationSection):
        _touch_relocation_table(section)

    if isinstance(section, NoteSection):
        for index, note in enumerate(_safe_call(section.iter_notes, default=[]) or []):
            if index >= 16:
                break
            for key in ("n_name", "n_type", "n_desc", "n_offset"):
                try:
                    _ = note[key]
                except Exception:
                    _ = getattr(note, key, None)

    if isinstance(section, ARMAttributesSection):
        _touch_arm_attributes(section)

    if isinstance(section, (ELFHashSection, GNUHashSection)):
        _touch_hash_section(section, names)

    if hasattr(section, "iter_stabs"):
        for index, stab in enumerate(_safe_call(section.iter_stabs, default=[]) or []):
            if index >= 16:
                break
            _ = stab

    handler = RelocationHandler(elf)
    linked = _safe_call(handler.find_relocations_for_section, section)
    if linked is not None:
        _touch_relocation_table(linked)


def _touch_segment(segment, sections, names):
    _ = segment.header
    _ = _safe_call(segment.data)
    _ = _safe_call(segment.__getitem__, "p_type")
    _ = _safe_call(segment.__getitem__, "p_offset")

    for section in sections[:12]:
        _ = _safe_call(segment.section_in_segment, section)

    if isinstance(segment, InterpSegment):
        _ = _safe_call(segment.get_interp_name)

    if isinstance(segment, NoteSegment):
        for index, note in enumerate(_safe_call(segment.iter_notes, default=[]) or []):
            if index >= 16:
                break
            for key in ("n_name", "n_type", "n_desc", "n_offset"):
                try:
                    _ = note[key]
                except Exception:
                    _ = getattr(note, key, None)

    if isinstance(segment, DynamicSegment):
        _touch_dynamic(segment, names)


def _touch_elf(elf, blob, names):
    _ = elf.elfclass
    _ = elf.little_endian
    _ = elf.header
    _ = _safe_call(elf.__getitem__, "e_entry")
    _ = _safe_call(elf.get_machine_arch)
    _ = _safe_call(elf.get_shstrndx)
    _ = _safe_call(elf.has_phantom_bytes)

    sections = []
    num_sections = _safe_call(elf.num_sections, default=0) or 0
    for index in range(min(num_sections, 64)):
        section = _safe_call(elf.get_section, index)
        if section is None:
            continue
        sections.append(section)
        _ = _safe_call(elf.get_section, index, section["sh_type"])
        _touch_section(section, elf, names)

    for name in names[:16]:
        _ = _safe_call(elf.get_section_by_name, name)
        _ = _safe_call(elf.get_section_index, name)
        _ = _safe_call(elf.has_section, name)

    seen_types = []
    for section in sections:
        section_type = _safe_call(section.__getitem__, "sh_type")
        if section_type in seen_types or section_type is None:
            continue
        seen_types.append(section_type)
        for index, filtered in enumerate(_safe_call(elf.iter_sections, section_type, default=[]) or []):
            if index >= 8:
                break
            _ = filtered.name

    entry = _safe_call(elf.__getitem__, "e_entry", default=0) or 0
    _ = list(_safe_call(elf.address_offsets, entry, 1, default=[]) or [])

    segments = []
    num_segments = _safe_call(elf.num_segments, default=0) or 0
    for index in range(min(num_segments, 32)):
        segment = _safe_call(elf.get_segment, index)
        if segment is None:
            continue
        segments.append(segment)
        _touch_segment(segment, sections, names)

    seen_segment_types = []
    for segment in segments:
        segment_type = _safe_call(segment.__getitem__, "p_type")
        if segment_type in seen_segment_types or segment_type is None:
            continue
        seen_segment_types.append(segment_type)
        for index, filtered in enumerate(_safe_call(elf.iter_segments, segment_type, default=[]) or []):
            if index >= 8:
                break
            _ = filtered.header

    _ = _safe_call(elf.has_dwarf_info)
    _ = _safe_call(elf.has_dwarf_info, strict=True)
    _ = _safe_call(elf.has_ehabi_info)
    _ = _safe_call(elf.get_ehabi_infos)

    shadow_elf = _safe_call(_open_elf, blob)
    if shadow_elf is not None:
        _ = _safe_call(shadow_elf.__enter__)
        _ = _safe_call(shadow_elf.__exit__, None, None, None)
        _ = _safe_call(shadow_elf.close)


def TestOneInput(data):
    try:
        names = list(_iter_names(data))
        for blob in _candidate_blobs(data):
            elf = _safe_call(_open_elf, blob)
            if elf is None:
                continue
            _touch_elf(elf, blob, names)
            _ = _safe_call(elf.close)
    except Exception:
        pass


def main():
    if _coverage_mode():
        return
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
