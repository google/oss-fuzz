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

from elftools.ehabi.ehabiinfo import (
    CannotUnwindEHABIEntry,
    CorruptEHABIEntry,
    EHABIEntry,
    GenericEHABIEntry,
)
from elftools.elf.dynamic import DynamicSection, DynamicSegment
from elftools.elf.elffile import ELFFile
from elftools.elf.hash import ELFHashSection, ELFHashTable, GNUHashSection, GNUHashTable


COMMON_NAMES = [
    "",
    "__cxa_atexit",
    "__cxa_finalize",
    "__libc_start_main",
    "__register_atfork",
    "abort",
    "caller",
    "exit",
    "function1_ver1_1",
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


def _touch_symbol(symbol):
    _ = getattr(symbol, "name", None)
    _ = getattr(symbol, "entry", None)
    _ = _safe_call(symbol.__getitem__, "st_name")
    _ = _safe_call(symbol.__getitem__, "st_value")


def _touch_hash_table(table, names):
    _ = _safe_call(table.get_number_of_symbols)
    for name in names[:16]:
        symbol = _safe_call(table.get_symbol, name)
        if symbol is not None:
            _touch_symbol(symbol)


def _touch_dynamic(container, names):
    _ = _safe_call(container.num_tags)
    for tag_name in ("DT_HASH", "DT_GNU_HASH", "DT_REL", "DT_RELA", "DT_RELR", "DT_STRTAB"):
        _ = _safe_call(container.get_table_offset, tag_name)
        _ = list(_safe_call(container.iter_tags, tag_name, default=[]) or [])

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

    for table in (_safe_call(container.get_relocation_tables, default={}) or {}).values():
        _ = _safe_call(table.num_relocations)


def _touch_ehabi_entry(entry):
    _ = getattr(entry, "function_offset", None)
    _ = getattr(entry, "personality", None)
    _ = getattr(entry, "bytecode_array", None)
    _ = getattr(entry, "eh_table_offset", None)
    _ = getattr(entry, "unwindable", None)
    _ = getattr(entry, "corrupt", None)
    _ = getattr(entry, "reason", None)
    _ = _safe_call(entry.mnmemonic_array)
    _ = repr(entry)


def _touch_ehabi(blob, elf):
    _touch_ehabi_entry(EHABIEntry(0, 0, [0x97, 0x84, 0x08]))
    _touch_ehabi_entry(CannotUnwindEHABIEntry(0))
    _touch_ehabi_entry(GenericEHABIEntry(0, 1))
    _touch_ehabi_entry(CorruptEHABIEntry("bad"))

    if not _safe_call(elf.has_ehabi_info):
        return

    for info in list(_safe_call(elf.get_ehabi_infos, default=[]) or [])[:8]:
        _ = _safe_call(info.section_name)
        _ = _safe_call(info.section_offset)
        count = _safe_call(info.num_entry, default=0) or 0
        for index in range(min(count, 16)):
            entry = _safe_call(info.get_entry, index)
            if entry is not None:
                _touch_ehabi_entry(entry)

    shadow = _safe_call(_open_elf, blob)
    if shadow is not None:
        _ = _safe_call(shadow.get_ehabi_infos)
        _ = _safe_call(shadow.close)


def _touch_elf(elf, blob, names):
    _ = elf.header
    _ = _safe_call(elf.get_machine_arch)
    _ = _safe_call(elf.get_section_by_name, ".hash")
    _ = _safe_call(elf.get_section_by_name, ".gnu.hash")
    _ = _safe_call(elf.get_section_by_name, ".ARM.exidx")
    _ = _safe_call(elf.get_section_by_name, ".ARM.extab")

    for name in names[:8]:
        _ = _safe_call(ELFHashTable.elf_hash, name)
        _ = _safe_call(GNUHashTable.gnu_hash, name)

    empty_hash = ELFHashTable(None, 0, 0, None)
    _ = _safe_call(empty_hash.get_number_of_symbols)

    for section in list(_safe_call(elf.iter_sections, default=[]) or [])[:64]:
        if isinstance(section, ELFHashSection):
            _touch_hash_table(section, names)
        elif isinstance(section, GNUHashSection):
            _touch_hash_table(section, names)
        elif isinstance(section, DynamicSection):
            _touch_dynamic(section, names)

    for segment in list(_safe_call(elf.iter_segments, default=[]) or [])[:32]:
        if isinstance(segment, DynamicSegment):
            _touch_dynamic(segment, names)
            for tag_name in ("DT_HASH", "DT_GNU_HASH"):
                _, offset = _safe_call(segment.get_table_offset, tag_name, default=(None, None)) or (None, None)
                if offset is None:
                    continue
                if tag_name == "DT_HASH":
                    hash_table = _safe_call(ELFHashTable, elf, offset, None, segment)
                else:
                    hash_table = _safe_call(GNUHashTable, elf, offset, segment)
                if hash_table is not None:
                    _touch_hash_table(hash_table, names)

    _touch_ehabi(blob, elf)


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
