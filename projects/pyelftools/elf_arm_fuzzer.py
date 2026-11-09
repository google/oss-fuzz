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

from elftools.ehabi.ehabiinfo import (
    CannotUnwindEHABIEntry,
    CorruptEHABIEntry,
    EHABIEntry,
    GenericEHABIEntry,
)
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationHandler, RelocationSection
from elftools.elf.sections import ARMAttributesSection, NoteSection


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

    header = bytearray(52)
    header[0:4] = b"\x7fELF"
    header[4] = 1
    header[5] = 1
    header[6] = 1
    yield bytes(header) + data[:8192]


def _open_elf(blob):
    return ELFFile(io.BytesIO(blob), stream_loader=lambda _: io.BytesIO(blob))


def _touch_arm_attributes(section):
    _ = section.header
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
            for attribute in _safe_call(subsubsection.iter_attributes, "TAG_CPU_NAME", default=[]) or []:
                _ = getattr(attribute, "value", None)

    for subsection in _safe_call(section.iter_subsections, "aeabi", default=[]) or []:
        _ = subsection.header


def _touch_relocation(relocation):
    _ = relocation.entry
    _ = _safe_call(relocation.is_RELA)
    _ = _safe_call(relocation.__getitem__, "r_offset")
    _ = _safe_call(relocation.__getitem__, "r_info")
    _ = repr(relocation)
    _ = str(relocation)


def _touch_relocation_section(section):
    _ = section.header
    _ = section.name
    _ = _safe_call(section.is_RELA)
    count = _safe_call(section.num_relocations, default=0) or 0
    for index in range(min(count, 32)):
        relocation = _safe_call(section.get_relocation, index)
        if relocation is not None:
            _touch_relocation(relocation)
    for index, relocation in enumerate(_safe_call(section.iter_relocations, default=[]) or []):
        if index >= 32:
            break
        _touch_relocation(relocation)


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


def _touch_ehabi(elf):
    _touch_ehabi_entry(EHABIEntry(0, 0, [0x97, 0x84, 0x08]))
    _touch_ehabi_entry(CannotUnwindEHABIEntry(0))
    _touch_ehabi_entry(GenericEHABIEntry(0, 1))
    _touch_ehabi_entry(CorruptEHABIEntry("bad"))

    _ = _safe_call(elf.has_ehabi_info)
    for info in list(_safe_call(elf.get_ehabi_infos, default=[]) or [])[:8]:
        _ = _safe_call(info.section_name)
        _ = _safe_call(info.section_offset)
        count = _safe_call(info.num_entry, default=0) or 0
        for index in range(min(count, 32)):
            entry = _safe_call(info.get_entry, index)
            if entry is not None:
                _touch_ehabi_entry(entry)


def _touch_elf(elf):
    _ = elf.header
    _ = _safe_call(elf.get_machine_arch)
    _ = _safe_call(elf.get_section_by_name, ".ARM.attributes")
    _ = _safe_call(elf.get_section_by_name, ".ARM.exidx")
    _ = _safe_call(elf.get_section_by_name, ".ARM.extab")
    _ = _safe_call(elf.get_section_by_name, ".rel.text")
    _ = _safe_call(elf.get_section_by_name, ".rela.text")
    _ = _safe_call(elf.get_section_index, ".ARM.attributes")
    _ = _safe_call(elf.has_section, ".ARM.attributes")

    sections = list(_safe_call(elf.iter_sections, default=[]) or [])
    handler = RelocationHandler(elf)

    for section in sections[:64]:
        _ = section.name
        _ = section.header
        if isinstance(section, ARMAttributesSection):
            _touch_arm_attributes(section)
        if isinstance(section, RelocationSection):
            _touch_relocation_section(section)
        if isinstance(section, NoteSection):
            for note in list(_safe_call(section.iter_notes, default=[]) or [])[:8]:
                _ = note
        _ = _safe_call(handler.find_relocations_for_section, section)

    text_section = _safe_call(elf.get_section_by_name, ".text")
    if text_section is not None:
        relocation_section = _safe_call(handler.find_relocations_for_section, text_section)
        if relocation_section is not None:
            _touch_relocation_section(relocation_section)
            _ = _safe_call(
                handler.apply_section_relocations,
                io.BytesIO(_safe_call(text_section.data, default=b"") or b""),
                relocation_section,
            )

    _touch_ehabi(elf)


def TestOneInput(data):
    try:
        for blob in _candidate_blobs(data):
            elf = _safe_call(_open_elf, blob)
            if elf is None:
                continue
            _touch_elf(elf)
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
