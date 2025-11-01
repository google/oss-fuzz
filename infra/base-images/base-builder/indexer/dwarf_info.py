#!/usr/bin/env python3
# Copyright 2025 Google LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""DWARF info parser for ELF files."""

import dataclasses
import io
import os
from typing import Sequence

from absl import logging
from elftools.elf import elffile

_IGNORED_UNIT_TYPES = ("DW_UT_type", "DW_UT_split_type")


@dataclasses.dataclass
class CompilationUnit:
  """Represents a DWARF compilation unit.

  Attributes:
    producer: The producer of the compilation unit.
    name: The name of the compilation unit.
    compdir: The compilation directory of the compilation unit.
    language: The language of the compilation unit.
    apple_flags: Flags used in the compilation unit (if compiled with `-glldb`).
    isysroot: The isysroot of the compilation unit.
  """

  producer: str
  name: str
  compdir: str
  language: int
  apple_flags: str | None
  isysroot: str | None


def get_all_compilation_units(
    elf_file_path: os.PathLike[str],
) -> list[CompilationUnit]:
  """Parses compilation units from an ELF file.

  Args:
    elf_file_path: The path to the ELF file.

  Returns:
    A list of CompilationUnit objects.
  """
  result = []
  with open(elf_file_path, "rb") as f:
    elf_file = elffile.ELFFile(f)
    if not elf_file.has_dwarf_info():
      logging.error("No DWARF info found in %s", elf_file_path)
      return []
    dwarf_info = elf_file.get_dwarf_info()
    for compilation_unit in dwarf_info.iter_CUs():
      if compilation_unit.header.version < 5:
        # Only DWARF5 has a unit_type field in the header.
        # For older versions, we do a best effort approach.
        logging.warning(
            "[!] Compilation Unit with unsupported DWARF version %d",
            compilation_unit.header.version,
        )
      elif compilation_unit.header.unit_type in _IGNORED_UNIT_TYPES:
        # Type units are not interesting for us.
        continue
      elif compilation_unit.header.unit_type not in (
          "DW_UT_compile",
          "DW_UT_partial",
      ):
        raise ValueError(
            "Unsupported DWARF compilation unit type"
            f" {compilation_unit.header.unit_type}"
        )

      top_debug_info_entry = compilation_unit.get_top_DIE()
      if top_debug_info_entry.tag != "DW_TAG_compile_unit":
        logging.error("Top DIE is not a full compile unit")

      producer = top_debug_info_entry.attributes[
          "DW_AT_producer"
      ].value.decode()

      name = top_debug_info_entry.attributes["DW_AT_name"].value.decode()
      language = top_debug_info_entry.attributes["DW_AT_language"].value
      compdir = top_debug_info_entry.attributes["DW_AT_comp_dir"].value.decode()

      # When using `-glldb`, the compile flags are stored
      # in the DW_AT_APPLE_flags attribute
      apple_flags = None
      if top_debug_info_entry.attributes.get("DW_AT_APPLE_flags", None):
        apple_flags = top_debug_info_entry.attributes[
            "DW_AT_APPLE_flags"
        ].value.decode()

      isysroot = None
      if top_debug_info_entry.attributes.get("DW_AT_LLVM_isysroot", None):
        isysroot = top_debug_info_entry.attributes[
            "DW_AT_LLVM_isysroot"
        ].value.decode()

      result.append(
          CompilationUnit(
              producer=producer,
              name=name,
              compdir=compdir,
              language=language,
              apple_flags=apple_flags,
              isysroot=isysroot,
          )
      )
  return result


def parse_clang_record_command_line_value(command: str) -> Sequence[str]:
  """Parses the value of a `-frecord-command-line` entry from clang.

   Separate arguments within a command line are combined with spaces.
   Spaces and backslashes within an argument are escaped with backslashes.

  Args:
    command: The command line string to split.

  Returns:
    A sequence of strings, each representing a single argument.

  Raises:
    ValueError: If the command line contains an invalid escape sequence.
    ValueError: If the command line contains an empty argument.
  """
  value = io.StringIO(command)
  args = []
  current_arg = ""
  while True:
    c = value.read(1)
    match c:
      case "":
        # We found the end of the string.
        break
      case "\\":
        # We found a backslash, the next character should be either a space or
        # another backslash.
        c = value.read(1)
        if c not in (" ", "\\"):
          raise ValueError(f"Invalid Escape Sequence: \\{c}")
        current_arg += c
      case " ":
        # unescaped spaces separate arguments.
        if not current_arg:
          raise ValueError("Arguments should not be empty.")
        args.append(current_arg)
        current_arg = ""
      case _:
        # Anything else is part of the current argument.
        current_arg += c

  if not current_arg:
    raise ValueError("Last argument should not be empty.")

  args.append(current_arg)
  return args
