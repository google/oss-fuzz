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

"""Diffs compile commands generated via DWARF info and compilation databases."""

import collections
from collections.abc import Sequence
import json
import pathlib
from absl import app
from absl import flags
from absl import logging
import dwarf_info

_BINARY_PATH = flags.DEFINE_string(
    "binary_path", None, "Path to the binary file.", required=True
)

_COMPILE_COMMANDS_PATH = flags.DEFINE_string(
    "compile_commands_path",
    None,
    "Path to the compile commands file.",
    required=True,
)


def main(argv: Sequence[str]) -> None:
  if len(argv) > 1:
    raise app.UsageError("Too many command-line arguments.")

  binary_path = pathlib.Path(_BINARY_PATH.value)
  compilation_units = dwarf_info.get_all_compilation_units(binary_path)
  logging.info("Found %d compilation units.", len(compilation_units))

  # Question 1: Do we have repeated CU names in the binary?
  cu_files = collections.Counter([cu.name for cu in compilation_units])
  logging.info("Most Common CU names: %s", cu_files.most_common(1))

  libs = binary_path.parent / "lib"
  for lib in libs.iterdir():
    new_cus = dwarf_info.get_all_compilation_units(lib)
    logging.info("Found %d compilation units in %s", len(new_cus), lib)
    compilation_units.extend(new_cus)

  with open(_COMPILE_COMMANDS_PATH.value, "r") as f:
    compile_commands = json.load(f)

  # Question 2: Do we have repeated files in the compile commands?
  cc_files = collections.Counter([cc["file"] for cc in compile_commands])
  logging.info("Most Common commands files: %s", cc_files.most_common(1))

  cc_files = set(cc_files)
  cu_files = set(cu_files)

  for file in cc_files - cu_files:
    logging.info("File not found in CU: %s", file)

  for file in cu_files - cc_files:
    logging.info("File not found in CC: %s", file)

  for file in cu_files.intersection(cc_files):
    logging.info("File found in both: %s", file)


if __name__ == "__main__":
  app.run(main)
