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

"""clang_wrapper tests."""

import json
import pathlib

import clang_wrapper
import unittest


class ClangWrapperTest(unittest.TestCase):

  def test_force_optimization_flag_no_optimization(self):
    """Tests that optimization flags are not forced when not present."""
    argv = ["clang", "-c", "test.c", "-o", "test.o"]
    modified_argv = clang_wrapper.force_optimization_flag(argv)
    self.assertCountEqual(modified_argv, argv)

  def test_force_optimization_flag(self):
    """Tests that optimization flags are forced when present."""
    argv = ["clang", "-O2", "-c", "test.c", "-o", "test.o", "-O1"]
    modified_argv = clang_wrapper.force_optimization_flag(argv)
    self.assertCountEqual(
        modified_argv, ["clang", "-O0", "-c", "test.c", "-o", "test.o", "-O0"]
    )

  def test_remove_invalid_coverage_flags(self):
    """Tests that invalid coverage flags are removed."""
    argv = [
        "clang",
        "-foo",
        "-fsanitize-coverage-allowlist=allowlist",
        "-fsanitize-coverage-ignorelist=ignorelist",
        "-c",
        "test.c",
    ]
    modified_argv = clang_wrapper.fix_coverage_flags(
        argv, "-fsanitize-coverage=bb,no-prune,trace-pc-guard"
    )
    self.assertCountEqual(
        modified_argv,
        [
            "clang",
            "-foo",
            "-c",
            "test.c",
            "-fsanitize-coverage=bb,no-prune,trace-pc-guard",
        ],
    )

  def test_merge_incremental_cdb(self):
    """Tests that incremental cdb is merged correctly."""
    cdb_path = pathlib.Path(self.create_tempdir().full_path)
    merged_cdb_path = pathlib.Path(self.create_tempdir().full_path)

    old_cdb_fragments = {
        "test.c.123.json": {
            "directory": "/build",
            "file": "test.c",
            "output": "test.o",
            "arguments": ["-c", "test.c"],
        },
        "test.c.455.json": {
            "directory": "/build/subdir",
            "file": "test.c",
            "output": "test.o",
            "arguments": ["-c", "test.c"],
        },
        "foo.c.455.json": {
            "directory": "/build",
            "file": "foo.c",
            "output": "foo.o",
            "arguments": ["-c", "foo.c"],
        },
    }

    new_cdb_fragments = {
        "test.c.aaa.json": {
            "directory": "/build/subdir",
            "file": "test.c",
            "output": "test.o",
            "arguments": ["-c", "test.c"],
        },
    }

    for cdb_fragment_path, cdb_fragment in old_cdb_fragments.items():
      (merged_cdb_path / cdb_fragment_path).write_text(
          json.dumps(cdb_fragment) + ",\n"
      )

    for cdb_fragment_path, cdb_fragment in new_cdb_fragments.items():
      (cdb_path / cdb_fragment_path).write_text(
          json.dumps(cdb_fragment) + ",\n"
      )

    (cdb_path / "not_a_json").write_text("not a json")

    clang_wrapper.merge_incremental_cdb(cdb_path, merged_cdb_path)

    self.assertCountEqual(
        merged_cdb_path.iterdir(),
        [
            pathlib.Path(merged_cdb_path) / ".lock",
            pathlib.Path(merged_cdb_path) / "test.c.123.json",
            pathlib.Path(merged_cdb_path) / "test.c.aaa.json",
            pathlib.Path(merged_cdb_path) / "foo.c.455.json",
        ],
    )


if __name__ == "__main__":
  unittest.main()
