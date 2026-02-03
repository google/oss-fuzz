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
        "-fsanitize-coverage=edge",
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
        "foo.123_linker_commands.json": {"invalid": "foo"},
    }

    new_cdb_fragments = {
        "test.c.aaa.json": [{
            "directory": "/build/subdir",
            "file": "test.c",
            "output": "test.o",
            "arguments": ["-c", "test.c"],
        }],
        "bar.c.bbb.json": [
            {
                "directory": "/build/subdir",
                "file": "bar.c",
                "output": "bar.o",
                "arguments": ["-c", "bar.c"],
            },
            {
                "directory": "/build/subdir",
                "file": "bar2.c",
                "output": "bar2.o",
                "arguments": ["-c", "bar2.c"],
            },
        ],
    }

    for cdb_fragment_path, cdb_fragment in old_cdb_fragments.items():
      suffix = (
          ",\n"
          if not cdb_fragment_path.endswith("_linker_commands.json")
          else ""
      )
      (merged_cdb_path / cdb_fragment_path).write_text(
          json.dumps(cdb_fragment) + suffix
      )

    for cdb_fragment_path, cdb_fragment in new_cdb_fragments.items():
      (cdb_path / cdb_fragment_path).write_text(
          ",\n".join([json.dumps(frag) for frag in cdb_fragment]) + ",\n"
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
            pathlib.Path(merged_cdb_path) / "foo.123_linker_commands.json",
            pathlib.Path(merged_cdb_path) / "bar.c.bbb.json",
        ],
    )

  def test_merge_incremental_cdb_duplicate_outputs(self):
    """Tests that incremental cdb is merged correctly with duplicate outputs."""
    cdb_path = pathlib.Path(self.create_tempdir().full_path)
    merged_cdb_path = pathlib.Path(self.create_tempdir().full_path)

    fragment1 = {
        "directory": "/build",
        "file": "test.c",
        "output": "test.o",
    }
    (merged_cdb_path / "1.json").write_text(json.dumps(fragment1) + ",\n")

    fragment2 = {
        "directory": "/build",
        "file": "test.c",
        "output": "test.o",
    }
    (cdb_path / "2.json").write_text(json.dumps(fragment2) + ",\n")
    (cdb_path / "3.json").write_text(json.dumps(fragment2) + ",\n")

    clang_wrapper.merge_incremental_cdb(cdb_path, merged_cdb_path)

    self.assertCountEqual(
        merged_cdb_path.iterdir(),
        [
            merged_cdb_path / ".lock",
            merged_cdb_path / "2.json",
            merged_cdb_path / "3.json",
        ],
    )
    self.assertFalse((merged_cdb_path / "1.json").exists())


if __name__ == "__main__":
  unittest.main()
