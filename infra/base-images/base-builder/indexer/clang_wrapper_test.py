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


if __name__ == "__main__":
  unittest.main()
