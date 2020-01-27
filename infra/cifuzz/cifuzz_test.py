# Copyright 2020 Google LLC
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
"""Test the functionality of the cifuzz module's functions:
1. Building fuzzers.
2. Running fuzzers.
"""

import os
import unittest

import utils
import helper

EXAMPLE_PROJECT = 'example'


class BuildFuzzersTest(unittest.TestCase):
  """Test build_fuzzers function in the utils module."""

  def test_valid(self):
    """Test building fuzzers with valid inputs."""
    with tempfile.TemporaryDirectory() as tmp_dir:
      out_path = os.path.join(tmp_dir, 'out')
      workspace_path = os.path.join(tmp_dir, 'workspace')
      os.mkdir(out_path)
      os.mkdir(workspace_path)
      self.assertTrue(cifuzz.build_fuzzers(EXAMPLE_PROJECT, 'oss-fuzz', '0b95fe1039ed7c38fea1f97078316bfc1030c523', workspace_path, out_path))
      self.assertTrue(os.path.exists(os.path.join(out_path, 'do_stuff_fuzzer')))


if __name__ == '__main__':
  unittest.main()
