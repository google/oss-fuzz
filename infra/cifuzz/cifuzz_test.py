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
import sys
import tempfile
import unittest

# pylint: disable=wrong-import-position
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import cifuzz

EXAMPLE_PROJECT = 'example'


class BuildFuzzersIntegrationTest(unittest.TestCase):
  """Test build_fuzzers function in the utils module."""

  def test_valid(self):
    """Test building fuzzers with valid inputs."""
    with tempfile.TemporaryDirectory() as tmp_dir:
      out_path = os.path.join(tmp_dir, 'out')
      workspace_path = os.path.join(tmp_dir, 'workspace')
      os.mkdir(out_path)
      os.mkdir(workspace_path)
      self.assertTrue(
          cifuzz.build_fuzzers(EXAMPLE_PROJECT, 'oss-fuzz',
                               '0b95fe1039ed7c38fea1f97078316bfc1030c523',
                               workspace_path, out_path))
      self.assertTrue(os.path.exists(os.path.join(out_path, 'do_stuff_fuzzer')))


def test_invalid_project_name(self):
  """Test building fuzzers with invalid project name."""
  with tempfile.TemporaryDirectory() as tmp_dir:
    out_path = os.path.join(tmp_dir, 'out')
    workspace_path = os.path.join(tmp_dir, 'workspace')
    os.mkdir(out_path)
    os.mkdir(workspace_path)
    self.assertFalse(
        cifuzz.build_fuzzers('not_a_valid_project', 'oss-fuzz',
                             '0b95fe1039ed7c38fea1f97078316bfc1030c523',
                             workspace_path, out_path))


def test_invalid_repo_name(self):
  """Test building fuzzers with invalid repo name."""
  with tempfile.TemporaryDirectory() as tmp_dir:
    out_path = os.path.join(tmp_dir, 'out')
    workspace_path = os.path.join(tmp_dir, 'workspace')
    os.mkdir(out_path)
    os.mkdir(workspace_path)
    self.assertFalse(
        cifuzz.build_fuzzers(EXAMPLE_PROJECT, 'not-real-repo',
                             '0b95fe1039ed7c38fea1f97078316bfc1030c523',
                             workspace_path, out_path))


def test_invalid_commit_sha(self):
  """Test building fuzzers with invalid commit SHA."""
  with tempfile.TemporaryDirectory() as tmp_dir:
    out_path = os.path.join(tmp_dir, 'out')
    workspace_path = os.path.join(tmp_dir, 'workspace')
    os.mkdir(out_path)
    os.mkdir(workspace_path)
    self.assertFalse(
        cifuzz.build_fuzzers(EXAMPLE_PROJECT, 'oss-fuzz', '', workspace_path,
                             out_path))


def test_invalid_workspace(self):
  """Test building fuzzers with invalid workspace."""
  with tempfile.TemporaryDirectory() as tmp_dir:
    out_path = os.path.join(tmp_dir, 'out')
    os.mkdir(out_path)
    self.assertFalse(
        cifuzz.build_fuzzers(EXAMPLE_PROJECT, 'oss-fuzz',
                             '0b95fe1039ed7c38fea1f97078316bfc1030c523',
                             'not/a/dir', out_path))


def test_invalid_out(self):
  """Test building fuzzers with invalid out directory."""
  with tempfile.TemporaryDirectory() as tmp_dir:
    workspace_path = os.path.join(tmp_dir, 'workspace')
    os.mkdir(workspace_path)
    self.assertFalse(
        cifuzz.build_fuzzers(EXAMPLE_PROJECT, 'oss-fuzz',
                             '0b95fe1039ed7c38fea1f97078316bfc1030c523',
                             workspace_path, 'not/a/dir'))


if __name__ == '__main__':
  unittest.main()
