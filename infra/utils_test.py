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
"""Test the functionality of the utils module's functions:
1. is_fuzz_target_local
2. get_fuzz_targets
3. get_env_var
"""

import os
import unittest

import utils
import helper

EXAMPLE_PROJECT = 'example'


class IsFuzzTargetLocalUnitTest(unittest.TestCase):
  """Test is_fuzz_target_local function in the utils module."""

  def test_invalid_filepath(self):
    """Test the function with an invalid file path."""
    is_local = utils.is_fuzz_target_local('not/a/real/file')
    self.assertFalse(is_local)
    is_local = utils.is_fuzz_target_local('')
    self.assertFalse(is_local)
    is_local = utils.is_fuzz_target_local(' ')
    self.assertFalse(is_local)

  def test_valid_filepath(self):
    """Checks is_fuzz_target_local function with a valid filepath."""
    utils.chdir_to_root()
    helper.build_fuzzers_impl(EXAMPLE_PROJECT,
                              True,
                              'libfuzzer',
                              'address',
                              'x86_64', [],
                              None,
                              no_cache=False,
                              mount_location=None)
    is_local = utils.is_fuzz_target_local(
        os.path.join(helper.OSSFUZZ_DIR, 'build', 'out', EXAMPLE_PROJECT,
                     'do_stuff_fuzzer'))
    self.assertTrue(is_local)
    is_local = utils.is_fuzz_target_local(
        os.path.join(helper.OSSFUZZ_DIR, 'build', 'out', EXAMPLE_PROJECT,
                     'do_stuff_fuzzer.dict'))
    self.assertFalse(is_local)


class GetFuzzTargetsUnitTest(unittest.TestCase):
  """Test get_fuzz_targets function in the utils module."""

  def test_valid_filepath(self):
    """Tests that fuzz targets can be retrieved once the fuzzers are built."""
    utils.chdir_to_root()
    helper.build_fuzzers_impl(EXAMPLE_PROJECT,
                              True,
                              'libfuzzer',
                              'address',
                              'x86_64', [],
                              None,
                              no_cache=False,
                              mount_location=None)
    fuzz_targets = utils.get_fuzz_targets(
        os.path.join(helper.OSSFUZZ_DIR, 'build', 'out', EXAMPLE_PROJECT))
    self.assertCountEqual(fuzz_targets, [
        os.path.join(helper.OSSFUZZ_DIR, 'build', 'out', EXAMPLE_PROJECT,
                     'do_stuff_fuzzer')
    ])
    fuzz_targets = utils.get_fuzz_targets(
        os.path.join(helper.OSSFUZZ_DIR, 'infra'))
    self.assertFalse(fuzz_targets)

  def test_invalid_filepath(self):
    """Tests what get_fuzz_targets return when invalid filepath is used."""
    utils.chdir_to_root()
    helper.build_fuzzers_impl(EXAMPLE_PROJECT,
                              True,
                              'libfuzzer',
                              'address',
                              'x86_64', [],
                              None,
                              no_cache=False,
                              mount_location=None)
    fuzz_targets = utils.get_fuzz_targets('not/a/valid/file/path')
    self.assertFalse(fuzz_targets)


if __name__ == '__main__':
  unittest.main()
