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
"""Test the functionality of the utils module's functions"""

import os
import tempfile
import unittest

import utils
import helper

EXAMPLE_PROJECT = 'example'

TEST_OUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            'cifuzz', 'test_files', 'out')


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

    is_local = utils.is_fuzz_target_local(
        os.path.join(TEST_OUT_DIR, 'do_stuff_fuzzer'))
    self.assertTrue(is_local)
    is_local = utils.is_fuzz_target_local(TEST_OUT_DIR)
    self.assertFalse(is_local)


class GetFuzzTargetsUnitTest(unittest.TestCase):
  """Test get_fuzz_targets function in the utils module."""

  def test_valid_filepath(self):
    """Tests that fuzz targets can be retrieved once the fuzzers are built."""
    fuzz_targets = utils.get_fuzz_targets(TEST_OUT_DIR)
    self.assertCountEqual(fuzz_targets,
                          [os.path.join(TEST_OUT_DIR, 'do_stuff_fuzzer')])
    fuzz_targets = utils.get_fuzz_targets(
        os.path.join(helper.OSSFUZZ_DIR, 'infra'))
    self.assertFalse(fuzz_targets)

  def test_invalid_filepath(self):
    """Tests what get_fuzz_targets return when invalid filepath is used."""
    fuzz_targets = utils.get_fuzz_targets('not/a/valid/file/path')
    self.assertFalse(fuzz_targets)


class ExecuteUnitTest(unittest.TestCase):
  """Test execute function in the utils module."""

  def test_valid_command(self):
    """Tests that execute can produce valid output."""
    with tempfile.TemporaryDirectory() as tmp_dir:
      out, err, err_code = utils.execute(['ls', '.'],
                                         location=tmp_dir,
                                         check_result=False)
      self.assertEqual(err_code, 0)
      self.assertEqual(err, '')
      self.assertEqual(out, '')
      out, err, err_code = utils.execute(['mkdir', 'tmp'],
                                         location=tmp_dir,
                                         check_result=False)
      self.assertEqual(err_code, 0)
      self.assertEqual(err, '')
      self.assertEqual(out, '')
      out, err, err_code = utils.execute(['ls', '.'],
                                         location=tmp_dir,
                                         check_result=False)
      self.assertEqual(err_code, 0)
      self.assertEqual(err, '')
      self.assertEqual(out, 'tmp\n')

  def test_error_command(self):
    """Tests that execute can correctly surface errors."""
    with tempfile.TemporaryDirectory() as tmp_dir:
      out, err, err_code = utils.execute(['ls', 'notarealdir'],
                                         location=tmp_dir,
                                         check_result=False)
      self.assertEqual(err_code, 2)
      self.assertIsNotNone(err)
      self.assertEqual(out, '')
      with self.assertRaises(RuntimeError):
        out, err, err_code = utils.execute(['ls', 'notarealdir'],
                                           location=tmp_dir,
                                           check_result=True)


if __name__ == '__main__':
  unittest.main()
