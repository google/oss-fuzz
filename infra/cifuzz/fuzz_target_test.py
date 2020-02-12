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
"""Test the functionality of the fuzz_target module."""

import os
import sys
import unittest
import unittest.mock

# Pylint has issue importing utils which is why error suppression is required.
# pylint: disable=wrong-import-position
# pylint: disable=import-error
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import fuzz_target
import utils

# NOTE: This integration test relies on
# https://github.com/google/oss-fuzz/tree/master/projects/example project
EXAMPLE_PROJECT = 'example'


class IsReproducibleUnitTest(unittest.TestCase):
  """Test is_reproducible function in the fuzz_target module."""

  def setUp(self):
    """Sets up dummy fuzz target to test is_reproducible method."""
    self.test_target = fuzz_target.FuzzTarget('/example/path', 10,
                                              '/example/outdir')

  def test_with_reproducible(self):
    """Tests that a is_reproducible will return true if crash is detected."""
    test_all_success = [(0, 0, 1)] * 10
    all_success_mock = unittest.mock.Mock()
    all_success_mock.side_effect = test_all_success
    utils.execute = all_success_mock
    self.assertTrue(self.test_target.is_reproducible('/fake/path/to/testcase'))
    self.assertEqual(1, all_success_mock.call_count)

    test_one_success = [(0, 0, 0)] * 9 + [(0, 0, 1)]
    one_success_mock = unittest.mock.Mock()
    one_success_mock.side_effect = test_one_success
    utils.execute = one_success_mock
    self.assertTrue(self.test_target.is_reproducible('/fake/path/to/testcase'))
    self.assertEqual(10, one_success_mock.call_count)

  def test_with_not_reproducible(self):
    """Tests that a is_reproducible will return False if crash not detected."""
    test_all_fail = [(0, 0, 0)] * 10
    all_fail_mock = unittest.mock.Mock()
    all_fail_mock.side_effect = test_all_fail
    utils.execute = all_fail_mock
    self.assertFalse(self.test_target.is_reproducible('/fake/path/to/testcase'))


class GetTestCaseUnitTest(unittest.TestCase):
  """Test get_test_case function in the fuzz_target module."""

  def setUp(self):
    """Sets up dummy fuzz target to test get_test_case method."""
    self.test_target = fuzz_target.FuzzTarget('/example/path', 10,
                                              '/example/outdir')

  def test_with_valid_error_string(self):
    """Tests that get_test_case returns the correct test case give an error."""
    test_case_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                  'test_files', 'example_fuzzer_output.txt')
    with open(test_case_path, 'r') as test_fuzz_output:
      parsed_test_case = self.test_target.get_test_case(test_fuzz_output.read())
    self.assertEqual(
        parsed_test_case,
        '/example/outdir/crash-ad6700613693ef977ff3a8c8f4dae239c3dde6f5')

  def test_with_invalid_error_string(self):
    """Tests that get_test_case will return None with a bad error string."""
    self.assertIsNone(self.test_target.get_test_case(''))
    self.assertIsNone(self.test_target.get_test_case(' Example crash string.'))


if __name__ == '__main__':
  unittest.main()
