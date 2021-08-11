# Copyright 2021 Google LLC
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
"""Tests for stack_parser."""
import os
import unittest
from unittest import mock

import parameterized
from pyfakefs import fake_filesystem_unittest

import stack_parser

# NOTE: This integration test relies on
# https://github.com/google/oss-fuzz/tree/master/projects/example project.
EXAMPLE_PROJECT = 'example'

# Location of data used for testing.
TEST_DATA_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                              'test_data')


class ParseOutputTest(fake_filesystem_unittest.TestCase):
  """Tests parse_fuzzer_output."""

  def setUp(self):
    self.setUpPyfakefs()
    self.maxDiff = None  # pylint: disable=invalid-name

  @parameterized.parameterized.expand([('example_crash_fuzzer_output.txt',
                                        'example_crash_fuzzer_bug_summary.txt'),
                                       ('msan_crash_fuzzer_output.txt',
                                        'msan_crash_fuzzer_bug_summary.txt')])
  def test_parse_valid_output(self, fuzzer_output_file, bug_summary_file):
    """Checks that the parse fuzzer output can correctly parse output."""
    # Read the fuzzer output from disk.
    fuzzer_output_path = os.path.join(TEST_DATA_PATH, fuzzer_output_file)
    self.fs.add_real_file(fuzzer_output_path)
    with open(fuzzer_output_path, 'rb') as fuzzer_output_handle:
      fuzzer_output = fuzzer_output_handle.read()
    bug_summary_path = '/bug-summary.txt'
    with mock.patch('logging.info') as mock_info:
      stack_parser.parse_fuzzer_output(fuzzer_output, bug_summary_path)
      mock_info.assert_not_called()

    with open(bug_summary_path) as bug_summary_handle:
      bug_summary = bug_summary_handle.read()

    # Compare the bug to the expected one.
    expected_bug_summary_path = os.path.join(TEST_DATA_PATH, bug_summary_file)
    self.fs.add_real_file(expected_bug_summary_path)
    with open(expected_bug_summary_path) as expected_bug_summary_handle:
      expected_bug_summary = expected_bug_summary_handle.read()

    self.assertEqual(expected_bug_summary, bug_summary)

  def test_parse_invalid_output(self):
    """Checks that no files are created when an invalid input was given."""
    artifact_path = '/bug-summary.txt'
    with mock.patch('logging.error') as mock_error:
      stack_parser.parse_fuzzer_output(b'not a valid output_string',
                                       artifact_path)
      assert mock_error.call_count
    self.assertFalse(os.path.exists(artifact_path))


if __name__ == '__main__':
  unittest.main()
