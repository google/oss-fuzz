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
import tempfile
import unittest

import stack_parser

# NOTE: This integration test relies on
# https://github.com/google/oss-fuzz/tree/master/projects/example project.
EXAMPLE_PROJECT = 'example'

# Location of files used for testing.
TEST_FILES_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                               'test_files')


class ParseOutputTest(unittest.TestCase):
  """Tests parse_fuzzer_output."""

  def test_parse_valid_output(self):
    """Checks that the parse fuzzer output can correctly parse output."""
    # Read the fuzzer output from disk.
    fuzzer_output_path = os.path.join(TEST_FILES_PATH,
                                      'example_crash_fuzzer_output.txt')
    with open(fuzzer_output_path, 'rb') as fuzzer_output_handle:
      fuzzer_output = fuzzer_output_handle.read()
    with tempfile.TemporaryDirectory() as tmp_dir:
      bug_summary_filename = 'bug-summary.txt'
      bug_summary_path = os.path.join(tmp_dir, bug_summary_filename)
      stack_parser.parse_fuzzer_output(fuzzer_output, bug_summary_path)
      self.assertEqual(os.listdir(tmp_dir), [bug_summary_filename])
      with open(bug_summary_path) as bug_summary_handle:
        bug_summary = bug_summary_handle.read()

    # Compare the bug to the expected one.
    expected_bug_summary_path = os.path.join(TEST_FILES_PATH,
                                             'bug_summary_example.txt')
    with open(expected_bug_summary_path) as expected_bug_summary_handle:
      expected_bug_summary = expected_bug_summary_handle.read()
    self.assertEqual(expected_bug_summary, bug_summary)

  def test_parse_invalid_output(self):
    """Checks that no files are created when an invalid input was given."""
    with tempfile.TemporaryDirectory() as tmp_dir:
      artifact = os.path.join(tmp_dir, 'bug-summary.txt')
      stack_parser.parse_fuzzer_output(b'not a valid output_string', artifact)
      self.assertEqual(len(os.listdir(tmp_dir)), 0)


if __name__ == '__main__':
  unittest.main()
