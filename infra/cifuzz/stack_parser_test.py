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
    test_output_path = os.path.join(TEST_FILES_PATH,
                                    'example_crash_fuzzer_output.txt')
    test_summary_path = os.path.join(TEST_FILES_PATH, 'bug_summary_example.txt')
    with tempfile.TemporaryDirectory() as tmp_dir:
      with open(test_output_path, 'rb') as test_fuzz_output:
        stack_parser.parse_fuzzer_output(test_fuzz_output.read(), tmp_dir)
      result_files = ['bug_summary.txt']
      self.assertCountEqual(os.listdir(tmp_dir), result_files)

      # Compare the bug summaries.
      with open(os.path.join(tmp_dir, 'bug_summary.txt')) as bug_summary:
        detected_summary = bug_summary.read()
      with open(test_summary_path) as bug_summary:
        real_summary = bug_summary.read()
      self.assertEqual(detected_summary, real_summary)

  def test_parse_invalid_output(self):
    """Checks that no files are created when an invalid input was given."""
    with tempfile.TemporaryDirectory() as tmp_dir:
      stack_parser.parse_fuzzer_output(b'not a valid output_string', tmp_dir)
      self.assertEqual(len(os.listdir(tmp_dir)), 0)


if __name__ == '__main__':
  unittest.main()
