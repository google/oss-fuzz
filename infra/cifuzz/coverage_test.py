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
"""Tests for coverage.py"""
import unittest
from unittest import mock

import coverage



class GetFuzzerStatsDirUrlTest(unittest.TestCase):
  """Tests _get_fuzzer_stats_dir_url."""

  TEST_PROJECT = 'curl'

  @mock.patch('coverage.get_json_from_url', return_value={})
  def test_get_valid_project(self, mocked_get_json_from_url):
    """Tests that a project's coverage report can be downloaded and parsed.

    NOTE: This test relies on the TEST_PROJECT repo's coverage report.
    The "example" project was not used because it has no coverage reports.
    """
    coverage._get_fuzzer_stats_dir_url(self.TEST_PROJECT)
    (url,), _ = mocked_get_json_from_url.call_args
    self.assertEqual(
        'https://storage.googleapis.com/oss-fuzz-coverage/'
        'latest_report_info/curl.json', url)

  def test_get_invalid_project(self):
    """Tests that passing a bad project returns None."""
    self.assertIsNone(coverage._get_fuzzer_stats_dir_url('not-a-proj'))
    self.assertIsNone(coverage._get_fuzzer_stats_dir_url(''))


if __name__ == '__main__':
  unittest.main()
