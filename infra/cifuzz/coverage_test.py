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
import os
import json
import unittest
from unittest import mock

import coverage

# pylint: disable=protected-access

TEST_FILES_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                               'test_files')

PROJECT_NAME = 'curl'
REPO_PATH = '/src/curl'
FUZZ_TARGET = 'curl_fuzzer'
PROJECT_COV_JSON_FILENAME = 'example_curl_cov.json'
FUZZ_TARGET_COV_JSON_FILENAME = 'example_curl_fuzzer_cov.json'
INVALID_TARGET = 'not-a-fuzz-target'

with open(os.path.join(TEST_FILES_PATH,
                       PROJECT_COV_JSON_FILENAME),) as cov_file_handle:
  PROJECT_COV_INFO = json.loads(cov_file_handle.read())


class GetFuzzerStatsDirUrlTest(unittest.TestCase):
  """Tests _get_fuzzer_stats_dir_url."""

  @mock.patch('coverage.get_json_from_url', return_value={})
  def test_get_valid_project(self, mocked_get_json_from_url):
    """Tests that a project's coverage report can be downloaded and parsed.

    NOTE: This test relies on the PROJECT_NAME repo's coverage report.
    The "example" project was not used because it has no coverage reports.
    """
    coverage._get_fuzzer_stats_dir_url(PROJECT_NAME)
    (url,), _ = mocked_get_json_from_url.call_args
    self.assertEqual(
        'https://storage.googleapis.com/oss-fuzz-coverage/'
        'latest_report_info/curl.json', url)

  def test_get_invalid_project(self):
    """Tests that passing a bad project returns None."""
    self.assertIsNone(coverage._get_fuzzer_stats_dir_url('not-a-proj'))


class GetTargetCoverageReportTest(unittest.TestCase):
  """Tests get_target_coverage_report."""

  def setUp(self):
    with mock.patch('coverage._get_latest_cov_report_info',
                    return_value=PROJECT_COV_INFO):
      self.coverage_getter = coverage.OssFuzzCoverageGetter(
          PROJECT_NAME, REPO_PATH)

  @mock.patch('coverage.get_json_from_url', return_value={})
  def test_valid_target(self, mocked_get_json_from_url):
    """Tests that a target's coverage report can be downloaded and parsed."""
    self.coverage_getter.get_target_coverage_report(FUZZ_TARGET)
    (url,), _ = mocked_get_json_from_url.call_args
    self.assertEqual(
        'https://storage.googleapis.com/oss-fuzz-coverage/'
        'curl/fuzzer_stats/20200226/curl_fuzzer.json', url)

  def test_invalid_target(self):
    """Tests that passing an invalid target coverage report returns None."""
    self.assertIsNone(
        self.coverage_getter.get_target_coverage_report(INVALID_TARGET))

  @mock.patch('coverage._get_latest_cov_report_info', return_value=None)
  def test_invalid_project_json(self, _):
    """Tests an invalid project JSON results in None being returned."""
    coverage_getter = coverage.OssFuzzCoverageGetter(PROJECT_NAME, REPO_PATH)
    self.assertIsNone(coverage_getter.get_target_coverage_report(FUZZ_TARGET))


class GetFilesCoveredByTargetTest(unittest.TestCase):
  """Tests get_files_covered_by_target."""

  def setUp(self):
    with mock.patch('coverage._get_latest_cov_report_info',
                    return_value=PROJECT_COV_INFO):
      self.coverage_getter = coverage.OssFuzzCoverageGetter(
          PROJECT_NAME, REPO_PATH)

  def test_valid_target(self):
    """Tests that covered files can be retrieved from a coverage report."""
    with open(os.path.join(TEST_FILES_PATH,
                           FUZZ_TARGET_COV_JSON_FILENAME),) as file_handle:
      fuzzer_cov_info = json.loads(file_handle.read())

    with mock.patch('coverage.OssFuzzCoverageGetter.get_target_coverage_report',
                    return_value=fuzzer_cov_info):
      file_list = self.coverage_getter.get_files_covered_by_target(FUZZ_TARGET)

    curl_files_list_path = os.path.join(TEST_FILES_PATH,
                                        'example_curl_file_list.json')
    with open(curl_files_list_path) as file_handle:
      expected_file_list = json.loads(file_handle.read())
    self.assertCountEqual(file_list, expected_file_list)

  def test_invalid_target(self):
    """Tests passing invalid fuzz target returns None."""
    self.assertIsNone(
        self.coverage_getter.get_files_covered_by_target(INVALID_TARGET))


class IsFileCoveredTest(unittest.TestCase):
  """Tests for is_file_covered."""

  def test_is_file_covered_covered(self):
    """Tests that is_file_covered returns True for a covered file."""
    file_coverage = {
        'filename': '/src/systemd/src/basic/locale-util.c',
        'summary': {
            'regions': {
                'count': 204,
                'covered': 200,
                'notcovered': 200,
                'percent': 98.03
            }
        }
    }
    self.assertTrue(coverage.is_file_covered(file_coverage))

  def test_is_file_covered_not_covered(self):
    """Tests that is_file_covered returns False for a not covered file."""
    file_coverage = {
        'filename': '/src/systemd/src/basic/locale-util.c',
        'summary': {
            'regions': {
                'count': 204,
                'covered': 0,
                'notcovered': 0,
                'percent': 0
            }
        }
    }
    self.assertFalse(coverage.is_file_covered(file_coverage))


if __name__ == '__main__':
  unittest.main()
