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


class GetTargetCoverageReportTest(unittest.TestCase):
  """Tests get_target_coverage_report."""

  EXAMPLE_COV_JSON = 'example_curl_cov.json'
  EXAMPLE_FUZZER = 'curl_fuzzer'

  def setUp(self):
    with open(os.path.join(TEST_FILES_PATH, self.EXAMPLE_COV_JSON),
              'r') as file_handle:
      example_cov_info = json.loads(file_handle.read())
    project_name = 'curl'
    repo_path = '/src/curl'
    with mock.patch('coverage._get_latest_cov_report_info',
                    return_value=example_cov_info):
      self.coverage_getter = coverage.OssFuzzCoverageGetter(
          project_name, repo_path)

  @mock.patch('coverage.get_json_from_url', return_value={})
  def test_valid_target(self, mocked_get_json_from_url):
    """Tests that a target's coverage report can be downloaded and parsed."""
    self.coverage_getter.get_target_coverage_report(self.EXAMPLE_FUZZER)
    (url,), _ = mocked_get_json_from_url.call_args
    self.assertEqual(
        'https://storage.googleapis.com/oss-fuzz-coverage/'
        'curl/fuzzer_stats/20200226/curl_fuzzer.json', url)

  def test_invalid_target(self):
    """Tests that passing an invalid target coverage report returns None."""
    self.assertIsNone(
        self.coverage_getter.get_target_coverage_report('not-valid-target'))


class GetFilesCoveredByTargetTest(unittest.TestCase):
  """Tests get_files_covered_by_target."""

  FUZZER_COV_JSON_FILENAME = 'example_curl_fuzzer_cov.json'
  EXAMPLE_FUZZER = 'curl_fuzzer'
  PROJECT_NAME = 'curl'
  REPO_PATH = '/src/curl'

  def setUp(self):
    example_cov_json = 'example_curl_cov.json'
    with open(os.path.join(TEST_FILES_PATH, example_cov_json)) as file_handle:
      self.cov_report = json.loads(file_handle.read())

    with mock.patch('coverage._get_latest_cov_report_info',
                    return_value=self.cov_report):
      self.coverage_getter = coverage.OssFuzzCoverageGetter(
          self.PROJECT_NAME, self.REPO_PATH)
    with open(os.path.join(TEST_FILES_PATH,
                           self.FUZZER_COV_JSON_FILENAME)) as file_handle:
      self.fuzzer_cov_report = json.loads(file_handle.read())

  def test_valid_target(self):
    """Tests that covered files can be retrieved from a coverage report."""
    with mock.patch('coverage.OssFuzzCoverageGetter.get_target_coverage_report',
                    return_value=self.fuzzer_cov_report):
      file_list = self.coverage_getter.get_files_covered_by_target(
          self.EXAMPLE_FUZZER)

    curl_files_list_path = os.path.join(TEST_FILES_PATH,
                                        'example_curl_file_list.json')
    with open(curl_files_list_path) as file_handle:
      true_files_list = json.load(file_handle)
    self.assertCountEqual(file_list, true_files_list)


class IsFileCoveredTest(unittest.TestCase):
  """Tests for is_file_covered."""
  def test_is_file_covered_covered(self):
    """Tests that is_file_covered returns True for a covered file."""
    file_coverage = {
        'filename': '/src/systemd/src/basic/locale-util.c',
        'summary': {
            'regions': {
                'count': 204, 'covered': 200, 'notcovered': 200,
                'percent': 98.03
            }
        }
    }
    self.assertTrue(coverage.is_file_covered(file_coverage))

  def test_is_file_covered_covered(self):
    """Tests that is_file_covered returns False for a noncovered file."""
    file_coverage = {
        'filename': '/src/systemd/src/basic/locale-util.c',
        'summary': {
            'regions': {
                'count': 204, 'covered': 0, 'notcovered': 0,
                'percent': 0
            }
        }
    }
    self.assertFalse(coverage.is_file_covered(file_coverage))


if __name__ == '__main__':
  unittest.main()
