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
"""Tests for get_coverage.py"""
import os
import json
import unittest
from unittest import mock

import parameterized
from pyfakefs import fake_filesystem_unittest
import pytest

import get_coverage

# pylint: disable=protected-access

TEST_DATA_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                              'test_data')

PROJECT_NAME = 'curl'
REPO_PATH = '/src/curl'
FUZZ_TARGET = 'curl_fuzzer'
PROJECT_COV_JSON_FILENAME = 'example_curl_cov.json'
FUZZ_TARGET_COV_JSON_FILENAME = 'example_curl_fuzzer_cov.json'
INVALID_TARGET = 'not-a-fuzz-target'

with open(os.path.join(TEST_DATA_PATH,
                       PROJECT_COV_JSON_FILENAME),) as cov_file_handle:
  PROJECT_COV_INFO = json.loads(cov_file_handle.read())


class GetOssFuzzFuzzerStatsDirUrlTest(unittest.TestCase):
  """Tests _get_oss_fuzz_fuzzer_stats_dir_url."""

  @mock.patch('http_utils.get_json_from_url',
              return_value={
                  'fuzzer_stats_dir':
                      'gs://oss-fuzz-coverage/systemd/fuzzer_stats/20210303'
              })
  def test_get_valid_project(self, mock_get_json_from_url):
    """Tests that a project's coverage report can be downloaded and parsed.

    NOTE: This test relies on the PROJECT_NAME repo's coverage report.
    The "example" project was not used because it has no coverage reports.
    """
    result = get_coverage._get_oss_fuzz_fuzzer_stats_dir_url(PROJECT_NAME)
    (url,), _ = mock_get_json_from_url.call_args
    self.assertEqual(
        'https://storage.googleapis.com/oss-fuzz-coverage/'
        'latest_report_info/curl.json', url)

    expected_result = (
        'https://storage.googleapis.com/oss-fuzz-coverage/systemd/fuzzer_stats/'
        '20210303')
    self.assertEqual(result, expected_result)

  def test_get_invalid_project(self):
    """Tests that passing a bad project returns None."""
    self.assertIsNone(
        get_coverage._get_oss_fuzz_fuzzer_stats_dir_url('not-a-proj'))


class OSSFuzzCoverageGetTargetCoverageTest(unittest.TestCase):
  """Tests OSSFuzzCoverage.get_target_coverage."""

  def setUp(self):
    with mock.patch('get_coverage._get_oss_fuzz_latest_cov_report_info',
                    return_value=PROJECT_COV_INFO):
      self.oss_fuzz_coverage = get_coverage.OSSFuzzCoverage(
          REPO_PATH, PROJECT_NAME)

  @mock.patch('http_utils.get_json_from_url', return_value={})
  def test_valid_target(self, mock_get_json_from_url):
    """Tests that a target's coverage report can be downloaded and parsed."""
    self.oss_fuzz_coverage.get_target_coverage(FUZZ_TARGET)
    (url,), _ = mock_get_json_from_url.call_args
    self.assertEqual(
        'https://storage.googleapis.com/oss-fuzz-coverage/'
        'curl/fuzzer_stats/20200226/curl_fuzzer.json', url)

  def test_invalid_target(self):
    """Tests that passing an invalid target coverage report returns None."""
    self.assertIsNone(
        self.oss_fuzz_coverage.get_target_coverage(INVALID_TARGET))

  @mock.patch('get_coverage._get_oss_fuzz_latest_cov_report_info',
              return_value=None)
  def test_invalid_project_json(self, _):  # pylint: disable=no-self-use
    """Tests an invalid project JSON results in None being returned."""
    with pytest.raises(get_coverage.CoverageError):
      get_coverage.OSSFuzzCoverage(REPO_PATH, PROJECT_NAME)


def _get_expected_curl_covered_file_list():
  """Returns the expected covered file list for
  FUZZ_TARGET_COV_JSON_FILENAME."""
  curl_files_list_path = os.path.join(TEST_DATA_PATH,
                                      'example_curl_file_list.json')
  with open(curl_files_list_path) as file_handle:
    return json.loads(file_handle.read())


def _get_example_curl_coverage():
  """Returns the contents of the fuzzer stats JSON file for
  FUZZ_TARGET_COV_JSON_FILENAME."""
  with open(os.path.join(TEST_DATA_PATH,
                         FUZZ_TARGET_COV_JSON_FILENAME)) as file_handle:
    return json.loads(file_handle.read())


class OSSFuzzCoverageGetFilesCoveredByTargetTest(unittest.TestCase):
  """Tests OSSFuzzCoverage.get_files_covered_by_target."""

  def setUp(self):
    with mock.patch('get_coverage._get_oss_fuzz_latest_cov_report_info',
                    return_value=PROJECT_COV_INFO):
      self.oss_fuzz_coverage = get_coverage.OSSFuzzCoverage(
          REPO_PATH, PROJECT_NAME)

  @parameterized.parameterized.expand([({
      'data': []
  },), ({
      'data': [[]]
  },), ({
      'data': [{}]
  },)])
  def test_malformed_cov_data(self, coverage_data):
    """Tests that covered files can be retrieved from a coverage report."""
    with mock.patch('get_coverage.OSSFuzzCoverage.get_target_coverage',
                    return_value=coverage_data):
      self.oss_fuzz_coverage.get_files_covered_by_target(FUZZ_TARGET)

  def test_valid_target(self):
    """Tests that covered files can be retrieved from a coverage report."""
    fuzzer_cov_data = _get_example_curl_coverage()
    with mock.patch('get_coverage.OSSFuzzCoverage.get_target_coverage',
                    return_value=fuzzer_cov_data):
      file_list = self.oss_fuzz_coverage.get_files_covered_by_target(
          FUZZ_TARGET)

    expected_file_list = _get_expected_curl_covered_file_list()
    self.assertCountEqual(file_list, expected_file_list)

  def test_invalid_target(self):
    """Tests passing invalid fuzz target returns None."""
    self.assertIsNone(
        self.oss_fuzz_coverage.get_files_covered_by_target(INVALID_TARGET))


class FilesystemCoverageGetFilesCoveredByTargetTest(
    fake_filesystem_unittest.TestCase):
  """Tests FilesystemCoverage.get_files_covered_by_target."""

  def setUp(self):
    _fuzzer_cov_data = _get_example_curl_coverage()
    self._expected_file_list = _get_expected_curl_covered_file_list()
    self.coverage_path = '/coverage'
    self.filesystem_coverage = get_coverage.FilesystemCoverage(
        REPO_PATH, self.coverage_path)
    self.setUpPyfakefs()
    self.fs.create_file(os.path.join(self.coverage_path, 'fuzzer_stats',
                                     FUZZ_TARGET + '.json'),
                        contents=json.dumps(_fuzzer_cov_data))

  def test_valid_target(self):
    """Tests that covered files can be retrieved from a coverage report."""
    file_list = self.filesystem_coverage.get_files_covered_by_target(
        FUZZ_TARGET)
    self.assertCountEqual(file_list, self._expected_file_list)

  def test_invalid_target(self):
    """Tests passing invalid fuzz target returns None."""
    self.assertIsNone(
        self.filesystem_coverage.get_files_covered_by_target(INVALID_TARGET))


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
    self.assertTrue(get_coverage.is_file_covered(file_coverage))

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
    self.assertFalse(get_coverage.is_file_covered(file_coverage))


class GetOssFuzzLatestCovReportInfo(unittest.TestCase):
  """Tests that _get_oss_fuzz_latest_cov_report_info works as
  intended."""

  PROJECT = 'project'
  LATEST_REPORT_INFO_URL = ('https://storage.googleapis.com/oss-fuzz-coverage/'
                            'latest_report_info/project.json')

  @mock.patch('logging.error')
  @mock.patch('http_utils.get_json_from_url', return_value={'coverage': 1})
  def test_get_oss_fuzz_latest_cov_report_info(self, mock_get_json_from_url,
                                               mock_error):
    """Tests that _get_oss_fuzz_latest_cov_report_info works as intended."""
    result = get_coverage._get_oss_fuzz_latest_cov_report_info(self.PROJECT)
    self.assertEqual(result, {'coverage': 1})
    mock_error.assert_not_called()
    mock_get_json_from_url.assert_called_with(self.LATEST_REPORT_INFO_URL)

  @mock.patch('logging.error')
  @mock.patch('http_utils.get_json_from_url', return_value=None)
  def test_get_oss_fuzz_latest_cov_report_info_fail(self, _, mock_error):
    """Tests that _get_oss_fuzz_latest_cov_report_info works as intended when we
    can't get latest report info."""
    result = get_coverage._get_oss_fuzz_latest_cov_report_info('project')
    self.assertIsNone(result)
    mock_error.assert_called_with(
        'Could not get the coverage report json from url: %s.',
        self.LATEST_REPORT_INFO_URL)


if __name__ == '__main__':
  unittest.main()
