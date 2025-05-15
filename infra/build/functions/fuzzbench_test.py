# Copyright 2025 Google LLC
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
#
################################################################################
"""Tests for fuzzbench.py."""
import requests
import unittest
from unittest import mock

import fuzzbench


class GetFuzzTargetName(unittest.TestCase):
  """Tests for get_fuzz_target_name."""

  @mock.patch('requests.get')
  @mock.patch('random.randint')
  @mock.patch('logging.info')
  def test_successful_retrieval(self, mock_logging_info, mock_randint, mock_get):
    """Tests successful retrieval and random selection of a fuzz target."""
    mock_response = mock.MagicMock()
    mock_response.raise_for_status.return_value = None
    mock_response.json.return_value = {
      'result': 'success',
      'pairs': [
        {'executable': 'target1'},
        {'executable': 'target2'},
        {'executable': 'target3'}
      ]
    }
    mock_get.return_value = mock_response
    mock_randint.return_value = 1

    project_name = 'test_project'
    fuzz_target = fuzzbench.get_fuzz_target_name(project_name)

    self.assertEqual(fuzz_target, 'target2')
    mock_get.assert_called_once_with(
      f'https://introspector.oss-fuzz.com/api/harness-source-and-executable?project={project_name}',
      headers={'accept': 'application/json'}
    )
    mock_randint.assert_called_once_with(0, 2)
    mock_logging_info.assert_called_with('Using fuzz target: target2')

  @mock.patch('requests.get')
  @mock.patch('logging.info')
  def test_api_error(self, mock_logging_info, mock_get):
    """Tests handling of API errors during the request."""
    mock_response = mock.MagicMock()
    mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError('API Error')
    mock_get.return_value = mock_response

    project_name = 'error_project'
    with self.assertRaises(requests.exceptions.HTTPError):
      fuzzbench.get_fuzz_target_name(project_name)

    mock_get.assert_called_once_with(
      f'https://introspector.oss-fuzz.com/api/harness-source-and-executable?project={project_name}',
      headers={'accept': 'application/json'}
    )
    mock_logging_info.assert_not_called()

  @mock.patch('requests.get')
  @mock.patch('logging.info')
  def test_no_fuzz_targets(self, mock_logging_info, mock_get):
    """Tests the case where the API returns an error indicating no fuzz targets."""
    mock_response = mock.MagicMock()
    mock_response.raise_for_status.return_value = None
    mock_response.json.return_value = {'result': 'error'}
    mock_get.return_value = mock_response

    project_name = 'empty_project'
    fuzz_target = fuzzbench.get_fuzz_target_name(project_name)

    self.assertIsNone(fuzz_target)
    mock_get.assert_called_once_with(
      f'https://introspector.oss-fuzz.com/api/harness-source-and-executable?project={project_name}',
      headers={'accept': 'application/json'}
    )
    mock_logging_info.assert_called_once_with(f'There are no fuzz targets available for {project_name}')

  @mock.patch('requests.get')
  @mock.patch('logging.info')
  def test_empty_pairs(self, mock_logging_info, mock_get):
    """Tests the case where the API returns an empty list of fuzz target pairs."""
    mock_response = mock.MagicMock()
    mock_response.raise_for_status.return_value = None
    mock_response.json.return_value = {'result': 'success', 'pairs': []}
    mock_get.return_value = mock_response

    project_name = 'empty_pairs_project'
    fuzz_target = fuzzbench.get_fuzz_target_name(project_name)

    self.assertIsNone(fuzz_target)
    mock_get.assert_called_once_with(
      f'https://introspector.oss-fuzz.com/api/harness-source-and-executable?project={project_name}',
      headers={'accept': 'application/json'}
    )
    mock_logging_info.assert_called_once_with(f'There are no fuzz targets available for {project_name}')


if __name__ == '__main__':
    unittest.main()
