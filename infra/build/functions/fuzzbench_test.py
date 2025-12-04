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

import logging
import os
import requests
import sys
import shutil
import tempfile
import unittest
from unittest import mock

import build_lib
import build_project
import fuzzbench
import fuzzbench_local_run

LOG_FILE_PATH = os.path.join(os.path.dirname(__file__),
                             'fuzzbench_test_log.txt')


class GetFuzzTargetName(unittest.TestCase):
  """Tests for get_fuzz_target_name."""

  @mock.patch('requests.get')
  @mock.patch('random.randint')
  @mock.patch('logging.info')
  def test_successful_retrieval(self, mock_logging_info, mock_randint,
                                mock_get):
    """Tests successful retrieval and random selection of a fuzz target."""
    mock_response = mock.MagicMock()
    mock_response.raise_for_status.return_value = None
    mock_response.json.return_value = {
        'result':
            'success',
        'pairs': [{
            'executable': 'target1'
        }, {
            'executable': 'target2'
        }, {
            'executable': 'target3'
        }]
    }
    mock_get.return_value = mock_response
    mock_randint.return_value = 1

    project_name = 'test_project'
    fuzz_target = fuzzbench.get_fuzz_target_name(project_name)

    self.assertEqual(fuzz_target, 'target2')
    mock_get.assert_called_once_with(
        f'https://introspector.oss-fuzz.com/api/harness-source-and-executable?project={project_name}',
        headers={'accept': 'application/json'})
    mock_randint.assert_called_once_with(0, 2)
    mock_logging_info.assert_called_with('Using fuzz target: target2')

  @mock.patch('requests.get')
  @mock.patch('logging.info')
  def test_api_error(self, mock_logging_info, mock_get):
    """Tests handling of API errors during the request."""
    mock_response = mock.MagicMock()
    mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError(
        'API Error')
    mock_get.return_value = mock_response

    project_name = 'error_project'
    with self.assertRaises(requests.exceptions.HTTPError):
      fuzzbench.get_fuzz_target_name(project_name)

    mock_get.assert_called_once_with(
        f'https://introspector.oss-fuzz.com/api/harness-source-and-executable?project={project_name}',
        headers={'accept': 'application/json'})
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
        headers={'accept': 'application/json'})
    mock_logging_info.assert_called_once_with(
        f'There are no fuzz targets available for {project_name}')

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
        headers={'accept': 'application/json'})
    mock_logging_info.assert_called_once_with(
        f'There are no fuzz targets available for {project_name}')


class FuzzbenchRunsTest(unittest.TestCase):
  """Tests for fuzzbench runs."""

  def setUp(self):
    """Creates a temporary directory for fuzzbench runs tests."""
    self.temp_dir = tempfile.mkdtemp()

  def tearDown(self):
    """Removes temporary directory."""
    with open(LOG_FILE_PATH, 'w', encoding='utf-8') as log_file:
      fuzzbench_local_run.remove_temp_dir_content(self.temp_dir, -1, log_file)
      shutil.rmtree(self.temp_dir)
    os.remove(LOG_FILE_PATH)

  def _fuzzbench_test_setup(self):
    """Returns necessary variables for fuzzbench runs setup."""
    project_name = 'example'
    fuzz_target_name = 'do_stuff_fuzzer'
    project_yaml, dockerfile_lines = build_project.get_project_data(
        project_name)
    project = build_project.Project(project_name, project_yaml,
                                    dockerfile_lines)
    fuzzing_engine = 'mopt'
    build = build_project.Build(fuzzing_engine, 'address', 'x86_64')
    env = fuzzbench.get_env(project, build, fuzz_target_name)

    return fuzzing_engine, project, env

  def _assert_log_content(self, frequency):
    """Asserts the frequency of 'successfully' in the log content."""
    with open(LOG_FILE_PATH, 'r', encoding='utf-8') as log_file:
      log_content = log_file.read()
      count = log_content.count('successfully')
      self.assertGreaterEqual(count, frequency)

  def _fuzzbench_setup_steps_test(self, fuzzing_engine, project, env):
    """Test for fuzzbench setup steps."""
    steps = fuzzbench.get_fuzzbench_setup_steps()
    fuzzbench_local_run.run_steps_locally(steps,
                                          self.temp_dir,
                                          LOG_FILE_PATH,
                                          testing=True)
    self._assert_log_content(3)

  def _get_project_image_steps_test(self, fuzzing_engine, project, env_dict):
    """Test for project image steps."""
    config = build_project.Config(build_type=fuzzbench.FUZZBENCH_BUILD_TYPE,
                                  fuzzing_engine=fuzzing_engine,
                                  fuzz_target=env_dict['FUZZ_TARGET'])
    steps = build_lib.get_project_image_steps(project.name,
                                              project.image,
                                              project.fuzzing_language,
                                              config=config)
    fuzzbench_local_run.run_steps_locally(steps,
                                          self.temp_dir,
                                          LOG_FILE_PATH,
                                          testing=True)
    self._assert_log_content(3)

  def _build_fuzzers_steps_test(self, fuzzing_engine, project, env):
    """Test for build fuzzers steps."""
    steps = fuzzbench.get_build_fuzzers_steps(fuzzing_engine, project, env)
    fuzzbench_local_run.run_steps_locally(steps,
                                          self.temp_dir,
                                          LOG_FILE_PATH,
                                          testing=True)
    self._assert_log_content(2)

  def _corpus_steps_test(self, fuzzing_engine, project, env_dict):
    """Test for corpus steps."""
    steps = fuzzbench.get_gcs_corpus_steps(fuzzing_engine, project, env_dict)
    fuzzbench_local_run.run_steps_locally(steps,
                                          self.temp_dir,
                                          LOG_FILE_PATH,
                                          testing=True)
    self._assert_log_content(2)

  def _build_ood_image_steps_test(self, fuzzing_engine, project, env_dict):
    """Test for build ood image steps."""
    steps = fuzzbench.get_build_ood_image_steps(fuzzing_engine, project,
                                                env_dict)
    # Limit fuzzing time for testing
    build_ood_image_args = steps[2]['args']
    for i in range(len(build_ood_image_args)):
      if 'MAX_TOTAL_TIME' in build_ood_image_args[i]:
        build_ood_image_args[i] = 'MAX_TOTAL_TIME=5'
    fuzzbench_local_run.run_steps_locally(steps,
                                          self.temp_dir,
                                          LOG_FILE_PATH,
                                          testing=True)
    self._assert_log_content(3)

  def _run_ood_image_step_test(self, fuzzing_engine, project, env_dict):
    """Test for run ood image step."""
    steps = fuzzbench.get_push_and_run_ood_image_steps(fuzzing_engine, project,
                                                       env_dict)
    test_steps = []
    for step in steps:
      if step['args'][0] != 'push':
        test_steps.append(step)
    fuzzbench_local_run.run_steps_locally(test_steps,
                                          self.temp_dir,
                                          LOG_FILE_PATH,
                                          testing=True)
    self._assert_log_content(1)

  def _extract_crashes_steps_test(self, fuzzing_engine, project, env_dict):
    """Test for extract crashes steps."""
    steps = fuzzbench.get_extract_crashes_steps(fuzzing_engine, project,
                                                env_dict)
    for step in steps:
      if '-runs=0 -artifact_prefix=' in step['args'][-1]:
        step['args'] = ['timeout', '10'] + step['args']
    fuzzbench_local_run.run_steps_locally(steps,
                                          self.temp_dir,
                                          LOG_FILE_PATH,
                                          testing=True)
    self._assert_log_content(3)

  def test_fuzzbench_runs(self):
    """Test for fuzzbench runs."""
    fuzzing_engine, project, env = self._fuzzbench_test_setup()
    env_dict = {string.split('=')[0]: string.split('=')[1] for string in env}
    self._fuzzbench_setup_steps_test(fuzzing_engine, project, env)
    self._get_project_image_steps_test(fuzzing_engine, project, env_dict)
    self._build_fuzzers_steps_test(fuzzing_engine, project, env)
    self._corpus_steps_test(fuzzing_engine, project, env_dict)
    # Disable OOD test as it seems broken
    # TODO(Jonathan) (David) fix this test.
    # self._build_ood_image_steps_test(fuzzing_engine, project, env_dict)
    # self._run_ood_image_step_test(fuzzing_engine, project, env_dict)
    self._extract_crashes_steps_test(fuzzing_engine, project, env_dict)


if __name__ == '__main__':
  unittest.main()
