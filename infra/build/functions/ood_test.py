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
import sys
import shutil
import tempfile
import unittest

import build_lib
import build_project
import fuzzbench
import ood_run_local

LOG_FILE_PATH = os.path.join(os.path.dirname(__file__), 'ood_test_log.txt')

class FuzzbenchTest(unittest.TestCase):
  """Tests for fuzzbench runs"""
  temp_dir = tempfile.mkdtemp()

  def remove_temp_dir(self):
    """"""
    ood_run_local.remove_temp_dir_content(self.temp_dir, -1)
    shutil.rmtree(self.temp_dir)

  def _fuzzbench_setup_steps_test(self, fuzzing_engine, project, env):
    steps = fuzzbench.get_fuzzbench_setup_steps()
    ood_run_local.run_steps_locally(steps, self.temp_dir, LOG_FILE_PATH, testing=True)
      
    with open(LOG_FILE_PATH, 'r', encoding='utf-8') as log_file:
      log_content = log_file.read()
      expected_string = 'Cloning'
      self.assertIn(expected_string, log_content)

  def _get_project_image_steps_test(self, fuzzing_engine, project, env_dict):
    config = build_project.Config(build_type=fuzzbench.FUZZBENCH_BUILD_TYPE,
                    fuzzing_engine=fuzzing_engine,
                    fuzz_target=env_dict['FUZZ_TARGET'])
    steps = build_lib.get_project_image_steps(project.name,
                                              project.image,
                                              project.fuzzing_language,
                                              config=config)
    ood_run_local.run_steps_locally(steps, self.temp_dir, LOG_FILE_PATH, testing=True)
      
    with open(LOG_FILE_PATH, 'r', encoding='utf-8') as log_file:
      log_content = log_file.read()
      expected_string = 'clone'
      self.assertIn(expected_string, log_content)


  def _build_fuzzers_steps_test(self, fuzzing_engine, project, env):
    steps = fuzzbench.get_build_fuzzers_steps(fuzzing_engine, project, env)
    ood_run_local.run_steps_locally(steps, self.temp_dir, LOG_FILE_PATH, testing=True)
      
    with open(LOG_FILE_PATH, 'r', encoding='utf-8') as log_file:
      log_content = log_file.read()
      expected_string = 'Copying afl-fuzz'
      self.assertIn(expected_string, log_content)

  def _corpus_steps_test(self, fuzzing_engine, project, env_dict):
    steps = fuzzbench.get_gcs_corpus_steps(fuzzing_engine, project, env_dict)
    ood_run_local.run_steps_locally(steps, self.temp_dir, LOG_FILE_PATH, testing=True)
      
    with open(LOG_FILE_PATH, 'r', encoding='utf-8') as log_file:
      log_content = log_file.read()
      expected_string = 'URL exists.'
      self.assertIn(expected_string, log_content)
  
  def _build_ood_image_steps_test(self, fuzzing_engine, project, env_dict):
    steps = fuzzbench.get_build_ood_image_steps(fuzzing_engine, project, env_dict)
    ood_run_local.run_steps_locally(steps, self.temp_dir, LOG_FILE_PATH, testing=True)
      
    with open(LOG_FILE_PATH, 'r', encoding='utf-8') as log_file:
      log_content = log_file.read()
      expected_string = 'Successfully built'
      self.assertIn(expected_string, log_content)
  
  def _run_ood_image_step_test(self, fuzzing_engine, project, env_dict):
    steps = fuzzbench.get_push_and_run_ood_image_steps(fuzzing_engine, project, env_dict)
    test_steps = []
    for step in steps:
      if step['args'][0] != 'push':
        test_steps.append(step)
    ood_run_local.run_steps_locally(test_steps, self.temp_dir, LOG_FILE_PATH, testing=True)
      
    with open(LOG_FILE_PATH, 'r', encoding='utf-8') as log_file:
      log_content = log_file.read()
      expected_string = 'Running target'
      self.assertIn(expected_string, log_content)
  
  def _extract_crashes_steps_test(self, fuzzing_engine, project, env_dict):
    steps = fuzzbench.get_extract_crashes_steps(fuzzing_engine, project, env_dict)
  
    for step in steps:
      if '-runs=0 -artifact_prefix=' in step['args'][-1]:
        step['args'] = ['timeout', '10'] + step['args']
    ood_run_local.run_steps_locally(steps, self.temp_dir, LOG_FILE_PATH, testing=True)
      
    with open(LOG_FILE_PATH, 'r', encoding='utf-8') as log_file:
      log_content = log_file.read()
      expected_string = 'inflating'
      self.assertIn(expected_string, log_content)


  def test_fuzzbench(self):
    fuzzing_engine, project, env = ood_test_setup()
    env_dict = {string.split('=')[0]: string.split('=')[1] for string in env}
    instance = FuzzbenchTest()
    instance._fuzzbench_setup_steps_test(fuzzing_engine, project, env)
    instance._get_project_image_steps_test(fuzzing_engine, project, env_dict)
    instance._build_fuzzers_steps_test(fuzzing_engine, project, env)
    instance._corpus_steps_test(fuzzing_engine, project, env_dict)
    instance._build_ood_image_steps_test(fuzzing_engine, project, env_dict)
    instance._run_ood_image_step_test(fuzzing_engine, project, env_dict)
    instance._extract_crashes_steps_test(fuzzing_engine, project, env_dict)
    self.remove_temp_dir()


def ood_test_setup():
  project_name = 'example'
  fuzz_target_name = 'do_stuff_fuzzer'
  project_yaml, dockerfile_lines = build_project.get_project_data(project_name)
  project = build_project.Project(project_name, project_yaml, dockerfile_lines)
  fuzzing_engine = 'mopt'
  build = build_project.Build(fuzzing_engine, 'address', 'x86_64')
  env = fuzzbench.get_env(project, build, fuzz_target_name)

  return fuzzing_engine, project, env


if __name__ == '__main__':
  unittest.main()
