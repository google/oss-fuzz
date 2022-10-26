# Copyright 2022 Google LLC
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
"""Tests for trial_build.py."""
import json
import unittest
from unittest import mock

import test_utils
import trial_build


class GetProjectsToBuild(unittest.TestCase):
  """Tests for get_projects_to_build."""

  PROJECTS = ['myproject', 'myfailingproject']

  @mock.patch('trial_build._get_production_build_statuses',
              return_value={
                  'myproject': True,
                  'myfailingproject': False
              })
  def test_force_build(self, mock_get_production_build_statuses):
    """Tests force build works."""
    del mock_get_production_build_statuses
    buildable_projects = trial_build.get_projects_to_build(
        self.PROJECTS, 'fuzzing', True)
    self.assertEqual(self.PROJECTS, buildable_projects)

  @mock.patch('trial_build._get_production_build_statuses',
              return_value={
                  'myproject': True,
                  'myfailingproject': False
              })
  def test_get_projects_to_build(self, mock_get_production_build_statuses):
    """Tests get_projects_to_build works."""
    del mock_get_production_build_statuses
    buildable_projects = trial_build.get_projects_to_build(
        self.PROJECTS, 'fuzzing', True)
    self.assertEqual(self.PROJECTS, buildable_projects)


class TrialBuildMainTest(unittest.TestCase):
  """Tests for trial_build_main."""

  @mock.patch('trial_build.wait_on_builds', return_value=True)
  @mock.patch('oauth2client.client.GoogleCredentials.get_application_default',
              return_value=None)
  @mock.patch('build_project.run_build')
  @mock.patch('build_and_push_test_images.build_and_push_images')
  def test_build_steps_correct(self, mock_gcb_build_and_push_images,
                               mock_run_build, mock_get_application_default,
                               mock_wait_on_builds):
    """Tests that the correct build steps for building a project are passed to
    GCB."""
    del mock_gcb_build_and_push_images
    del mock_get_application_default
    del mock_wait_on_builds
    self.maxDiff = None  # pylint: disable=invalid-name
    build_id = 1
    mock_run_build.return_value = build_id
    branch_name = 'mybranch'
    project = 'skcms'
    args = [
        '--sanitizers', 'address', 'undefined', '--fuzzing-engines', 'afl',
        'libfuzzer', '--branch', branch_name, '--force-build', project
    ]
    self.assertTrue(trial_build.trial_build_main(args))
    expected_build_steps_path = test_utils.get_test_data_file_path(
        'expected_trial_build_steps.json')
    with open(expected_build_steps_path, 'r') as file_handle:
      expected_build_steps = json.load(file_handle)

    # Snippet for updating this:
    # f=open('/tmp/a', 'w')
    # json.dump(mock_run_build.call_args_list[0][0][1], f); f.close()
    self.assertEqual(mock_run_build.call_args_list[0][0][1],
                     expected_build_steps)


if __name__ == '__main__':
  unittest.main(exit=False)
