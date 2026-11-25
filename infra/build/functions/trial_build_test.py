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

  @mock.patch('build_lib.get_unique_build_step_image_id',
              return_value='UNIQUE_ID')
  @mock.patch('trial_build.wait_on_builds', return_value=True)
  @mock.patch('oauth2client.client.GoogleCredentials.get_application_default',
              return_value=None)
  @mock.patch('build_project.run_build')
  @mock.patch('build_and_push_test_images.build_and_push_images')
  def test_build_steps_correct(self, mock_gcb_build_and_push_images,
                               mock_run_build, mock_get_application_default,
                               mock_wait_on_builds,
                               mock_get_unique_build_step_image_id):
    """Tests that the correct build steps for building a project are passed to
    GCB."""
    del mock_gcb_build_and_push_images
    del mock_get_application_default
    del mock_wait_on_builds
    self.maxDiff = None  # pylint: disable=invalid-name
    build_id = 1
    mock_run_build.return_value = {'id': build_id}
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


@mock.patch('build_lib.get_unique_build_step_image_id',
            return_value='UNIQUE_ID')
@mock.patch('trial_build.wait_on_builds', return_value=True)
@mock.patch('trial_build._get_production_build_statuses', return_value={})
@mock.patch('oauth2client.client.GoogleCredentials.get_application_default',
            return_value=None)
@mock.patch('build_project.run_build', return_value={'id': 1})
@mock.patch('build_and_push_test_images.build_and_push_images')
class TrialBuildSourceTest(unittest.TestCase):
  """Tests that trial builds build the approved commit and don't publish."""

  COMMIT = '0123456789abcdef0123456789abcdef01234567'
  SOURCE = ('https://github.com/pr-author/oss-fuzz', 'pr-branch', COMMIT)

  def _get_steps(self, mock_run_build, args, source):
    """Runs a trial build of skcms with |args| and |source|, and returns the
    steps of each GCB build that it started."""
    args = args + ['--version-tag', 'ubuntu-24-04', '--force-build', 'skcms']
    self.assertTrue(
        trial_build.trial_build_main(args, local_base_build=True,
                                     source=source))
    return [call[0][1] for call in mock_run_build.call_args_list]

  def test_builds_commit(self, mock_build_and_push_images, mock_run_build, *_):
    """Tests that the source comes from |source|, even when the command
    tries to change it."""
    del mock_build_and_push_images
    args = [
        '--repo', 'https://github.com/evil/repo', '--branch', 'evil',
        '--commit', 'f' * 40, '--sanitizers', 'address', 'indexer',
        '--fuzzing-engines', 'libfuzzer'
    ]
    all_steps = self._get_steps(mock_run_build, args, self.SOURCE)
    self.assertEqual(2, len(all_steps))
    expected_clone_step = {
        'args': [
            '-c', 'git init oss-fuzz && cd oss-fuzz && '
            'git fetch --depth 1 -- https://github.com/pr-author/oss-fuzz '
            f'{self.COMMIT} && git checkout --detach {self.COMMIT}'
        ],
        'entrypoint': 'bash',
        'name': 'gcr.io/cloud-builders/git',
    }
    for steps in all_steps:
      self.assertEqual(expected_clone_step, steps[0])
      self.assertNotIn('evil', json.dumps(steps))

  def test_indexer_does_not_publish(self, mock_build_and_push_images,
                                    mock_run_build, *_):
    """Tests that indexer trial builds don't upload snapshots or push images to
    production."""
    del mock_build_and_push_images
    all_steps = self._get_steps(mock_run_build, ['--sanitizers', 'indexer'],
                                self.SOURCE)
    self.assertEqual(1, len(all_steps))
    steps = json.dumps(all_steps[0])
    self.assertIn('/opt/indexer/index_build.py', steps)
    self.assertNotIn('clusterfuzz-builds', steps)
    self.assertNotIn('us-docker.pkg.dev/oss-fuzz/indexer', steps)
    self.assertNotIn('us-docker.pkg.dev/oss-fuzz/tracer', steps)
    self.assertNotIn('"push"', steps)


if __name__ == '__main__':
  unittest.main(exit=False)
