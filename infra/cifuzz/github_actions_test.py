# Copyright 2020 Google LLC
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
"""Module is used to test CIFuzz using the GitHub actions CITool. Its purpose
is to assert that CIFuzz is able to detect bugs and notify users, as well as
prevent old bugs from being uncovered."""

import os
import sys
import tempfile
import unittest
import unittest.mock

import cifuzz

os.environ['OSS_FUZZ_ROOT'] = os.path.dirname(
    os.path.dirname(os.path.abspath(__file__)))
#pylint: disable=wrong-import-position
#pylint: disable=import-error
sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)), 'actions',
                 'build_fuzzers'))
import build_fuzzers_entrypoint
sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)), 'actions',
                 'run_fuzzers'))
import run_fuzzers_entrypoint

EXAMPLE_PROJECT = 'example'
EXAMPLE_REPO = 'oss-fuzz'
GITHUB_REF = 'refs/pull/3415/merge'
GITHUB_EVENT_NAME = 'pull_request'


class GitHubActionsBuildUnitTest(unittest.TestCase):
  """Test the build_fuzzers_entrypoint module for CIFuzz."""

  def test_dry_run_true_build_fail(self):
    """Tests build failures when dry_run mode is on."""
    with tempfile.TemporaryDirectory() as tmp_dir:
      with unittest.mock.patch.object(cifuzz,
                                      'build_fuzzers',
                                      return_value=False):
        self.assertEqual(
            0,
            build_w_args('not-a-proj', EXAMPLE_REPO, 'pull_request', GITHUB_REF,
                         tmp_dir, 'True'))
        self.assertEqual(
            0,
            build_w_args('not-a-proj', EXAMPLE_REPO, 'push', GITHUB_REF,
                         tmp_dir, 'TRUE'))

  def test_dry_run_false_build_fail(self):
    """Tests build failures when dry_run mode is off."""
    with tempfile.TemporaryDirectory() as tmp_dir:
      with unittest.mock.patch.object(cifuzz,
                                      'build_fuzzers',
                                      return_value=False):
        self.assertEqual(
            1,
            build_w_args('not-a-proj', EXAMPLE_REPO, 'pull_request', GITHUB_REF,
                         tmp_dir, 'False'))
        self.assertEqual(
            1,
            build_w_args('not-a-proj', EXAMPLE_REPO, 'push', GITHUB_REF,
                         tmp_dir, 'false'))

  def test_dry_run_false_build_success(self):
    """Build success when dry run mode is off."""
    with tempfile.TemporaryDirectory() as tmp_dir:
      with unittest.mock.patch.object(
          cifuzz, 'build_fuzzers',
          return_value=True), unittest.mock.patch.object(cifuzz,
                                                         'check_fuzzer_build',
                                                         return_value=True):
        self.assertEqual(
            0,
            build_w_args('not-a-proj', EXAMPLE_REPO, 'pull_request', GITHUB_REF,
                         tmp_dir, 'False'))
        self.assertEqual(
            0,
            build_w_args('not-a-proj', EXAMPLE_REPO, 'push', GITHUB_REF,
                         tmp_dir, 'false'))

  def test_dry_run_true_build_success(self):
    """Build success when dry run mode is on."""
    with tempfile.TemporaryDirectory() as tmp_dir:
      with unittest.mock.patch.object(cifuzz,
                                      'build_fuzzers',
                                      return_value=True):
        self.assertEqual(
            0,
            build_w_args('not-a-proj', EXAMPLE_REPO, 'pull_request', GITHUB_REF,
                         tmp_dir, 'True'))
        self.assertEqual(
            0,
            build_w_args('not-a-proj', EXAMPLE_REPO, 'push', GITHUB_REF,
                         tmp_dir, 'TRUE'))

  def test_build_check(self):
    """Checks that check fuzzers will fail on a bad build check."""
    with tempfile.TemporaryDirectory() as tmp_dir, unittest.mock.patch.object(
        cifuzz, 'build_fuzzers', return_value=True):
      with unittest.mock.patch.object(cifuzz,
                                      'check_fuzzer_build',
                                      side_effect=[True, False, False]):
        self.assertEqual(
            0,
            build_w_args(EXAMPLE_PROJECT, EXAMPLE_REPO, 'pull_request',
                         GITHUB_REF, tmp_dir, 'false'))
        self.assertEqual(
            0,
            build_w_args(EXAMPLE_PROJECT, EXAMPLE_REPO, 'pull_request',
                         GITHUB_REF, tmp_dir, 'true'))
        self.assertEqual(
            1,
            build_w_args(EXAMPLE_PROJECT, EXAMPLE_REPO, 'pull_request',
                         GITHUB_REF, tmp_dir, 'false'))


#pylint: disable=too-many-arguments
def build_w_args(project_name, repo_name, event_name, ref, workspace, dry_run):
  """Tests an actions build with the specified arguments.

  Args:
    project_name: The name of OSS-Fuzz project.
    repo_name: The name of the GitHub repo associated with the project.
    event_name: either 'pull_request' or 'push'.
    ref: The GitHub reference to be checked out.
    workspace: The location to store data for this run.
    dry_run: If errors should be reported or not.

  Returns:
    The return code of the actions run.
  """
  actions_args = dict()
  actions_args['OSS_FUZZ_PROJECT_NAME'] = project_name
  actions_args['GITHUB_REPOSITORY'] = repo_name
  actions_args['GITHUB_EVENT_NAME'] = event_name
  actions_args['GITHUB_REF'] = ref
  actions_args['OSS_FUZZ_ROOT'] = os.path.dirname(
      os.path.dirname(os.path.abspath(__file__)))
  actions_args['GITHUB_WORKSPACE'] = workspace
  actions_args['DRY_RUN'] = dry_run
  with unittest.mock.patch.dict(os.environ, actions_args):
    return build_fuzzers_entrypoint.main()


class GitHubActionsRunUnitTest(unittest.TestCase):
  """Test the run_fuzzers_entrypoint module for CIFuzz."""

  def test_run_fuzzers_dry_run(self):
    """Tess the run fuzzers function with dry_run on."""
    with tempfile.TemporaryDirectory() as tmp_dir:
      with unittest.mock.patch.object(cifuzz,
                                      'run_fuzzers',
                                      return_value=[True, True]):
        self.assertEqual(0, run_w_args('project', 10, tmp_dir, 'True'))
      with unittest.mock.patch.object(cifuzz,
                                      'run_fuzzers',
                                      return_value=[False, True]):
        self.assertEqual(0, run_w_args('project', 10, tmp_dir, 'true'))
      with unittest.mock.patch.object(cifuzz,
                                      'run_fuzzers',
                                      return_value=[True, False]):
        self.assertEqual(0, run_w_args('project', 10, tmp_dir, 'trUe'))
      with unittest.mock.patch.object(cifuzz,
                                      'run_fuzzers',
                                      return_value=[False, False]):
        self.assertEqual(0, run_w_args('project', 10, tmp_dir, 'TRUE'))

  def test_run_fuzzers_dry_run_off(self):
    """Tess the run fuzzers function with dry_run off."""
    with tempfile.TemporaryDirectory() as tmp_dir:
      with unittest.mock.patch.object(cifuzz,
                                      'run_fuzzers',
                                      return_value=[True, True]):
        self.assertEqual(2, run_w_args('project', 10, tmp_dir, 'FALSE'))
      with unittest.mock.patch.object(cifuzz,
                                      'run_fuzzers',
                                      return_value=[False, True]):
        self.assertEqual(1, run_w_args('project', 10, tmp_dir, 'False'))
      with unittest.mock.patch.object(cifuzz,
                                      'run_fuzzers',
                                      return_value=[True, False]):
        self.assertEqual(0, run_w_args('project', 10, tmp_dir, 'false'))
      with unittest.mock.patch.object(cifuzz,
                                      'run_fuzzers',
                                      return_value=[False, False]):
        self.assertEqual(1, run_w_args('project', 10, tmp_dir, 'falSE'))


def run_w_args(project_name, fuzz_seconds, workspace, dry_run):
  """Tests an actions run with the specified arguments.

  Args:
    project_name: The name of OSS-Fuzz project.
    fuzz_seconds: The length of time in seconds to be fuzzed.
    workspace: The location to store data for this run.
    dry_run: If errors should be reported or not.

  Returns:
    The return code of the actions run.
  """
  actions_args = dict()
  actions_args['OSS_FUZZ_PROJECT_NAME'] = project_name
  actions_args['FUZZ_SECONDS'] = str(fuzz_seconds)
  actions_args['OSS_FUZZ_ROOT'] = os.path.dirname(
      os.path.dirname(os.path.abspath(__file__)))
  actions_args['GITHUB_WORKSPACE'] = workspace
  actions_args['DRY_RUN'] = dry_run
  with unittest.mock.patch.dict(os.environ, actions_args):
    return run_fuzzers_entrypoint.main()


if __name__ == '__main__':
  unittest.main()
