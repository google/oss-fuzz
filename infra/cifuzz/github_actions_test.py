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

os.environ['OSS_FUZZ_ROOT'] = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
#pylint: disable=wrong-import-position
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)),'actions', 'build_fuzzers'))
import build_fuzzers_entrypoint

EXAMPLE_PROJECT = 'example'
EXAMPLE_REPO = 'oss-fuzz'
GITHUB_REF = 'refs/pull/3415/merge'
GITHUB_EVENT_NAME = 'pull_request'

class GitHubActionsBuildIntegrationTest(unittest.TestCase):
  """Test is_reproducible function in the fuzz_target module."""

  def test_dry_run_true_build_fail(self):
    with tempfile.TemporaryDirectory() as tmp_dir:
      self.assertFalse(build_w_args('not-a-proj', EXAMPLE_REPO, 'pull_request', GITHUB_REF, tmp_dir, 'true'))
      self.assertFalse(build_w_args(EXAMPLE_PROJECT, 'not-a-repo', 'pull_request', GITHUB_REF, tmp_dir, 'True'))
      self.assertFalse(build_w_args(EXAMPLE_PROJECT, EXAMPLE_REPO, 'not-a-option', GITHUB_REF, tmp_dir, 'TRUE'))
      self.assertFalse(build_w_args(EXAMPLE_PROJECT, EXAMPLE_REPO, 'pull_request', GITHUB_REF, 'not/a/dir', 'truE'))

  def test_dry_run_false_build_fail(self):
    with tempfile.TemporaryDirectory() as tmp_dir:
      self.assertTrue(build_w_args('not-a-proj', EXAMPLE_REPO, 'pull_request', GITHUB_REF, tmp_dir, 'false'))
      self.assertTrue(build_w_args(EXAMPLE_PROJECT, 'not-a-repo', 'pull_request', GITHUB_REF, tmp_dir, 'False'))
      self.assertTrue(build_w_args(EXAMPLE_PROJECT, EXAMPLE_REPO, 'not-a-option', GITHUB_REF, tmp_dir, 'FALSE'))
      self.assertTrue(build_w_args(EXAMPLE_PROJECT, EXAMPLE_REPO, 'pull_request', GITHUB_REF, 'not/a/dir', 'fALse'))

  def test_build_success(self):
    with tempfile.TemporaryDirectory() as tmp_dir:
      self.assertFalse(build_w_args(EXAMPLE_PROJECT, EXAMPLE_REPO, 'pull_request', GITHUB_REF, tmp_dir, 'false'))

  def test_build_check(self):
    with tempfile.TemporaryDirectory() as tmp_dir:
      with unittest.mock.patch.object(cifuzz, 'check_fuzzer_build', side_effect=[True, False, False]):
        self.assertFalse(build_w_args(EXAMPLE_PROJECT, EXAMPLE_REPO, 'pull_request', GITHUB_REF, tmp_dir, 'false'))
        self.assertFalse(build_w_args(EXAMPLE_PROJECT, EXAMPLE_REPO, 'pull_request', GITHUB_REF, tmp_dir, 'true'))
        self.assertTrue(build_w_args(EXAMPLE_PROJECT, EXAMPLE_REPO, 'pull_request', GITHUB_REF, tmp_dir, 'false'))

def build_w_args(project, repo, event_name, ref, workspace, dry_run):
  """Tests an actions run with the specified arguments.

  Args:
    project: The name of OSS-Fuzz project.
    repo: The name of the GitHub repo associated with the project.
    event_name: either 'pull_request' or 'push'.
    ref: The GitHub reference to be checked out.
    workspace: The location to store data for this run.
    dry_run: If errors should be reported or not.

  Returns:
    The return code of the actions run.
  """
  actions_args = dict()
  actions_args['OSS_FUZZ_PROJECT_NAME'] = project
  actions_args['GITHUB_REPOSITORY'] = repo
  actions_args['GITHUB_EVENT_NAME'] = event_name
  actions_args['GITHUB_REF'] = ref
  actions_args['OSS_FUZZ_ROOT'] = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
  actions_args['GITHUB_WORKSPACE'] = workspace
  actions_args['DRY_RUN'] = dry_run
  with unittest.mock.patch.dict(os.environ, actions_args):
    return build_fuzzers_entrypoint.main()

if __name__ == '__main__':
    unittest.main()
