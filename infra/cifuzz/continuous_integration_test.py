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
"""Tests for continuous_integration_module."""
import os
import sys
import tempfile
import unittest
from unittest import mock

import continuous_integration
import docker

# pylint: disable=wrong-import-position,import-error
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import repo_manager
import test_helpers

# pylint: disable=no-self-use


class FixGitRepoForDiffTest(unittest.TestCase):
  """Tests for fix_git_repo_for_diff."""

  @mock.patch('utils.execute')
  def test_fix_git_repo_for_diff(self, mock_execute):
    """Tests that fix_git_repo_for_diff works as intended."""
    repo_dir = '/dir'
    repo_manager_obj = repo_manager.RepoManager(repo_dir)
    continuous_integration.fix_git_repo_for_diff(repo_manager_obj)
    expected_command = [
        'git', 'symbolic-ref', 'refs/remotes/origin/HEAD',
        'refs/remotes/origin/master'
    ]

    mock_execute.assert_called_with(expected_command, location=repo_dir)


class GetBuildCommand(unittest.TestCase):
  """Tests for get_build_command."""

  def test_build_command(self):
    """Tests that get_build_command works as intended."""
    self.assertEqual(continuous_integration.get_build_command(), 'compile')


class CheckoutSpecifiedCommitTest(unittest.TestCase):
  """Tests that a failed checkout cannot be treated as a successful build."""

  def test_pr_checkout_failure(self):
    """A missing PR ref fails checkout."""
    manager = mock.Mock()
    manager.checkout_pr.side_effect = RuntimeError('Missing PR ref')

    self.assertFalse(
        continuous_integration.checkout_specified_commit(
            manager, 'refs/pull/1/merge', None))
    manager.checkout_pr.assert_called_once_with('refs/pull/1/merge')
    manager.checkout_commit.assert_not_called()

  def test_commit_checkout_failure(self):
    """A missing commit fails checkout."""
    manager = mock.Mock()
    manager.checkout_commit.side_effect = ValueError('Missing commit')

    self.assertFalse(
        continuous_integration.checkout_specified_commit(
            manager, None, 'deadbeef'))
    manager.checkout_commit.assert_called_once_with('deadbeef')

  def test_successful_checkout(self):
    """A successful checkout reports success."""
    manager = mock.Mock()

    self.assertTrue(
        continuous_integration.checkout_specified_commit(
            manager, 'refs/pull/1/merge', None))


class GithubCheckoutFailureTest(unittest.TestCase):
  """Tests that both GitHub CI paths report checkout failures."""

  @mock.patch('build_specified_commit.detect_main_repo',
              return_value=('example.com', '/src/example'))
  @mock.patch.object(continuous_integration.InternalGithub,
                     '_copy_repo_from_image')
  @mock.patch.object(continuous_integration.InternalGithub,
                     '_checkout_specified_commit',
                     return_value=False)
  def test_internal_github_build_preparation_fails(self, _, __, ___):
    """Internal GitHub builds stop when checkout fails."""
    with tempfile.TemporaryDirectory() as tmp_dir:
      config = test_helpers.create_build_config(oss_fuzz_project_name='example',
                                                project_repo_name='example',
                                                workspace=tmp_dir,
                                                pr_ref='refs/pull/1/merge',
                                                cfl_platform='github')
      ci = continuous_integration.InternalGithub(config)

      self.assertFalse(ci.prepare_for_fuzzer_build().success)

  @mock.patch('repo_manager.clone_repo_and_get_manager')
  @mock.patch.object(continuous_integration.ExternalGithub,
                     '_checkout_specified_commit',
                     return_value=False)
  def test_external_github_build_preparation_fails(self, _, mock_clone):
    """External GitHub builds stop when checkout fails."""
    with tempfile.TemporaryDirectory() as tmp_dir:
      config = test_helpers.create_build_config(
          project_repo_name='example',
          workspace=tmp_dir,
          git_url='https://example.com/repo',
          pr_ref='refs/pull/1/merge',
          cfl_platform='github')
      ci = continuous_integration.ExternalGithub(config)

      self.assertFalse(ci.prepare_for_fuzzer_build().success)
      mock_clone.assert_called_once()


class GetReplaceRepoAndBuildCommand(unittest.TestCase):
  """Tests for get_replace_repo_and_build_command."""

  def test_get_replace_repo_and_build_command(self):
    """Tests that get_replace_repo_and_build_command works as intended."""
    host_repo_path = '/path/on/host/to/repo'
    image_repo_path = '/src/repo'
    command = continuous_integration.get_replace_repo_and_build_command(
        host_repo_path, image_repo_path)
    expected_command = ('cd / && rm -rf /src/repo/* && '
                        'cp -r /path/on/host/to/repo /src && cd - '
                        '&& compile')
    self.assertEqual(command, expected_command)


class BuildExternalProjetDockerImage(unittest.TestCase):
  """Tests for build_external_project_docker_image."""

  @mock.patch('helper.docker_build')
  def test_build_external_project_docker_image(self, mock_docker_build):
    """Tests that build_external_project_docker_image works as intended."""
    build_integration_path = '.clusterfuzzlite'
    project_src = '/path/to/project/src'
    continuous_integration.build_external_project_docker_image(
        project_src, build_integration_path)

    mock_docker_build.assert_called_with([
        '-t', docker.EXTERNAL_PROJECT_IMAGE, '-f',
        os.path.join('.clusterfuzzlite', 'Dockerfile'), project_src
    ])


# TODO(metzman): Write tests for the rest of continuous_integration.py.
