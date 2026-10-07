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
import unittest
from unittest import mock

import continuous_integration
import docker

# pylint: disable=wrong-import-position,import-error
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import repo_manager

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
