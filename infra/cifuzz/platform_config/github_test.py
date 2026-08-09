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
"""Tests for platform_config.github."""
import os
import unittest
from unittest import mock

import platform_config.github
import test_helpers

# pylint: disable=arguments-differ


class GetProjectRepoOwnerAndNameTest(unittest.TestCase):
  """Tests for get_project_repo_owner and get_project_repo_name."""

  @mock.patch('platform_config.github._get_event_data', return_value={})
  def setUp(self, _):
    test_helpers.patch_environ(self)
    self.repo_owner = 'repo-owner'
    self.repo_name = 'repo-name'
    os.environ['GITHUB_REPOSITORY'] = f'{self.repo_owner}/{self.repo_name}'
    self.platform_conf = platform_config.github.PlatformConfig()

  def test_github_repository_owner(self):
    """Tests that the correct result is returned when repository contains the
    owner and repo name (as it does on GitHub)."""
    self.assertEqual(self.platform_conf.project_repo_owner, self.repo_owner)

  def test_github_repository_name(self):
    """Tests that the correct result is returned when repository contains the
    owner and repo name (as it does on GitHub)."""
    os.environ['GITHUB_REPOSITORY'] = f'{self.repo_owner}/{self.repo_name}'
    self.assertEqual(self.platform_conf.project_repo_name, self.repo_name)


class ProjectSrcPathTest(unittest.TestCase):
  """Tests for project_src_path."""

  def setUp(self):
    test_helpers.patch_environ(self)
    self.workspace = '/workspace'
    os.environ['GITHUB_WORKSPACE'] = self.workspace
    self.project_src_dir_name = 'project-src'

  @mock.patch('platform_config.github._get_event_data', return_value={})
  def test_github_unset(self, _):
    """Tests that project_src_path returns None when no PROJECT_SRC_PATH is
    set."""
    github_env = platform_config.github.PlatformConfig()
    self.assertIsNone(github_env.project_src_path)

  @mock.patch('platform_config.github._get_event_data', return_value={})
  def test_github(self, _):
    """Tests that project_src_path returns the correct result on GitHub."""
    os.environ['PROJECT_SRC_PATH'] = self.project_src_dir_name
    expected_project_src_path = os.path.join(self.workspace,
                                             self.project_src_dir_name)
    github_env = platform_config.github.PlatformConfig()
    self.assertEqual(github_env.project_src_path, expected_project_src_path)


class GetGitUrlTest(unittest.TestCase):
  """Tests for GenericPlatformConfig.git_url."""

  @mock.patch('platform_config.github._get_event_data', return_value={})
  def setUp(self, _):
    test_helpers.patch_environ(self)
    self.platform_conf = platform_config.github.PlatformConfig()

  def test_repository(self):
    """Tests that the correct result is returned when repository contains the
    owner and repo name (as it does on GitHub)."""
    os.environ['GITHUB_REPOSITORY'] = 'repo/owner'
    self.assertEqual('https://github.com/repo/owner',
                     self.platform_conf.git_url)
