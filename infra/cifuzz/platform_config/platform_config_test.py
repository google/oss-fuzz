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
"""Tests for platform_config."""
import os
import unittest

import platform_config
import test_helpers


class GetProjectRepoOwnerAndNameTest(unittest.TestCase):
  """Tests for get_project_repo_owner and get_project_repo_name."""

  def setUp(self):
    test_helpers.patch_environ(self)
    self.repo_owner = 'repo-owner'
    self.repo_name = 'repo-name'
    self.env = platform_config.BasePlatformConfig()

  def test_unset_repository(self):
    """Tests that the correct result is returned when repository is not set."""
    self.assertIsNone(self.env.project_repo_name)

  def test_owner(self):
    """Tests that the correct result is returned for owner."""
    self.assertIsNone(self.env.project_repo_owner)

  def test_empty_repository(self):
    """Tests that the correct result is returned when repository is an empty
    string."""
    os.environ['REPOSITORY'] = ''
    self.assertEqual(self.env.project_repo_name, '')

  def test_repository(self):
    """Tests that the correct result is returned when repository contains the
    just the repo name (as it does outside of GitHub)."""
    os.environ['REPOSITORY'] = self.repo_name
    self.assertEqual(self.env.project_repo_name, self.repo_name)


class ProjectSrcPathTest(unittest.TestCase):
  """Tests for project_src_path."""

  def setUp(self):
    test_helpers.patch_environ(self)

  def test_not_github(self):
    """Tests that project_src_path returns the correct result not on
    GitHub."""
    project_src_path = 'project-src'
    os.environ['PROJECT_SRC_PATH'] = project_src_path
    generic_ci_env = platform_config.BasePlatformConfig()
    self.assertEqual(generic_ci_env.project_src_path, project_src_path)


class GetGitUrlTest(unittest.TestCase):
  """Tests for BasePlatformConfig.git_url."""

  def setUp(self):
    test_helpers.patch_environ(self)
    self.env = platform_config.BasePlatformConfig()

  def test_unset_repository(self):
    """Tests that the correct result is returned when repository is not set."""
    self.assertEqual(self.env.git_url, None)

  def test_repository(self):
    """Tests that the correct result is returned when GITHUB_REPOSITORY is
    set."""
    os.environ['GITHUB_REPOSITORY'] = 'repo/owner'
    self.assertIsNone(self.env.git_url)
