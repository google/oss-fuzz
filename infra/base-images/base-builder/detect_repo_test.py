# Copyright 2019 Google LLC
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
"""Test the functionality of the detect_repo module.
This will consist of the following functional test:
  1. Determine if an OSS-Fuzz projects main repo can be detected from example
  commits.
  2. Determine if an OSS-Fuzz project main repo can be detected from a
  repo name.
"""
import os
import re
import sys
import tempfile
import unittest

import detect_repo

# Appending to path for access to repo_manager module.
# pylint: disable=wrong-import-position
sys.path.append(
    os.path.dirname(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__)))))
import repo_manager
import test_repos
# pylint: enable=wrong-import-position


@unittest.skipIf(not os.getenv('INTEGRATION_TESTS'),
                 'INTEGRATION_TESTS=1 not set')
class DetectRepoIntegrationTest(unittest.TestCase):
  """Class to test the functionality of the detect_repo module."""

  def test_infer_main_repo_from_commit(self):
    """Tests that the main repo can be inferred based on an example commit."""

    with tempfile.TemporaryDirectory() as tmp_dir:
      # Construct example repo's to check for commits.
      for test_repo in test_repos.TEST_REPOS:
        repo_manager.clone_repo_and_get_manager(test_repo.git_url, tmp_dir)
        self.check_with_repo(test_repo.git_url,
                             test_repo.git_repo_name,
                             tmp_dir,
                             commit=test_repo.old_commit)

  def test_infer_main_repo_from_name(self):
    """Tests that the main project repo can be inferred from a repo name."""
    with tempfile.TemporaryDirectory() as tmp_dir:
      for test_repo in test_repos.TEST_REPOS:
        repo_manager.clone_repo_and_get_manager(test_repo.git_url, tmp_dir)
        self.check_with_repo(test_repo.git_url, test_repo.git_repo_name,
                             tmp_dir)

  def check_with_repo(self, repo_origin, repo_name, tmp_dir, commit=None):
    """Checks the detect repo's main method for a specific set of inputs.

    Args:
      repo_origin: URL of the git repo.
      repo_name: The name of the directory it is cloned to.
      tmp_dir: The location of the directory of git repos to be searched.
      commit: The commit that should be used to look up the repo.
    """
    command = ['python3', 'detect_repo.py', '--src_dir', tmp_dir]

    if commit:
      command += ['--example_commit', commit]
    else:
      command += ['--repo_name', repo_name]

    out, _ = detect_repo.execute(command,
                                 location=os.path.dirname(
                                     os.path.realpath(__file__)))
    match = re.search(r'\bDetected repo: ([^ ]+) ([^ ]+)', out.rstrip())
    if match and match.group(1) and match.group(2):
      self.assertEqual(match.group(1), repo_origin)
      self.assertEqual(match.group(2), os.path.join(tmp_dir, repo_name))
    else:
      self.assertIsNone(repo_origin)
      self.assertIsNone(repo_name)


if __name__ == '__main__':
  unittest.main()
