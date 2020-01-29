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
  1. Determine if a OSS-Fuzz projects main repo can be accurately deduce
  from example commits.
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
# pylint: enable=wrong-import-position


class DetectRepoTest(unittest.TestCase):
  """Class to test the functionality of the detect_repo module."""

  def test_infer_main_repo(self):
    """Tests that the main repo can be inferred based on an example commit."""

    with tempfile.TemporaryDirectory() as tmp_dir:

      # Construct example repo's to check for commits.
      repo_manager.RepoManager('https://github.com/curl/curl.git', tmp_dir)
      repo_manager.RepoManager('https://github.com/weinrank/usrsctp', tmp_dir)
      repo_manager.RepoManager('https://github.com/ntop/nDPI.git', tmp_dir)
      repo_manager.RepoManager('https://github.com/libarchive/libarchive.git',
                               tmp_dir)

      self.check_commit_with_repo('https://github.com/curl/curl.git', 'curl',
                                  'bc5d22c3dede2f04870c37aec9a50474c4b888ad',
                                  tmp_dir)

      self.check_commit_with_repo('https://github.com/weinrank/usrsctp',
                                  'usrsctp',
                                  '4886aaa49fb90e479226fcfc3241d74208908232',
                                  tmp_dir)
      self.check_commit_with_repo('https://github.com/ntop/nDPI.git', 'nDPI',
                                  'c4d476cc583a2ef1e9814134efa4fbf484564ed7',
                                  tmp_dir)
      self.check_commit_with_repo(
          'https://github.com/libarchive/libarchive.git', 'libarchive',
          '458e49358f17ec58d65ab1c45cf299baaf3c98d1', tmp_dir)
      self.check_commit_with_repo(None, None,
                                  'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', tmp_dir)

  def test_infer_main_repo_from_name(self):
    """Tests that the main project repo can be inferred from a repo name."""

    with tempfile.TemporaryDirectory() as tmp_dir:
      # Construct example repos to check for name.
      repo_manager.RepoManager('https://github.com/curl/curl.git', tmp_dir)
      repo_manager.RepoManager('https://github.com/ntop/nDPI.git', tmp_dir)
      repo_manager.RepoManager('https://github.com/libarchive/libarchive.git',
                               tmp_dir)
      self.check_ref_with_repo('https://github.com/curl/curl.git', 'curl',
                               tmp_dir)
      self.check_ref_with_repo('https://github.com/ntop/nDPI.git', 'nDPI',
                               tmp_dir)
      self.check_ref_with_repo('https://github.com/libarchive/libarchive.git',
                               'libarchive', tmp_dir)

  def check_ref_with_repo(self, repo_origin, repo_name, tmp_dir):
    """Checks the detect repo's main method for a specific set of inputs.

      Args:
        repo_origin: URL of the git repo.
        repo_name: The name of the directory it is cloned to.
        tmp_dir: The location of the directory of git repos to be searched.
      """
    command = [
        'python3', 'detect_repo.py', '--src_dir', tmp_dir, '--repo_name',
        repo_name
    ]
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

  def check_commit_with_repo(self, repo_origin, repo_name, commit, tmp_dir):
    """Checks the detect repos main method for a specific set of inputs.

    Args:
      repo_origin: URL of the git repo.
      repo_name: The name of the directory it is cloned to.
      commit: The commit that should be used to look up the repo.
      tmp_dir: The location of the directory of git repos to be searched.
    """
    command = [
        'python3', 'detect_repo.py', '--src_dir', tmp_dir, '--example_commit',
        commit
    ]
    out, _ = detect_repo.execute(command,
                                 location=os.path.dirname(
                                     os.path.abspath(__file__)))
    match = re.search(r'\bDetected repo: ([^ ]+) ([^ ]+)', out.rstrip())
    if match and match.group(1) and match.group(2):
      self.assertEqual(match.group(1), repo_origin)
      self.assertEqual(match.group(2), os.path.join(tmp_dir, repo_name))
    else:
      self.assertIsNone(repo_origin)
      self.assertIsNone(repo_name)


if __name__ == '__main__':
  unittest.main()
