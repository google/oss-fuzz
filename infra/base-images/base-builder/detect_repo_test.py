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
import collections
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

ExampleRepo = collections.namedtuple('ExampleRepo',
                                     ['project_name', 'git_url', 'commit_sha'])


class DetectRepoTest(unittest.TestCase):
  """Class to test the functionality of the detect_repo module."""

  # WARNING: These tests  are dependent upon the following repos existing and
  # the specified commits existing.
  example_repos = [
      ExampleRepo(project_name='curl',
                  git_url='https://github.com/curl/curl.git',
                  commit_sha='bc5d22c3dede2f04870c37aec9a50474c4b888ad'),
      ExampleRepo(project_name='usrsctp',
                  git_url='https://github.com/weinrank/usrsctp',
                  commit_sha='4886aaa49fb90e479226fcfc3241d74208908232'),
      ExampleRepo(project_name='nDPI',
                  git_url='https://github.com/ntop/nDPI.git',
                  commit_sha='c4d476cc583a2ef1e9814134efa4fbf484564ed7'),
      ExampleRepo(project_name='libarchive',
                  git_url='https://github.com/libarchive/libarchive.git',
                  commit_sha='458e49358f17ec58d65ab1c45cf299baaf3c98d1')
  ]

  def test_infer_main_repo_from_commit(self):
    """Tests that the main repo can be inferred based on an example commit."""

    with tempfile.TemporaryDirectory() as tmp_dir:
      # Construct example repo's to check for commits.
      for example_repo in self.example_repos:
        repo_manager.RepoManager(example_repo.git_url, tmp_dir)
        self.check_with_repo(example_repo.git_url,
                             example_repo.project_name,
                             tmp_dir,
                             commit=example_repo.commit_sha)

  def test_infer_main_repo_from_name(self):
    """Tests that the main project repo can be inferred from a repo name."""

    with tempfile.TemporaryDirectory() as tmp_dir:
      for example_repo in self.example_repos:
        repo_manager.RepoManager(example_repo.git_url, tmp_dir)
        self.check_with_repo(example_repo.git_url, example_repo.project_name,
                             tmp_dir)

<<<<<<< HEAD
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
=======
  def check_with_repo(self, repo_origin, repo_name, tmp_dir, commit=None):
    """Checks the detect repo's main method for a specific set of inputs.
>>>>>>> Updated detect_repo_tests

    Args:
      repo_origin: URL of the git repo.
      repo_name: The name of the directory it is cloned to.
      tmp_dir: The location of the directory of git repos to be searched.
      commit: The commit that should be used to look up the repo.
    """
    command = ['python3', 'detect_repo.py', '--src_dir', tmp_dir]

    if not commit:
      command += ['--repo_name', repo_name]
    else:
      command += ['--example_commit', commit]

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
