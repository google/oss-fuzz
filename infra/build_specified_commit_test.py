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
"""Test the functionality of the build image from commit module.
The will consist of the following functional tests
  1. The inferance of the main repo for a specific project
"""
import os
import tempfile
import unittest

import build_specified_commit
import helper

# Necessary because __file__ changes with os.chdir
TEST_DIR_PATH = os.path.dirname(os.path.realpath(__file__))


class BuildImageIntegrationTests(unittest.TestCase):
  """Testing if an image can be built from different states e.g. a commit"""

  def test_build_fuzzers_from_commit(self):
    """Tests if the fuzzers can build at a proper commit.

    This is done by using a known regression range for a specific test case.
    The old commit should show the error when its fuzzers run and the new one
    should not.
    """
    test_data = os.path.join(TEST_DIR_PATH, 'testcases', 'yara_test_data')

    with tempfile.TemporaryDirectory() as tmp_dir:
      project_name = 'yara'
      old_commit = 'f79be4f2330f4b89ea2f42e1c44ca998c59a0c0f'
      new_commit = 'f50a39051ea8c7f10d6d8db9656658b49601caef'
      fuzzer = 'rules_fuzzer'
      build_specified_commit.build_fuzzer_from_commit(
          project_name, old_commit, tmp_dir, sanitizer='address')
      old_error_code = helper.reproduce_impl(project_name, fuzzer, False, [],
                                             [], test_data)
      build_specified_commit.build_fuzzer_from_commit(
          project_name, new_commit, tmp_dir, sanitizer='address')
      new_error_code = helper.reproduce_impl(project_name, fuzzer, False, [],
                                             [], test_data)
      self.assertNotEqual(new_error_code, old_error_code)

  def test_detect_main_repo(self):
    """Test the detect main repo functionality of the build specific commit module."""
    repo_origin, repo_name = build_specified_commit.detect_main_repo_from_docker(
        'curl', 'bc5d22c3dede2f04870c37aec9a50474c4b888ad')
    self.assertEqual(repo_origin, 'https://github.com/curl/curl.git')
    self.assertEqual(repo_name, 'curl')

    repo_origin, repo_name = build_specified_commit.detect_main_repo_from_docker(
        'usrsctp', '4886aaa49fb90e479226fcfc3241d74208908232')
    self.assertEqual(repo_origin, 'https://github.com/weinrank/usrsctp')
    self.assertEqual(repo_name, 'usrsctp')

    repo_origin, repo_name = build_specified_commit.detect_main_repo_from_docker(
        'ndpi', 'c4d476cc583a2ef1e9814134efa4fbf484564ed7')
    self.assertEqual(repo_origin, 'https://github.com/ntop/nDPI.git')
    self.assertEqual(repo_name, 'ndpi')

    repo_origin, repo_name = build_specified_commit.detect_main_repo_from_docker(
        'notproj', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')
    self.assertIsNone(repo_origin)
    self.assertIsNone(repo_name)


if __name__ == '__main__':

  # Change to oss-fuzz main directory so helper.py runs correctly
  if os.getcwd() != os.path.dirname(TEST_DIR_PATH):
    os.chdir(os.path.dirname(TEST_DIR_PATH))
  unittest.main()
