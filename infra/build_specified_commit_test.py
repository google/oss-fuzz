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
"""Test the functionality of the build image from state module.
NOTE: THIS TEST NEEDS TO BE RUN FROM THE OSS-FUZZ BASE DIR
The will consist of the following functional tests
  1. The inferance of the main repo for a specific project
"""
import unittest
import os
import tempfile
import shutil

import build_specified_commit
import helper


class BuildImageUnitTests(unittest.TestCase):
  """Class to test the functionality of the build image from state module."""

  def test_infer_main_repo(self):
    """Tests that the main repo can be infered based on an example commit."""
    infered_repo = build_specified_commit.infer_main_repo(
        'curl', TMP_DIR, 'bc5d22c3dede2f04870c37aec9a50474c4b888ad')
    self.assertEqual(infered_repo, 'https://github.com/curl/curl.git')
    infered_repo = build_specified_commit.infer_main_repo('curl', TMP_DIR)
    self.assertEqual(infered_repo, 'https://github.com/curl/curl.git')

    infered_repo = build_specified_commit.infer_main_repo('usrsctp', TMP_DIR)
    self.assertEqual(infered_repo, 'https://github.com/weinrank/usrsctp')
    infered_repo = build_specified_commit.infer_main_repo(
        'usrsctp', TMP_DIR, '4886aaa49fb90e479226fcfc3241d74208908232')
    self.assertEqual(infered_repo, 'https://github.com/weinrank/usrsctp',
                     '4886aaa49fb90e479226fcfc3241d74208908232')

    infered_repo = build_specified_commit.infer_main_repo(
        'not_a_project', TMP_DIR)
    self.assertEqual(infered_repo, None)


class BuildImageIntegrationTests(unittest.TestCase):
  """Testing if an image can be built from different states e.g. a commit"""

  def test_build_fuzzers_from_commit(self):
    """Tests if the fuzzers can build at a proper commit.

    This is done by using a known regression range for a specific test case.
    The old commit should show the error when its fuzzers run and the new one
    should not.
    """
    project_name = 'yara'
    old_commit = 'f79be4f2330f4b89ea2f42e1c44ca998c59a0c0f'
    new_commit = 'f50a39051ea8c7f10d6d8db9656658b49601caef'
    fuzzer = 'rules_fuzzer'
    test_data = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'testcases', 'yara_test_data')
    build_specified_commit.build_fuzzer_from_commit(
        project_name, old_commit, TMP_DIR, sanitizer='address')
    old_error_code = helper.reproduce_impl(project_name, fuzzer, False, [], [],
                                           test_data)
    build_specified_commit.build_fuzzer_from_commit(
        project_name, new_commit, TMP_DIR, sanitizer='address')
    new_error_code = helper.reproduce_impl(project_name, fuzzer, False, [], [],
                                           test_data)
    self.assertNotEqual(new_error_code, old_error_code)


if __name__ == '__main__':
  if os.getcwd() != os.path.dirname(os.path.dirname(os.path.realpath(__file__))):
    print("Error: this script needs to be run from the OSS-Fuzz home directory")
  else:
    TMP_DIR = tempfile.mkdtemp()
    unittest.main()
    shutil.rmtree(TMP_DIR)
