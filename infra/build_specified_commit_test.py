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
import argparse
import unittest

from build_specified_commit import infer_main_repo
from build_specified_commit import build_fuzzer_from_commit
from helper import reproduce


class BuildImageUnitTests(unittest.TestCase):
  """Class to test the functionality of the build image from state module."""

  def test_infer_main_repo(self):
    """Tests that the main repo can be infered based on an example commit."""
    infered_repo = infer_main_repo('curl', 'tmp',
                                   'bc5d22c3dede2f04870c37aec9a50474c4b888ad')
    self.assertEqual(infered_repo, 'https://github.com/curl/curl.git')
    infered_repo = infer_main_repo('curl', 'tmp')
    self.assertEqual(infered_repo, 'https://github.com/curl/curl.git')

    infered_repo = infer_main_repo('usrsctp', 'tmp')
    self.assertEqual(infered_repo, 'https://github.com/weinrank/usrsctp')
    infered_repo = infer_main_repo('usrsctp', 'tmp',
                                   '4886aaa49fb90e479226fcfc3241d74208908232')
    self.assertEqual(infered_repo, 'https://github.com/weinrank/usrsctp',
                     '4886aaa49fb90e479226fcfc3241d74208908232')

    infered_repo = infer_main_repo('not_a_project', 'tmp')
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
    test_data = 'infra/yara_test_data'
    build_fuzzer_from_commit(
        project_name,
        old_commit,
        '/usr/local/google/home/lneat/Documents/oss-fuzz/infra/tmp',
        sanitizer='address')
    old_error_code = self.reproduce_error(project_name, test_data, fuzzer)
    build_fuzzer_from_commit(
        project_name,
        new_commit,
        '/usr/local/google/home/lneat/Documents/oss-fuzz/infra/tmp',
        sanitizer='address')
    new_error_code = self.reproduce_error(project_name, test_data, fuzzer)
    self.assertNotEqual(new_error_code, old_error_code)

  def reproduce_error(self, project_name, test_case, fuzzer_name):
    """Checks to see if the error is repoduceable at a specific commit.
    Args:
      project_name: The name of the project you are testing
      test_case: The path to the test_case you are passing in
      fuzzer_name: The name of the fuzz target to be tested
    Returns:
      True if the error still exists
    """
    parser = argparse.ArgumentParser()
    parser.add_argument('project_name', help='name of the project')
    parser.add_argument('fuzzer_name', help='name of the fuzzer')
    parser.add_argument('testcase_path', help='path of local testcase')
    parser.add_argument(
        'fuzzer_args',
        help='arguments to pass to the fuzzer',
        nargs=argparse.REMAINDER)
    parser.add_argument(
        '--valgrind', action='store_true', help='run with valgrind')
    parser.add_argument(
        '-e', action='append', help='set environment variable e.g. VAR=value')
    args = parser.parse_args([project_name, fuzzer_name, test_case])
    return reproduce(args)


if __name__ == '__main__':
  unittest.main()
