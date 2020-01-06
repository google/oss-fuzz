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
# See the License for the specific language governing perepo_managerissions and
# limitations under the License.
"""Test the functionality of bisection module.
1) Test a known case where an error appears in a regression range
2) Bisect can handle incorrect inputs
"""

import os
import unittest

import bisector

# Necessary because __file__ changes with os.chdir
TEST_DIR_PATH = os.path.dirname(os.path.realpath(__file__))


class TestBisect(unittest.TestCase):
  """Class to test the functionality of bisection method"""

  def test_bisect_invalid_repo(self):
    """Test the bisection method on a project that does not exist"""
    build_data = bisector.BuildData('not-a-real-repo', 'libfuzzer', 'address',
                                    'x86_64')
    commit_old = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
    commit_new = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
    testcase = os.path.join(TEST_DIR_PATH, 'testcases', 'usrsctp_test_data')
    fuzz_target = 'fuzzer_connect'
    with self.assertRaises(ValueError):
      bisector.bisect(commit_old, commit_new, testcase, fuzz_target, build_data)

  def test_bisect_curl(self):
    """Test the bisect method on the curl project."""
    build_data = bisector.BuildData('curl', 'libfuzzer', 'address', 'x86_64')
    commit_new = 'dda418266c99ceab368d723facb52069cbb9c8d5'
    commit_old = 'df26f5f9c36e19cd503c0e462e9f72ad37b84c82'
    fuzz_target = 'curl_fuzzer_ftp'
    testcase = os.path.join(TEST_DIR_PATH, 'testcases', 'curl_test_data')
    error_sha = bisector.bisect(commit_old, commit_new, testcase, fuzz_target,
                                build_data)
    self.assertEqual(error_sha, 'df26f5f9c36e19cd503c0e462e9f72ad37b84c82')

  def test_bisect_libarchive(self):
    """Test the bisect method on libarchive."""
    build_data = bisector.BuildData('libarchive', 'libfuzzer', 'undefined',
                                    'x86_64')
    commit_new = '458e49358f17ec58d65ab1c45cf299baaf3c98d1'
    commit_old = '5bd2a9b6658a3a6efa20bb9ad75bd39a44d71da6'
    fuzz_target = 'libarchive_fuzzer'
    testcase = os.path.join(TEST_DIR_PATH, 'testcases', 'libarchive_test_data')
    error_sha = bisector.bisect(commit_old, commit_new, testcase, fuzz_target,
                                build_data)
    self.assertEqual(error_sha, '840266712006de5e737f8052db920dfea2be4260')

  def test_bisect_usrsctp(self):
    """Test the bisect method on the usrsctp."""
    build_data = bisector.BuildData('usrsctp', 'libfuzzer', 'address', 'x86_64')
    commit_old = '4886aaa49fb90e479226fcfc3241d74208908232'
    commit_new = 'c710749b1053978179a027973a3ea3bccf20ee5c'
    testcase = os.path.join(TEST_DIR_PATH, 'testcases', 'usrsctp_test_data')
    fuzz_target = 'fuzzer_connect'
    error_sha = bisector.bisect(commit_old, commit_new, testcase, fuzz_target,
                                build_data)
    self.assertEqual(error_sha, '457d6ead58e82584d9dcb826f6739347f59ebd3a')

  def test_bisect_usrsctp_single_error_exists(self):
    """Tests what happens with a single with an error."""
    build_data = bisector.BuildData('usrsctp', 'libfuzzer', 'address', 'x86_64')
    commit_old = 'c710749b1053978179a027973a3ea3bccf20ee5c'
    commit_new = 'c710749b1053978179a027973a3ea3bccf20ee5c'
    testcase = os.path.join(TEST_DIR_PATH, 'testcases', 'usrsctp_test_data')
    fuzz_target = 'fuzzer_connect'
    error_sha = bisector.bisect(commit_old, commit_new, testcase, fuzz_target,
                                build_data)
    self.assertEqual(error_sha, 'c710749b1053978179a027973a3ea3bccf20ee5c')

  def test_bisect_usrsctp_single_no_error_exists(self):
    """Tests what happens with a single with an error."""
    build_data = bisector.BuildData('usrsctp', 'libfuzzer', 'address', 'x86_64')
    commit_old = '4886aaa49fb90e479226fcfc3241d74208908232'
    commit_new = '4886aaa49fb90e479226fcfc3241d74208908232'
    testcase = os.path.join(TEST_DIR_PATH, 'testcases', 'usrsctp_test_data')
    fuzz_target = 'fuzzer_connect'
    error_sha = bisector.bisect(commit_old, commit_new, testcase, fuzz_target,
                                build_data)
    self.assertEqual(error_sha, '4886aaa49fb90e479226fcfc3241d74208908232')


if __name__ == '__main__':
  # Change to oss-fuzz main directory so helper.py runs correctly.
  if os.getcwd() != os.path.dirname(TEST_DIR_PATH):
    os.chdir(os.path.dirname(TEST_DIR_PATH))
  unittest.main()
