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
The will consist of the following functional tests
  1. The inferance of the main repo for a specific project
"""

from build_image_from_state import infer_main_repo
from build_image_from_state import build_fuzzer_from_commit
from RepoManager import RepoManager
import unittest


class TestBuildFromState(unittest.TestCase):
  """Class to test the functionality of the build image from state  module."""

  def test_infer_main_repo(self):
    """Tests that the main repo can be infered based on an example commit."""
    infered_repo = infer_main_repo('curl', 'bc5d22c3dede2f04870c37aec9a50474c4b888ad')
    self.assertEqual(infered_repo, 'https://github.com/curl/curl.git')
    infered_repo = infer_main_repo('curl')
    self.assertEqual(infered_repo, 'https://github.com/curl/curl.git')

  def test_build_fuzzers_from_commit(self):
    build_fuzzer_from_commit('yara','4546fb2b588b385231495a123552b755ae4eba96',
                             'rules_fuzzer',
                             '/usr/local/google/home/lneat/Documents/oss-fuzz/infra/tmp')

if __name__ == '__main__':
  unittest.main()
