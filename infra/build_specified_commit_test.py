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
The will consist of the following functional tests:
  1. The inference of the main repo for a specific project.
  2. The building of a projects fuzzers from a specific commit.

"""
import os
import tempfile
import unittest

import build_specified_commit
import helper
import repo_manager
import test_repos

# necessary because __file__ changes with os.chdir
TEST_DIR_PATH = os.path.dirname(os.path.realpath(__file__))


@unittest.skipIf(not os.getenv('INTEGRATION_TESTS'),
                 'INTEGRATION_TESTS=1 not set')
class BuildImageIntegrationTest(unittest.TestCase):
  """Tests if an image can be built from different states e.g. a commit."""

  @unittest.skip('Test is failing (spuriously?).')
  def test_build_fuzzers_from_commit(self):
    """Tests if the fuzzers can build at a specified commit.

    This is done by using a known regression range for a specific test case.
    The old commit should show the error when its fuzzers run and the new one
    should not.
    """
    with tempfile.TemporaryDirectory() as tmp_dir:
      test_repo = test_repos.TEST_REPOS[1]
      self.assertTrue(helper.build_image_impl(test_repo.project_name))
      host_src_dir = build_specified_commit.copy_src_from_docker(
          test_repo.project_name, tmp_dir)

      test_repo_manager = repo_manager.clone_repo_and_get_manager(
          test_repo.git_url, host_src_dir, test_repo.oss_repo_name)
      build_data = build_specified_commit.BuildData(
          sanitizer='address',
          architecture='x86_64',
          engine='libfuzzer',
          project_name=test_repo.project_name)

      build_specified_commit.build_fuzzers_from_commit(test_repo.old_commit,
                                                       test_repo_manager,
                                                       host_src_dir, build_data)
      project = helper.Project(test_repo.project_name)
      old_result = helper.reproduce_impl(project=project,
                                         fuzzer_name=test_repo.fuzz_target,
                                         valgrind=False,
                                         env_to_add=[],
                                         fuzzer_args=[],
                                         testcase_path=test_repo.testcase_path)
      build_specified_commit.build_fuzzers_from_commit(test_repo.project_name,
                                                       test_repo_manager,
                                                       host_src_dir, build_data)
      new_result = helper.reproduce_impl(project=project,
                                         fuzzer_name=test_repo.fuzz_target,
                                         valgrind=False,
                                         env_to_add=[],
                                         fuzzer_args=[],
                                         testcase_path=test_repo.testcase_path)
      self.assertNotEqual(new_result, old_result)

  def test_detect_main_repo_from_commit(self):
    """Test the detect main repo function from build specific commit module."""
    # TODO(metzman): Fix these tests so they don't randomly break because of
    # changes in the outside world.
    for example_repo in test_repos.TEST_REPOS:
      if example_repo.new_commit:
        # TODO(metzman): This function calls _build_image_with_retries which
        # has a long delay (30 seconds). Figure out how to make this quicker.
        repo_origin, repo_name = build_specified_commit.detect_main_repo(
            example_repo.project_name, commit=example_repo.new_commit)
        self.assertEqual(repo_origin, example_repo.git_url)
        self.assertEqual(repo_name,
                         os.path.join('/src', example_repo.oss_repo_name))

    repo_origin, repo_name = build_specified_commit.detect_main_repo(
        test_repos.INVALID_REPO.project_name,
        test_repos.INVALID_REPO.new_commit)
    self.assertIsNone(repo_origin)
    self.assertIsNone(repo_name)

  def test_detect_main_repo_from_name(self):
    """Test the detect main repo function from build specific commit module."""
    for example_repo in test_repos.TEST_REPOS:
      if example_repo.project_name == 'gonids':
        # It's unclear how this test ever passed, but we can't infer the repo
        # because gonids doesn't really check it out, it uses "go get".
        continue
      repo_origin, repo_name = build_specified_commit.detect_main_repo(
          example_repo.project_name, repo_name=example_repo.git_repo_name)
      self.assertEqual(repo_origin, example_repo.git_url)
      self.assertEqual(
          repo_name,
          os.path.join(example_repo.image_location, example_repo.oss_repo_name))

    repo_origin, repo_name = build_specified_commit.detect_main_repo(
        test_repos.INVALID_REPO.project_name,
        test_repos.INVALID_REPO.oss_repo_name)
    self.assertIsNone(repo_origin)
    self.assertIsNone(repo_name)


if __name__ == '__main__':
  # Change to oss-fuzz main directory so helper.py runs correctly.
  if os.getcwd() != os.path.dirname(TEST_DIR_PATH):
    os.chdir(os.path.dirname(TEST_DIR_PATH))
  unittest.main()
