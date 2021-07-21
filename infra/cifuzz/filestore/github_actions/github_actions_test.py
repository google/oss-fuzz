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
"""Tests for github_actions."""
import os
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

# pylint: disable=wrong-import-position
INFRA_DIR = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__)))))
sys.path.append(INFRA_DIR)

from filestore import github_actions
import test_helpers

# pylint: disable=protected-access,no-self-use


class GithubActionsFilestoreTest(unittest.TestCase):
  """Tests for GithubActionsFilestore."""

  def setUp(self):
    test_helpers.patch_environ(self)
    self.github_token = 'example githubtoken'

  def _get_expected_http_headers(self):
    return {
        'Authorization': 'token {token}'.format(token=self.github_token),
        'Accept': 'application/vnd.github.v3+json',
    }

  @mock.patch('filestore.github_actions.github_api.list_artifacts')
  def test_list_artifacts(self, mocked_list_artifacts):
    """Tests that _list_artifacts works as intended."""
    owner = 'exampleowner'
    repo = 'examplerepo'
    os.environ['GITHUB_REPOSITORY'] = '{owner}/{repo}'.format(owner=owner,
                                                              repo=repo)
    config = test_helpers.create_run_config(github_token=self.github_token)
    filestore = github_actions.GithubActionsFilestore(config)
    filestore._list_artifacts()
    mocked_list_artifacts.assert_called_with(owner, repo,
                                             self._get_expected_http_headers())

  @mock.patch('logging.warning')
  @mock.patch('filestore.github_actions.GithubActionsFilestore._list_artifacts',
              return_value=None)
  @mock.patch('filestore.github_actions.github_api.find_artifact',
              return_value=None)
  def test_download_latest_build_no_artifact(self, _, __, mocked_warning):
    """Tests that download_latest_build returns None and doesn't exception when
    find_artifact can't find an artifact."""
    config = test_helpers.create_run_config(github_token=self.github_token)
    filestore = github_actions.GithubActionsFilestore(config)
    name = 'build-name'
    build_dir = 'build-dir'
    self.assertIsNone(filestore.download_latest_build(name, build_dir))
    mocked_warning.assert_called_with('Could not download artifact: %s.', name)

  @mock.patch('logging.warning')
  @mock.patch('filestore.github_actions.GithubActionsFilestore._list_artifacts',
              return_value=None)
  @mock.patch('filestore.github_actions.github_api.find_artifact',
              return_value=None)
  def test_download_corpus_no_artifact(self, _, __, mocked_warning):
    """Tests that download_corpus_build returns None and doesn't exception when
    find_artifact can't find an artifact."""
    config = test_helpers.create_run_config(github_token=self.github_token)
    filestore = github_actions.GithubActionsFilestore(config)
    name = 'corpus-name'
    dst_dir = 'corpus-dir'
    self.assertFalse(filestore.download_corpus(name, dst_dir))
    mocked_warning.assert_called_with('Could not download artifact: %s.', name)


class TarDirectoryTest(unittest.TestCase):
  """Tests for tar_directory."""

  def test_tar_directory(self):
    """Tests that tar_directory writes the archive to the correct location and
    archives properly."""
    with tempfile.TemporaryDirectory() as temp_dir:
      archive_path = os.path.join(temp_dir, 'myarchive.tar')
      archived_dir = os.path.join(temp_dir, 'toarchive')
      os.mkdir(archived_dir)
      archived_filename = 'file1'
      archived_file_path = os.path.join(archived_dir, archived_filename)
      with open(archived_file_path, 'w') as file_handle:
        file_handle.write('hi')
      github_actions.tar_directory(archived_dir, archive_path)
      self.assertTrue(os.path.exists(archive_path))

      # Now check it archives correctly.
      unpacked_directory = os.path.join(temp_dir, 'unpacked')
      with tarfile.TarFile(archive_path) as artifact_tarfile:
        artifact_tarfile.extractall(unpacked_directory)
      unpacked_archived_file_path = os.path.join(unpacked_directory,
                                                 archived_filename)
      self.assertTrue(os.path.exists(unpacked_archived_file_path))
