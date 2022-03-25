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
"""Tests for clusterfuzz_deployment.py"""

import os
import unittest
from unittest import mock

import parameterized
from pyfakefs import fake_filesystem_unittest

import clusterfuzz_deployment
import config_utils
import test_helpers
import workspace_utils

# NOTE: This integration test relies on
# https://github.com/google/oss-fuzz/tree/master/projects/example project.
EXAMPLE_PROJECT = 'example'

# An example fuzzer that triggers an error.
EXAMPLE_FUZZER = 'example_crash_fuzzer'

WORKSPACE = '/workspace'
EXPECTED_LATEST_BUILD_PATH = os.path.join(WORKSPACE, 'cifuzz-prev-build')

# pylint: disable=unused-argument


def _create_config(**kwargs):
  """Creates a config object and then sets every attribute that is a key in
  |kwargs| to the corresponding value. Asserts that each key in |kwargs| is an
  attribute of Config."""
  defaults = {
      'cfl_platform': 'github',
      'oss_fuzz_project_name': EXAMPLE_PROJECT,
      'workspace': WORKSPACE,
  }
  for default_key, default_value in defaults.items():
    if default_key not in kwargs:
      kwargs[default_key] = default_value

  return test_helpers.create_run_config(**kwargs)


def _create_deployment(**kwargs):
  config = _create_config(**kwargs)
  workspace = workspace_utils.Workspace(config)
  return clusterfuzz_deployment.get_clusterfuzz_deployment(config, workspace)


class OSSFuzzTest(fake_filesystem_unittest.TestCase):
  """Tests OSSFuzz."""

  def setUp(self):
    self.setUpPyfakefs()
    self.deployment = _create_deployment()
    self.corpus_dir = os.path.join(self.deployment.workspace.corpora,
                                   EXAMPLE_FUZZER)

  @mock.patch('http_utils.download_and_unpack_zip', return_value=True)
  def test_download_corpus(self, mock_download_and_unpack_zip):
    """Tests that we can download a corpus for a valid project."""
    self.deployment.download_corpus(EXAMPLE_FUZZER, self.corpus_dir)
    expected_url = ('https://storage.googleapis.com/example-backup.'
                    'clusterfuzz-external.appspot.com/corpus/libFuzzer/'
                    'example_crash_fuzzer/public.zip')
    call_args, _ = mock_download_and_unpack_zip.call_args
    self.assertEqual(call_args, (expected_url, self.corpus_dir))
    self.assertTrue(os.path.exists(self.corpus_dir))

  @mock.patch('http_utils.download_and_unpack_zip', return_value=False)
  def test_download_corpus_fail(self, _):
    """Tests that when downloading fails, an empty corpus directory is still
    returned."""
    self.deployment.download_corpus(EXAMPLE_FUZZER, self.corpus_dir)
    self.assertEqual(os.listdir(self.corpus_dir), [])

  def test_get_latest_build_name(self):
    """Tests that the latest build name can be retrieved from GCS."""
    latest_build_name = self.deployment.get_latest_build_name()
    self.assertTrue(latest_build_name.endswith('.zip'))
    self.assertTrue('address' in latest_build_name)

  @parameterized.parameterized.expand([
      ('upload_build', ('commit',),
       'Not uploading latest build because on OSS-Fuzz.'),
      ('upload_corpus', ('target', 'corpus-dir'),
       'Not uploading corpus because on OSS-Fuzz.'),
      ('upload_crashes', tuple(), 'Not uploading crashes because on OSS-Fuzz.'),
  ])
  def test_noop_methods(self, method, method_args, expected_message):
    """Tests that certain methods are noops for OSS-Fuzz."""
    with mock.patch('logging.info') as mock_info:
      method = getattr(self.deployment, method)
      self.assertIsNone(method(*method_args))
      mock_info.assert_called_with(expected_message)

  @mock.patch('http_utils.download_and_unpack_zip', return_value=True)
  def test_download_latest_build(self, mock_download_and_unpack_zip):
    """Tests that downloading the latest build works as intended under normal
    circumstances."""
    self.assertEqual(self.deployment.download_latest_build(),
                     EXPECTED_LATEST_BUILD_PATH)
    expected_url = ('https://storage.googleapis.com/clusterfuzz-builds/example/'
                    'example-address-202008030600.zip')
    mock_download_and_unpack_zip.assert_called_with(expected_url,
                                                    EXPECTED_LATEST_BUILD_PATH)

  @mock.patch('http_utils.download_and_unpack_zip', return_value=False)
  def test_download_latest_build_fail(self, _):
    """Tests that download_latest_build returns None when it fails to download a
    build."""
    self.assertIsNone(self.deployment.download_latest_build())


class ClusterFuzzLiteTest(fake_filesystem_unittest.TestCase):
  """Tests for ClusterFuzzLite."""

  def setUp(self):
    self.setUpPyfakefs()
    self.deployment = _create_deployment(mode='batch',
                                         oss_fuzz_project_name='',
                                         cloud_bucket='gs://bucket')
    self.corpus_dir = os.path.join(self.deployment.workspace.corpora,
                                   EXAMPLE_FUZZER)

  @mock.patch('filestore.github_actions.GithubActionsFilestore.download_corpus',
              return_value=True)
  def test_download_corpus(self, mock_download_corpus):
    """Tests that download_corpus works for a valid project."""
    self.deployment.download_corpus(EXAMPLE_FUZZER, self.corpus_dir)
    mock_download_corpus.assert_called_with('example_crash_fuzzer',
                                            self.corpus_dir)
    self.assertTrue(os.path.exists(self.corpus_dir))

  @mock.patch('filestore.github_actions.GithubActionsFilestore.download_corpus',
              side_effect=Exception)
  def test_download_corpus_fail(self, _):
    """Tests that when downloading fails, an empty corpus directory is still
    returned."""
    self.deployment.download_corpus(EXAMPLE_FUZZER, self.corpus_dir)
    self.assertEqual(os.listdir(self.corpus_dir), [])

  @mock.patch('filestore.github_actions.GithubActionsFilestore.download_build',
              side_effect=[False, True])
  @mock.patch('repo_manager.RepoManager.get_commit_list',
              return_value=['commit1', 'commit2'])
  @mock.patch('continuous_integration.GithubCiMixin.repo_dir',
              return_value='/path/to/repo')
  def test_download_latest_build(self, mock_repo_dir, mock_get_commit_list,
                                 mock_download_build):
    """Tests that downloading the latest build works as intended under normal
    circumstances."""
    self.assertEqual(self.deployment.download_latest_build(),
                     EXPECTED_LATEST_BUILD_PATH)
    expected_artifact_name = 'address-commit2'
    mock_download_build.assert_called_with(expected_artifact_name,
                                           EXPECTED_LATEST_BUILD_PATH)

  @mock.patch('filestore.github_actions.GithubActionsFilestore.download_build',
              side_effect=Exception)
  @mock.patch('repo_manager.RepoManager.get_commit_list',
              return_value=['commit1', 'commit2'])
  @mock.patch('continuous_integration.GithubCiMixin.repo_dir',
              return_value='/path/to/repo')
  def test_download_latest_build_fail(self, mock_repo_dir, mock_get_commit_list,
                                      _):
    """Tests that download_latest_build returns None when it fails to download a
    build."""
    self.assertIsNone(self.deployment.download_latest_build())

  @mock.patch('filestore.github_actions.GithubActionsFilestore.upload_build')
  def test_upload_build(self, mock_upload_build):
    """Tests that upload_build works as intended."""
    self.deployment.upload_build('commit')
    mock_upload_build.assert_called_with('address-commit',
                                         '/workspace/build-out')


class NoClusterFuzzDeploymentTest(fake_filesystem_unittest.TestCase):
  """Tests for NoClusterFuzzDeployment."""

  def setUp(self):
    self.setUpPyfakefs()
    config = test_helpers.create_run_config(workspace=WORKSPACE,
                                            cfl_platform='other',
                                            filestore='no_filestore',
                                            no_clusterfuzz_deployment=True)
    workspace = workspace_utils.Workspace(config)
    self.deployment = clusterfuzz_deployment.get_clusterfuzz_deployment(
        config, workspace)

    self.corpus_dir = os.path.join(workspace.corpora, EXAMPLE_FUZZER)

  @mock.patch('logging.info')
  def test_download_corpus(self, mock_info):
    """Tests that download corpus returns the path to the empty corpus
    directory."""
    self.deployment.download_corpus(EXAMPLE_FUZZER, self.corpus_dir)
    mock_info.assert_called_with(
        'Not downloading corpus because no ClusterFuzz deployment.')
    self.assertTrue(os.path.exists(self.corpus_dir))

  @parameterized.parameterized.expand([
      ('upload_build', ('commit',),
       'Not uploading latest build because no ClusterFuzz deployment.'),
      ('upload_corpus', ('target', 'corpus-dir'),
       'Not uploading corpus because no ClusterFuzz deployment.'),
      ('upload_crashes', tuple(),
       'Not uploading crashes because no ClusterFuzz deployment.'),
      ('download_latest_build', tuple(),
       'Not downloading latest build because no ClusterFuzz deployment.')
  ])
  def test_noop_methods(self, method, method_args, expected_message):
    """Tests that certain methods are noops for NoClusterFuzzDeployment."""
    with mock.patch('logging.info') as mock_info:
      method = getattr(self.deployment, method)
      self.assertIsNone(method(*method_args))
      mock_info.assert_called_with(expected_message)


class GetClusterFuzzDeploymentTest(unittest.TestCase):
  """Tests for get_clusterfuzz_deployment."""

  def setUp(self):
    test_helpers.patch_environ(self)
    os.environ['GITHUB_REPOSITORY'] = 'owner/myproject'

  @parameterized.parameterized.expand([
      (config_utils.BaseConfig.Platform.INTERNAL_GENERIC_CI,
       clusterfuzz_deployment.OSSFuzz),
      (config_utils.BaseConfig.Platform.INTERNAL_GITHUB,
       clusterfuzz_deployment.OSSFuzz),
      (config_utils.BaseConfig.Platform.EXTERNAL_GENERIC_CI,
       clusterfuzz_deployment.ClusterFuzzLite),
      (config_utils.BaseConfig.Platform.EXTERNAL_GITHUB,
       clusterfuzz_deployment.ClusterFuzzLite),
  ])
  def test_get_clusterfuzz_deployment(self, platform, expected_deployment_cls):
    """Tests that get_clusterfuzz_deployment returns the correct value."""
    with mock.patch('config_utils.BaseConfig.platform',
                    return_value=platform,
                    new_callable=mock.PropertyMock):
      with mock.patch('filestore_utils.get_filestore', return_value=None):
        with mock.patch('platform_config.github._get_event_data',
                        return_value={}):
          config = _create_config()
          workspace = workspace_utils.Workspace(config)

          self.assertIsInstance(
              clusterfuzz_deployment.get_clusterfuzz_deployment(
                  config, workspace), expected_deployment_cls)


if __name__ == '__main__':
  unittest.main()
