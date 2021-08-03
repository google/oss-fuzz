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


def _create_config(**kwargs):
  """Creates a config object and then sets every attribute that is a key in
  |kwargs| to the corresponding value. Asserts that each key in |kwargs| is an
  attribute of Config."""
  defaults = {
      'is_github': True,
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

  @mock.patch('http_utils.download_and_unpack_zip', return_value=True)
  def test_download_corpus(self, mocked_download_and_unpack_zip):
    """Tests that we can download a corpus for a valid project."""
    result = self.deployment.download_corpus(EXAMPLE_FUZZER)
    self.assertIsNotNone(result)
    expected_corpus_dir = os.path.join(self.deployment.workspace.corpora,
                                       EXAMPLE_FUZZER)
    expected_url = ('https://storage.googleapis.com/example-backup.'
                    'clusterfuzz-external.appspot.com/corpus/libFuzzer/'
                    'example_crash_fuzzer/public.zip')
    call_args, _ = mocked_download_and_unpack_zip.call_args
    self.assertEqual(call_args, (expected_url, expected_corpus_dir))

  @mock.patch('http_utils.download_and_unpack_zip', return_value=False)
  def test_download_corpus_fail(self, _):
    """Tests that when downloading fails, an empty corpus directory is still
    returned."""
    corpus_path = self.deployment.download_corpus(EXAMPLE_FUZZER)
    self.assertEqual(corpus_path,
                     '/workspace/cifuzz-corpus/example_crash_fuzzer')
    self.assertEqual(os.listdir(corpus_path), [])

  def test_get_latest_build_name(self):
    """Tests that the latest build name can be retrieved from GCS."""
    latest_build_name = self.deployment.get_latest_build_name()
    self.assertTrue(latest_build_name.endswith('.zip'))
    self.assertTrue('address' in latest_build_name)

  @parameterized.parameterized.expand([
      ('upload_latest_build', tuple(),
       'Not uploading latest build because on OSS-Fuzz.'),
      ('upload_corpus', ('target',),
       'Not uploading corpus because on OSS-Fuzz.'),
      ('upload_crashes', tuple(), 'Not uploading crashes because on OSS-Fuzz.'),
  ])
  def test_noop_methods(self, method, method_args, expected_message):
    """Tests that certain methods are noops for OSS-Fuzz."""
    with mock.patch('logging.info') as mocked_info:
      method = getattr(self.deployment, method)
      self.assertIsNone(method(*method_args))
      mocked_info.assert_called_with(expected_message)

  @mock.patch('http_utils.download_and_unpack_zip', return_value=True)
  def test_download_latest_build(self, mocked_download_and_unpack_zip):
    """Tests that downloading the latest build works as intended under normal
    circumstances."""
    self.assertEqual(self.deployment.download_latest_build(),
                     EXPECTED_LATEST_BUILD_PATH)
    expected_url = ('https://storage.googleapis.com/clusterfuzz-builds/example/'
                    'example-address-202008030600.zip')
    mocked_download_and_unpack_zip.assert_called_with(
        expected_url, EXPECTED_LATEST_BUILD_PATH)

  @mock.patch('http_utils.download_and_unpack_zip', return_value=False)
  def test_download_latest_build_fail(self, _):
    """Tests that download_latest_build returns None when it fails to download a
    build."""
    self.assertIsNone(self.deployment.download_latest_build())


class ClusterFuzzLiteTest(fake_filesystem_unittest.TestCase):
  """Tests for ClusterFuzzLite."""

  def setUp(self):
    self.setUpPyfakefs()
    self.deployment = _create_deployment(run_fuzzers_mode='batch',
                                         build_integration_path='/',
                                         oss_fuzz_project_name='',
                                         is_github=True)

  @mock.patch('filestore.github_actions.GithubActionsFilestore.download_corpus',
              return_value=True)
  def test_download_corpus(self, mocked_download_corpus):
    """Tests that download_corpus works for a valid project."""
    result = self.deployment.download_corpus(EXAMPLE_FUZZER)
    expected_corpus_dir = os.path.join(WORKSPACE, 'cifuzz-corpus',
                                       EXAMPLE_FUZZER)
    self.assertEqual(result, expected_corpus_dir)
    mocked_download_corpus.assert_called_with('example_crash_fuzzer',
                                              expected_corpus_dir)

  @mock.patch('filestore.github_actions.GithubActionsFilestore.download_corpus',
              side_effect=Exception)
  def test_download_corpus_fail(self, _):
    """Tests that when downloading fails, an empty corpus directory is still
    returned."""
    corpus_path = self.deployment.download_corpus(EXAMPLE_FUZZER)
    self.assertEqual(corpus_path,
                     '/workspace/cifuzz-corpus/example_crash_fuzzer')
    self.assertEqual(os.listdir(corpus_path), [])

  @mock.patch('filestore.github_actions.GithubActionsFilestore.download_build',
              return_value=True)
  def test_download_latest_build(self, mocked_download_build):
    """Tests that downloading the latest build works as intended under normal
    circumstances."""
    self.assertEqual(self.deployment.download_latest_build(),
                     EXPECTED_LATEST_BUILD_PATH)
    expected_artifact_name = 'address-latest'
    mocked_download_build.assert_called_with(expected_artifact_name,
                                             EXPECTED_LATEST_BUILD_PATH)

  @mock.patch('filestore.github_actions.GithubActionsFilestore.download_build',
              side_effect=Exception)
  def test_download_latest_build_fail(self, _):
    """Tests that download_latest_build returns None when it fails to download a
    build."""
    self.assertIsNone(self.deployment.download_latest_build())

  @mock.patch('filestore.github_actions.GithubActionsFilestore.' 'upload_build')
  def test_upload_latest_build(self, mocked_upload_build):
    """Tests that upload_latest_build works as intended."""
    self.deployment.upload_latest_build()
    mocked_upload_build.assert_called_with('address-latest',
                                           '/workspace/build-out')


class NoClusterFuzzDeploymentTest(fake_filesystem_unittest.TestCase):
  """Tests for NoClusterFuzzDeployment."""

  def setUp(self):
    self.setUpPyfakefs()
    config = test_helpers.create_run_config(build_integration_path='/',
                                            workspace=WORKSPACE,
                                            is_github=False)
    workspace = workspace_utils.Workspace(config)
    self.deployment = clusterfuzz_deployment.get_clusterfuzz_deployment(
        config, workspace)

  @mock.patch('logging.info')
  def test_download_corpus(self, mocked_info):
    """Tests that download corpus returns the path to the empty corpus
    directory."""
    corpus_path = self.deployment.download_corpus(EXAMPLE_FUZZER)
    self.assertEqual(corpus_path,
                     '/workspace/cifuzz-corpus/example_crash_fuzzer')
    mocked_info.assert_called_with(
        'Not downloading corpus because no ClusterFuzz deployment.')

  @parameterized.parameterized.expand([
      ('upload_latest_build', tuple(),
       'Not uploading latest build because no ClusterFuzz deployment.'),
      ('upload_corpus', ('target',),
       'Not uploading corpus because no ClusterFuzz deployment.'),
      ('upload_crashes', tuple(),
       'Not uploading crashes because no ClusterFuzz deployment.'),
      ('download_latest_build', tuple(),
       'Not downloading latest build because no ClusterFuzz deployment.')
  ])
  def test_noop_methods(self, method, method_args, expected_message):
    """Tests that certain methods are noops for NoClusterFuzzDeployment."""
    with mock.patch('logging.info') as mocked_info:
      method = getattr(self.deployment, method)
      self.assertIsNone(method(*method_args))
      mocked_info.assert_called_with(expected_message)


class GetClusterFuzzDeploymentTest(unittest.TestCase):
  """Tests for get_clusterfuzz_deployment."""

  @parameterized.parameterized.expand([
      (config_utils.BaseConfig.Platform.INTERNAL_GENERIC_CI,
       clusterfuzz_deployment.OSSFuzz),
      (config_utils.BaseConfig.Platform.INTERNAL_GITHUB,
       clusterfuzz_deployment.OSSFuzz),
      (config_utils.BaseConfig.Platform.EXTERNAL_GENERIC_CI,
       clusterfuzz_deployment.NoClusterFuzzDeployment),
      (config_utils.BaseConfig.Platform.EXTERNAL_GITHUB,
       clusterfuzz_deployment.ClusterFuzzLite),
  ])
  def test_get_clusterfuzz_deployment(self, platform, expected_deployment_cls):
    """Tests that get_clusterfuzz_deployment returns the correct value."""
    with mock.patch('config_utils.BaseConfig.platform',
                    return_value=platform,
                    new_callable=mock.PropertyMock):
      with mock.patch('filestore_utils.get_filestore', return_value=None):
        config = _create_config()
        workspace = workspace_utils.Workspace(config)

        self.assertIsInstance(
            clusterfuzz_deployment.get_clusterfuzz_deployment(
                config, workspace), expected_deployment_cls)


if __name__ == '__main__':
  unittest.main()
