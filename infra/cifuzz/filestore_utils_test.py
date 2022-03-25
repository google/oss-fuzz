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
"""Tests for filestore_utils."""
import unittest
from unittest import mock

import parameterized

import platform_config
import filestore
from filestore import github_actions
import filestore_utils
import test_helpers


class GetFilestoreTest(unittest.TestCase):
  """Tests for get_filestore."""

  @parameterized.parameterized.expand([
      ({
          'cfl_platform': 'github',
      }, github_actions.GithubActionsFilestore),
  ])
  def test_get_filestore(self, config_kwargs, filestore_cls):
    """Tests that get_filestore returns the right filestore given a certain
    platform."""
    run_config = test_helpers.create_run_config(**config_kwargs)
    filestore_impl = filestore_utils.get_filestore(run_config)
    self.assertIsInstance(filestore_impl, filestore_cls)

  @mock.patch('config_utils.BaseConfig.platform', return_value='other')
  @mock.patch('config_utils._get_platform_config',
              return_value=platform_config.BasePlatformConfig())
  def test_get_filestore_unsupported_platform(self, _, __):
    """Tests that get_filestore exceptions given a platform it doesn't
    support."""
    run_config = test_helpers.create_run_config()
    with self.assertRaises(filestore.FilestoreError):
      filestore_utils.get_filestore(run_config)
