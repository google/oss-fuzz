# Copyright 2020 Google LLC
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
"""Contains convenient helpers for writing tests."""

import contextlib
import os
import shutil
import tempfile
from unittest import mock

import config_utils


def _create_config(config_cls, **kwargs):
  """Creates a config object from |config_cls| and then sets every attribute
  that is a key in |kwargs| to the corresponding value. Asserts that each key in
  |kwargs| is an attribute of config."""
  with mock.patch('os.path.basename', return_value=None), mock.patch(
      'config_utils.get_project_src_path',
      return_value=None), mock.patch('config_utils._is_dry_run',
                                     return_value=True):
    config = config_cls()

  for key, value in kwargs.items():
    assert hasattr(config, key), 'Config doesn\'t have attribute: ' + key
    setattr(config, key, value)
  return config


def create_build_config(**kwargs):
  """Wrapper around _create_config for build configs."""
  return _create_config(config_utils.BuildFuzzersConfig, **kwargs)


def create_run_config(**kwargs):
  """Wrapper around _create_config for run configs."""
  return _create_config(config_utils.RunFuzzersConfig, **kwargs)


def create_workspace(workspace_path='/workspace'):
  """Returns a workspace located at |workspace_path| ('/workspace' by
  default)."""
  config = create_run_config(workspace=workspace_path)
  return config_utils.Workspace(config)


def patch_environ(testcase_obj, env=None):
  """Patch environment."""
  if env is None:
    env = {}

  patcher = mock.patch.dict(os.environ, env)
  testcase_obj.addCleanup(patcher.stop)
  patcher.start()


@contextlib.contextmanager
def temp_dir_copy(directory):
  """Context manager that yields a temporary copy of |directory|."""
  with tempfile.TemporaryDirectory() as temp_dir:
    temp_copy_path = os.path.join(temp_dir, os.path.basename(directory))
    shutil.copytree(directory, temp_copy_path)
    yield temp_copy_path
