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
import sys
import shutil
import tempfile
from unittest import mock

import config_utils
import docker
import workspace_utils

INFRA_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# pylint: disable=wrong-import-position,import-error
sys.path.append(INFRA_DIR)

import helper


# TODO(metzman): Get rid of these decorators.
@mock.patch('config_utils._is_dry_run', return_value=True)
@mock.patch('platform_config.BasePlatformConfig.project_src_path',
            return_value=None)
@mock.patch('os.path.basename', return_value=None)
def _create_config(config_cls, _, __, ___, **kwargs):
  """Creates a config object from |config_cls| and then sets every attribute
  that is a key in |kwargs| to the corresponding value. Asserts that each key in
  |kwargs| is an attribute of config."""
  with mock.patch('config_utils.BaseConfig.validate', return_value=True):
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
  return workspace_utils.Workspace(config)


def patch_environ(testcase_obj, env=None, empty=False, runner=False):
  """Patch environment. |testcase_obj| is the unittest.TestCase that contains
  tests. |env|, if specified, is a dictionary of environment variables to start
  from. If |empty| is True then the new patched environment will be empty. If
  |runner| is True then the necessary environment variables will be set to run
  the scripts from base-runner."""
  if env is None:
    env = {}

  patcher = mock.patch.dict(os.environ, env)
  testcase_obj.addCleanup(patcher.stop)
  patcher.start()
  if empty:
    for key in os.environ.copy():
      del os.environ[key]

  if runner:
    # Add the scripts for base-runner to the path since the wont be in
    # /usr/local/bin on host machines during testing.
    base_runner_dir = os.path.join(INFRA_DIR, 'base-images', 'base-runner')
    os.environ['PATH'] = (os.environ.get('PATH', '') + os.pathsep +
                          base_runner_dir)
    if 'GOPATH' not in os.environ:
      # A GOPATH must be set or else the coverage script fails, even for getting
      # the coverage of non-Go programs.
      os.environ['GOPATH'] = '/root/go'


@contextlib.contextmanager
def temp_dir_copy(directory):
  """Context manager that yields a temporary copy of |directory|."""
  with tempfile.TemporaryDirectory() as temp_dir:
    temp_copy_path = os.path.join(temp_dir, os.path.basename(directory))
    shutil.copytree(directory, temp_copy_path)
    yield temp_copy_path


@contextlib.contextmanager
def docker_temp_dir():
  """Returns a temporary a directory that is useful for use with docker. On
  cleanup this contextmanager uses docker to delete the directory's contents so
  that if anything is owned by root it can be deleted (which
  tempfile.TemporaryDirectory() cannot do) by non-root users."""
  with tempfile.TemporaryDirectory() as temp_dir:
    yield temp_dir
    helper.docker_run([
        '-v', f'{temp_dir}:/temp_dir', '-t', docker.BASE_BUILDER_TAG,
        '/bin/bash', '-c', 'rm -rf /temp_dir/*'
    ])
