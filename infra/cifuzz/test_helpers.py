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
import sys
import tempfile
from unittest import mock

import config_utils
import docker

# pylint: disable=wrong-import-position,import-error
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import helper


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


@contextlib.contextmanager
def temp_dir_for_docker():
  """Returns a temporary directory for mounting in docker that gets deleted
  later. The directory works well for mounting because the deletion will be done
  by docker, so any root-owned files can be deleted, even if tests aren't run by
  root."""
  with tempfile.TemporaryDirectory() as temp_dir:
    yield temp_dir
    docker_delete_dir(temp_dir)


def docker_delete_dir(directory, docker_image=docker.BASE_BUILDER_TAG):
  """Deletes |directory| using docker. This is useful because some
  files/directories created by docker are owned by root and thus the test won't
  be able to delete them. Runs the rm command in |docker_image|."""
  mount_name = '/directory-to-delete'
  if not helper.docker_run([
      '-v', f'{directory}:{mount_name}', '-t', docker_image, '/bin/bash', '-c',
      f'rm -rf {mount_name}/*'
  ]):
    raise RuntimeError(f'Could not delete {directory}')
