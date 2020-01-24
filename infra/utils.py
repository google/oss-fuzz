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
"""Utilities for OSS-Fuzz infrastructure."""

import logging
import os
import re
import stat
import sys

import build_specified_commit
import helper

ALLOWED_FUZZ_TARGET_EXTENSIONS = ['', '.exe']
FUZZ_TARGET_SEARCH_STRING = 'LLVMFuzzerTestOneInput'
VALID_TARGET_NAME = re.compile(r'^[a-zA-Z0-9_-]+$')

logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    stream=sys.stdout,
    level=logging.DEBUG)


def is_fuzz_target_local(file_path):
  """Returns whether |file_path| is a fuzz target binary (local path).
  Copied from clusterfuzz src/python/bot/fuzzers/utils.py
  with slight modifications.
  """
  filename, file_extension = os.path.splitext(os.path.basename(file_path))
  if not VALID_TARGET_NAME.match(filename):
    # Check fuzz target has a valid name (without any special chars).
    return False

  if file_extension not in ALLOWED_FUZZ_TARGET_EXTENSIONS:
    # Ignore files with disallowed extensions (to prevent opening e.g. .zips).
    return False

  if not os.path.exists(file_path) or not os.access(file_path, os.X_OK):
    return False

  if filename.endswith('_fuzzer'):
    return True

  if os.path.exists(file_path) and not stat.S_ISREG(os.stat(file_path).st_mode):
    return False

  with open(file_path, 'rb') as file_handle:
    return file_handle.read().find(FUZZ_TARGET_SEARCH_STRING.encode()) != -1


def get_fuzz_targets(path):
  """Get list of fuzz targets in a directory.

  Args:
    path: A path to search for fuzz targets in.

  Returns:
    A list of paths to fuzzers or an empty list if None.
  """

  fuzz_target_paths = []
  for root, _, _ in os.walk(path):
    for filename in os.listdir(path):
      file_path = os.path.join(root, filename)
      if is_fuzz_target_local(file_path):
        fuzz_target_paths.append(file_path)

  return fuzz_target_paths


def get_env_var(project_name, env_var_name):
  """Gets an environment variable from a docker image.

  Args:
    project_name: The oss-fuzz project to get the var from.
    env_var_name: The name of the variable to be checked.

  Returns:
    None on error or the enviroment variable value.
  """
  # Change to oss-fuzz main directory so helper.py runs correctly.
  if os.getcwd() != helper.OSSFUZZ_DIR:
    os.chdir(helper.OSSFUZZ_DIR)
  if not helper.build_image_impl(project_name):
    logging.error('Error: building %s image.', project_name)
    return None
  command = ['docker', 'run', '--rm', '--privileged']
  command += [
      'gcr.io/oss-fuzz/' + project_name, 'bash', '-c',
      'echo ${0}'.format(env_var_name)
  ]
  out, err_code = build_specified_commit.execute(command)
  if err_code:
    return None
  return out.replace('\'', '')


def get_container():
  """Gets the name of the current docker container you are in.

  Returns:
    Container name or None if not in a container.
  """
  with open('/proc/self/cgroup') as file_handle:
    if 'docker' not in file_handle.read():
      return None
    with open('/etc/hostname') as file_handle:
      return file_handle.read().strip()
