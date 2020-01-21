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
"""Utilities for OSS-Fuzz infrastructure."""

import os
import re
import stat
import sys

import helper
import utils

ALLOWED_FUZZ_TARGET_EXTENSIONS = ['', '.exe']
FUZZ_TARGET_SEARCH_STRING = 'LLVMFuzzerTestOneInput'
VALID_TARGET_NAME = re.compile(r'^[a-zA-Z0-9_-]+$')


def is_fuzz_target_local(file_path):
  """Returns whether |file_path| is a fuzz target binary (local path)."""
  filename, file_extension = os.path.splitext(os.path.basename(file_path))
  if not VALID_TARGET_NAME.match(filename):
    # Check fuzz target has a valid name (without any special chars).
    return False

  if file_extension not in ALLOWED_FUZZ_TARGET_EXTENSIONS:
    # Ignore files with disallowed extensions (to prevent opening e.g. .zips).
    return False

  if not os.path.exists(file_path):
    return False

  if not os.access(file_path, os.X_OK):
    return False

  if filename.endswith('_fuzzer'):
    return True

  if os.path.exists(file_path) and not stat.S_ISREG(os.stat(file_path).st_mode):
    # Don't read special files (eg: /dev/urandom).
    logs.log_warn('Tried to read from non-regular file: %s.' % file_path)
    return False

  with open(file_path, 'rb') as file_handle:
    return file_handle.read().find(FUZZ_TARGET_SEARCH_STRING.encode())


def get_project_fuzz_targets(project_name):
  """Get list of fuzz targets for a specific OSS-Fuzz project.

  Args:
    project_name: The name of the OSS-Fuzz in question.

  Returns:
    A list of paths to fuzzers or an empty list if None.
  """

  if not helper.check_project_exists(project_name):
    print('Error: Project {0} does not exist in OSS-Fuzz.'.format(project_name),
          file=sys.stderr)
    return []
  fuzz_target_paths = []
  path = os.path.join(helper.BUILD_DIR, 'out', project_name)
  print('Path', path)
  for root, _, files in os.walk(path):
    for filename in os.listdir(path):
      print('Possable fuzzer:', filename)
      file_path = os.path.join(root, filename)
      print(file_path)
      if is_fuzz_target_local(file_path):
        fuzz_target_paths.append(file_path)

  return fuzz_target_paths


def copy_to_docker(docker_image, src, dest):
  """Copys a file or directory local to a docker image.

  Args:
    docker_image: The name of the docker image you want to copy to.
    src: The location of the file/directory you want to copy.
    dest: The location of where you want the file/directory copied to.

  Return:
    True on success and False on failure.
"""


# Get the container name that are currently inside.
with open('/proc/self/cgroup') as file_handle:
  if 'docker' in file_handle.read():
    with open('/etc/hostname') as file_handle:
      primary_container = file_handle.read().strip()
  else:
    primary_container = None

command = [
    '--cap-add',
    'SYS_PTRACE',
]
if primary_container:
  command += ['--volumes-from', primary_container]

command += ['gcr.io/oss-fuzz/%s' % args.project_name]
command += ['/bin/bash', '-c', 'cp {0} {1}'.format(src, dest)]
result_code = helper.docker_run(command)
if result_code:
  print('Copying to docker image failed.', file=sys.stderr)
  return result_code
return 0
