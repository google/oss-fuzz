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
import posixpath
import re
import shlex
import stat
import subprocess
import sys

import helper

ALLOWED_FUZZ_TARGET_EXTENSIONS = ['', '.exe']
FUZZ_TARGET_SEARCH_STRING = 'LLVMFuzzerTestOneInput'
VALID_TARGET_NAME_REGEX = re.compile(r'^[a-zA-Z0-9_-]+$')
BLOCKLISTED_TARGET_NAME_REGEX = re.compile(r'^(jazzer_driver.*)$')

# Location of google cloud storage for latest OSS-Fuzz builds.
GCS_BASE_URL = 'https://storage.googleapis.com/'


def chdir_to_root():
  """Changes cwd to OSS-Fuzz root directory."""
  # Change to oss-fuzz main directory so helper.py runs correctly.
  if os.getcwd() != helper.OSS_FUZZ_DIR:
    os.chdir(helper.OSS_FUZZ_DIR)


def command_to_string(command):
  """Returns the stringfied version of |command| a list representing a binary to
  run and arguments to pass to it or a string representing a binary to run."""
  if isinstance(command, str):
    return command
  return shlex.join(command)


def execute(command,
            env=None,
            location=None,
            check_result=False,
            log_command=True):
  """Runs a shell command in the specified directory location.

  Args:
    command: The command as a list to be run.
    env: (optional) an environment to pass to Popen to run the command in.
    location (optional): The directory to run command in.
    check_result (optional): Should an exception be thrown on failure.

  Returns:
    stdout, stderr, returncode.

  Raises:
    RuntimeError: running a command resulted in an error.
  """

  if not location:
    location = os.getcwd()
  process = subprocess.Popen(command,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE,
                             cwd=location,
                             env=env)
  out, err = process.communicate()
  out = out.decode('utf-8', errors='ignore')
  err = err.decode('utf-8', errors='ignore')

  if log_command:
    command_str = command_to_string(command)
    display_err = err
  else:
    command_str = 'redacted'
    display_err = 'redacted'

  if err:
    logging.debug('Stderr of command "%s" is: %s.', command_str, display_err)
  if check_result and process.returncode:
    raise RuntimeError('Executing command "{0}" failed with error: {1}.'.format(
        command_str, display_err))
  return out, err, process.returncode


def get_fuzz_targets(path):
  """Gets fuzz targets in a directory.

  Args:
    path: A path to search for fuzz targets in.

  Returns:
    A list of paths to fuzzers or an empty list if None.
  """
  if not os.path.exists(path):
    return []
  fuzz_target_paths = []
  for root, _, fuzzers in os.walk(path):
    for fuzzer in fuzzers:
      file_path = os.path.join(root, fuzzer)
      if is_fuzz_target_local(file_path):
        fuzz_target_paths.append(file_path)

  return fuzz_target_paths


def get_container_name():
  """Gets the name of the current docker container you are in.

  Returns:
    Container name or None if not in a container.
  """
  result = subprocess.run(  # pylint: disable=subprocess-run-check
      ['systemd-detect-virt', '-c'],
      stdout=subprocess.PIPE).stdout
  if b'docker' not in result:
    return None
  with open('/etc/hostname') as file_handle:
    return file_handle.read().strip()


def is_executable(file_path):
  """Returns True if |file_path| is an exectuable."""
  return os.path.exists(file_path) and os.access(file_path, os.X_OK)


def is_fuzz_target_local(file_path):
  """Returns whether |file_path| is a fuzz target binary (local path).
  Copied from clusterfuzz src/python/bot/fuzzers/utils.py
  with slight modifications.
  """
  # pylint: disable=too-many-return-statements
  filename, file_extension = os.path.splitext(os.path.basename(file_path))
  if not VALID_TARGET_NAME_REGEX.match(filename):
    # Check fuzz target has a valid name (without any special chars).
    return False

  if BLOCKLISTED_TARGET_NAME_REGEX.match(filename):
    # Check fuzz target an explicitly disallowed name (e.g. binaries used for
    # jazzer-based targets).
    return False

  if file_extension not in ALLOWED_FUZZ_TARGET_EXTENSIONS:
    # Ignore files with disallowed extensions (to prevent opening e.g. .zips).
    return False

  if not is_executable(file_path):
    return False

  if filename.endswith('_fuzzer'):
    return True

  if os.path.exists(file_path) and not stat.S_ISREG(os.stat(file_path).st_mode):
    return False

  with open(file_path, 'rb') as file_handle:
    return file_handle.read().find(FUZZ_TARGET_SEARCH_STRING.encode()) != -1


def binary_print(string):
  """Prints string. Can print a binary string."""
  if isinstance(string, bytes):
    string += b'\n'
  else:
    string += '\n'
  sys.stdout.buffer.write(string)
  sys.stdout.flush()


def url_join(*url_parts):
  """Joins URLs together using the POSIX join method.

  Args:
    url_parts: Sections of a URL to be joined.

  Returns:
    Joined URL.
  """
  return posixpath.join(*url_parts)


def gs_url_to_https(url):
  """Converts |url| from a GCS URL (beginning with 'gs://') to an HTTPS one."""
  return url_join(GCS_BASE_URL, remove_prefix(url, 'gs://'))


def remove_prefix(string, prefix):
  """Returns |string| without the leading substring |prefix|."""
  # Match behavior of removeprefix from python3.9:
  # https://www.python.org/dev/peps/pep-0616/
  if string.startswith(prefix):
    return string[len(prefix):]

  return string
