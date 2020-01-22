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
"""A module to handle running a fuzz target for a specified amount of time."""
import logging
import subprocess
import os
import re
import sys

import utils


class FuzzTarget():
  """A class to manage a single fuzz target.

  Attributes:
    project_name: The name of the OSS-Fuzz project the target is associated.
    target_name: The name of the fuzz target.
    duration: The length of time in seconds that the target should run.
    target_path: The location of the fuzz target binary.
  """

  def __init__(self, project_name, target_path, duration):
    """Represents a single fuzz target.

    Args:
      project_name: The OSS-Fuzz project of this target.
      target_path: The location of the fuzz target binary.
      duration: The length of time  in seconds the target should run.
    """
    logging.basicConfig(
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        stream=sys.stdout,
        level=logging.DEBUG)
    self.target_name = target_path.split('/')[-1]
    self.duration = duration
    self.project_name = project_name
    self.target_path = target_path

  def start(self):
    """Starts the fuzz target run for the length of time specified by duration.

    Returns:
      (test_case, stack trace) if found or (None, None) on timeout or error.
    """

    command = [
        'docker', 'run', '--rm', '--privileged', '--volumes-from',
        utils.get_container()
    ]
    command += [
        '-e',
        'FUZZING_ENGINE=libfuzzer',
        '-e',
        'SANITIZER=address',
        '-e',
        'RUN_FUZZER_MODE=interactive',
    ]
    command += [
        'gcr.io/oss-fuzz-base/base-runner', 'bash', '-c',
        'cp -rf {0} {1} && run_fuzzer {2} && cp {1} {3}'.format(
            self.target_path, '/out', self.target_name,
            os.path.dirname(self.target_path))
    ]

    logging.debug('Running command: %s', ' '.join(command))
    process = subprocess.Popen(command,
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
    try:
      _, err = process.communicate(timeout=self.duration)
    except subprocess.TimeoutExpired:
      logging.debug('Fuzzer %s finished with timeout.', self.target_name)
      return None, None
    test_case = self.get_test_case(err.decode('ascii'))
    if not test_case:
      print('Error no test case found in stack trace.', file=sys.stderr)
      return None, None
    return test_case, err.decode('ascii')

  def get_test_case(self, error_string):
    """Gets the file from a fuzzer run stack trace.

    Args:
      error_string: The stack trace string containing the error.

    Returns:
      The error test case or None if not found.
    """
    match = re.search(r'\bTest unit written to \.([^ ]+)',
                      error_string.rstrip())
    if match:
      return match.split('/')[-1]
    return None
