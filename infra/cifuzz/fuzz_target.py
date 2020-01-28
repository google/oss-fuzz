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
import os
import re
import subprocess
import sys

# pylint: disable=wrong-import-position
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import utils

# TODO: Turn default logging to WARNING when CIFuzz is stable
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.DEBUG)


class FuzzTarget:
  """A class to manage a single fuzz target.

  Attributes:
    project_name: The name of the OSS-Fuzz project the target is associated.
    target_name: The name of the fuzz target.
    duration: The length of time in seconds that the target should run.
    target_path: The location of the fuzz target binary.
  """

  def __init__(self, project_name, target_path, duration, out_dir):
    """Represents a single fuzz target.

    Args:
      project_name: The OSS-Fuzz project of this target.
      target_path: The location of the fuzz target binary.
      duration: The length of time  in seconds the target should run.
      out_dir: The location of where the output from crashes should be stored.
    """
    self.target_name = os.path.basename(target_path)
    self.duration = duration
    self.project_name = project_name
    self.target_path = target_path
    self.out_dir = out_dir

  def fuzz(self):
    """Starts the fuzz target run for the length of time specified by duration.

    Returns:
      (test_case, stack trace) if found or (None, None) on timeout or error.
    """
    logging.info('Fuzzer %s, started.', self.target_name)
    docker_container = utils.get_container_name()
    command = ['docker', 'run', '--rm', '--privileged']
    if docker_container:
      command += [
          '--volumes-from', docker_container, '-e', 'OUT=' + self.out_dir
      ]
    else:
      command += ['-v', '%s:%s' % (self.out_dir, '/out')]

    command += [
        '-e', 'FUZZING_ENGINE=libfuzzer', '-e', 'SANITIZER=address', '-e',
        'RUN_FUZZER_MODE=interactive', 'gcr.io/oss-fuzz-base/base-runner',
        'bash', '-c', 'run_fuzzer {0}'.format(self.target_name)
    ]
    logging.info('Running command: %s', ' '.join(command))
    process = subprocess.Popen(command,
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)

    try:
      _, err = process.communicate(timeout=self.duration)
    except subprocess.TimeoutExpired:
      logging.info('Fuzzer %s, finished with timeout.', self.target_name)
      return None, None

    logging.info('Fuzzer %s, ended before timeout.', self.target_name)
    err_str = err.decode('ascii')
    test_case = self.get_test_case(err_str)
    if not test_case:
      logging.error('No test case found in stack trace.', file=sys.stderr)
      return None, None
    return test_case, err_str

  def get_test_case(self, error_string):
    """Gets the file from a fuzzer run stack trace.

    Args:
      error_string: The stack trace string containing the error.

    Returns:
      The error test case or None if not found.
    """
    match = re.search(r'\bTest unit written to \.\/([^\s]+)', error_string)
    if match:
      return os.path.join(self.out_dir, match.group(1))
    return None
