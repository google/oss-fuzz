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
"""Runs all relevant CIFuzz tests in a docker container."""
import argparse
import os
import subprocess
import sys
import unittest

#pylint: disable=import-error
#pylint: disable=wrong-import-position
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import utils
import helper

CONTAINER_NAME = 'cifuzz-base-test'


def main():
  """Runs all relevant CIFuzz tests in a docker container."""

  parser = argparse.ArgumentParser(description='Run CIFuzz test suite.')
  parser.add_argument('--no_docker', action='store_true')
  args = parser.parse_args()

  if args.no_docker:
    print('Running CIFuzz tests outside of container.')
    full_suite = unittest.TestLoader().discover(os.path.dirname(
        os.path.abspath(__file__)),
                                                pattern='*_test.py')
    return len(unittest.TextTestRunner().run(full_suite).failures)

  # If already in container run tests suite
  container = utils.get_container_name()
  if container:

    full_suite = unittest.TestLoader().discover(os.path.join(
        '/src', 'oss-fuzz', 'infra', 'cifuzz'),
                                                pattern='*_test.py')
    return len(unittest.TextTestRunner().run(full_suite).failures)

  # Build container for testing.
  print('Running CIFuzz tests inside of container.')
  docker_build_command = [
      'docker',
      'build',
      os.path.join(helper.OSSFUZZ_DIR, 'infra', 'cifuzz', 'cifuzz-base'),
      '-t',
      CONTAINER_NAME + ':latest',
  ]
  subprocess.call(docker_build_command)

  # Run the test suite inside of the container.
  docker_run_command = [
      'docker', 'run', '--rm', '-i', '--privileged', '-v',
      '%s:%s' % (helper.OSSFUZZ_DIR, '/src/oss-fuzz'), '-v',
      '/var/run/docker.sock:/var/run/docker.sock', '-v', '/tmp:/tmp',
      CONTAINER_NAME + ':latest', '/usr/bin/python3',
      '/src/oss-fuzz/infra/cifuzz/cifuzz_testsuite.py'
  ]
  return subprocess.call(docker_run_command)


if __name__ == '__main__':
  sys.exit(main())
