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
"""Unit tests for helper.py  build_image function using a specific commit.

This unit test calls the build_image --commit command which attempts
to create a docker image using a specific commit SHA. It then creates
a container of the created image and checks to see what commit the
container is at.If the commit set and the container commit match up,
then the test passes.

  Typical usage example:

  python build_image_test.py
"""

# Add helper.py to the python path
import sys
sys.path.append("..")

from helper import _build_image_from_commit
from helper import _is_base_image
from helper import build_fuzzers
from helper import check_build
import argparse
import os
import subprocess
import unittest

# List of test cases to use for the
TEST_DATA_FILE = "helper_test.data"

# The pairs of project names to commits that are to be tested
test_data = dict()


class TestBuildImageCommit(unittest.TestCase):
  """Tests that a docker image can be build with a specific commit."""

  def build_image_with_commit(self, project_name, commit):
    """ Builds an image with a specific project can be
    build at a commit.

    Args:
      project_name: the project you want to build
      commit: the commit SHA you want the project at

    Returns:
      The location of the image that was build
    """

    # switch dirs for build_image call to run properly
    cur_dir = os.getcwd()
    os.chdir("..")
    _build_image_from_commit(project_name, commit)
    os.chdir(cur_dir)
    is_base_image = _is_base_image(project_name)
    if is_base_image:
      image_project = 'oss-fuzz-base'
    else:
      image_project = 'oss-fuzz'

    # Extracting git version from the built docker image
    image_location = "gcr.io/%s/%s" % (image_project, project_name)
    return image_location

  def test_build_image_from_commit(self):
    """ Test to assert a project can be built with a specific commit."""

    for project_name, commit in test_data.items():
      image_location = self.build_image_with_commit(project_name, commit)
      bash_command = "cd /src/%s ; git rev-parse HEAD" % project_name
      command = [
          'docker', 'run', '-i', '--privileged', image_location, 'bash', '-c',
          bash_command
      ]
      process = subprocess.Popen(command, stdout=subprocess.PIPE)
      out, _ = process.communicate()
      image_commit = out.decode('ascii').strip('\n')
      self.assertEqual(image_commit, commit)

  def test_build_fuzzer_from_commit(self):
    """ Test to assert fuzzers can be build from a project image that
    is built using a specific commit."""

    parser = argparse.ArgumentParser()
    parser.add_argument('project_name')
    parser.add_argument('fuzzer_name', nargs='?')
    parser.add_argument('--engine', default='libfuzzer')
    parser.add_argument(
        '--sanitizer',
        default="address",
        help='the default is "address"; "dataflow" for "dataflow" engine')
    parser.add_argument('--architecture', default='x86_64')
    parser.add_argument(
        '-e', action='append', help="set environment variable e.g. VAR=value")
    parser.add_argument('source_path', help='path of local source', nargs='?')
    parser.add_argument(
        '--clean',
        dest='clean',
        action='store_true',
        help='clean existing artifacts.')
    parser.add_argument(
        '--no-clean',
        dest='clean',
        action='store_false',
        help='do not clean existing artifacts '
        '(default).')
    parser.set_defaults(clean=False)

    for project_name, commit in test_data.items():
      self.build_image_with_commit(project_name, commit)
      args = parser.parse_args([project_name])

      # switch dirs for build_fuzzers call to run properly
      cur_dir = os.getcwd()
      os.chdir("..")
      build_fuzzers(args)
      os.chdir(cur_dir)
      self.assertEqual(check_build(args), 0)


def load_test_data():
  """ Loads the project names and commit SHAs into a dictionary"""

  with open(TEST_DATA_FILE) as data_file:
    for line in data_file.readlines():
      pairs = line.strip('\n').split(" ")
      test_data[pairs[0]] = pairs[1]


if __name__ == '__main__':
  load_test_data()
  unittest.main()
