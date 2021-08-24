# Copyright 2021 Google LLC
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
#
################################################################################
"""Unit tests for build_project."""
import json
import datetime
import os
import sys
import unittest
from unittest import mock

from pyfakefs import fake_filesystem_unittest

FUNCTIONS_DIR = os.path.dirname(__file__)
sys.path.append(FUNCTIONS_DIR)
# pylint: disable=wrong-import-position

import build_project
import test_utils

# pylint: disable=no-member

PROJECTS_DIR = os.path.join(test_utils.OSS_FUZZ_DIR, 'projects')


class TestRequestCoverageBuilds(fake_filesystem_unittest.TestCase):
  """Unit tests for sync."""

  def setUp(self):
    self.maxDiff = None  # pylint: disable=invalid-name
    self.setUpPyfakefs()

  @mock.patch('build_lib.get_signed_url', return_value='test_url')
  @mock.patch('datetime.datetime')
  def test_get_build_steps(self, mock_url, mock_time):
    """Test for get_build_steps."""
    del mock_url, mock_time
    datetime.datetime = test_utils.SpoofedDatetime
    project_yaml_contents = ('language: c++\n'
                             'sanitizers:\n'
                             '  - address\n'
                             '  - memory\n'
                             '  - undefined\n'
                             'architectures:\n'
                             '  - x86_64\n'
                             '  - i386\n')
    project = 'test-project'
    project_dir = os.path.join(PROJECTS_DIR, project)
    self.fs.create_file(os.path.join(project_dir, 'project.yaml'),
                        contents=project_yaml_contents)
    dockerfile_contents = 'test line'
    self.fs.create_file(os.path.join(project_dir, 'Dockerfile'),
                        contents=dockerfile_contents)

    image_project = 'oss-fuzz'
    base_images_project = 'oss-fuzz-base'

    expected_build_steps_file_path = test_utils.get_test_data_file_path(
        'expected_build_steps.json')

    self.fs.add_real_file(expected_build_steps_file_path)
    with open(expected_build_steps_file_path) as expected_build_steps_file:
      expected_build_steps = json.load(expected_build_steps_file)

    config = build_project.Config(False, False, None, False)
    build_steps = build_project.get_build_steps(project, image_project,
                                                base_images_project, config)
    self.assertEqual(build_steps, expected_build_steps)


if __name__ == '__main__':
  unittest.main(exit=False)
