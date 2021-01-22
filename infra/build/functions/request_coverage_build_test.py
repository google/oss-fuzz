# Copyright 2020 Google Inc.
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
"""Unit tests for Cloud Function that builds coverage reports."""
import json
import datetime
import os
import sys
import unittest
from unittest import mock

from google.cloud import ndb

sys.path.append(os.path.dirname(__file__))
# pylint: disable=wrong-import-position

from datastore_entities import Project
from build_and_run_coverage import get_build_steps
import test_utils

# pylint: disable=no-member


class TestRequestCoverageBuilds(unittest.TestCase):
  """Unit tests for sync."""

  @classmethod
  def setUpClass(cls):
    cls.ds_emulator = test_utils.start_datastore_emulator()
    test_utils.wait_for_emulator_ready(cls.ds_emulator, 'datastore',
                                       test_utils.DATASTORE_READY_INDICATOR)
    test_utils.set_gcp_environment()

  def setUp(self):
    test_utils.reset_ds_emulator()

  @mock.patch('build_lib.get_signed_url', return_value='test_url')
  @mock.patch('build_lib.download_corpora_steps',
              return_value=[{
                  'url': 'test_download'
              }])
  @mock.patch('datetime.datetime')
  def test_get_coverage_build_steps(self, mocked_url, mocked_corpora_steps,
                                    mocked_time):
    """Test for get_build_steps."""
    del mocked_url, mocked_corpora_steps, mocked_time
    datetime.datetime = test_utils.SpoofedDatetime
    project_yaml_contents = ('language: c++\n'
                             'sanitizers:\n'
                             '  - address\n'
                             'architectures:\n'
                             '  - x86_64\n')
    dockerfile_contents = 'test line'
    image_project = 'oss-fuzz'
    base_images_project = 'oss-fuzz-base'
    testcase_path = os.path.join(os.path.dirname(__file__),
                                 'expected_coverage_build_steps.json')
    with open(testcase_path) as testcase_file:
      expected_coverage_build_steps = json.load(testcase_file)

    with ndb.Client().context():
      Project(name='test-project',
              project_yaml_contents=project_yaml_contents,
              dockerfile_contents=dockerfile_contents).put()

    dockerfile_lines = dockerfile_contents.split('\n')
    build_steps = get_build_steps('test-project', project_yaml_contents,
                                  dockerfile_lines, image_project,
                                  base_images_project)
    self.assertEqual(build_steps, expected_coverage_build_steps)

  @classmethod
  def tearDownClass(cls):
    test_utils.cleanup_emulator(cls.ds_emulator)


if __name__ == '__main__':
  unittest.main(exit=False)
