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
"""Unit tests for Cloud Function request builds which builds projects."""
import json
import datetime
import os
import sys
import unittest
from unittest import mock

from google.cloud import ndb

sys.path.append(os.path.dirname(__file__))
# pylint: disable=wrong-import-position

from datastore_entities import BuildsHistory
from datastore_entities import Project
from request_build import get_build_steps
from request_build import get_project_data
from request_build import update_build_history
import test_utils

# pylint: disable=no-member


class TestRequestBuilds(unittest.TestCase):
  """Unit tests for sync."""

  @classmethod
  def setUpClass(cls):
    cls.ds_emulator = test_utils.start_datastore_emulator()
    test_utils.wait_for_emulator_ready(cls.ds_emulator, 'datastore',
                                       test_utils.DATASTORE_READY_INDICATOR)
    test_utils.set_gcp_environment()

  def setUp(self):
    test_utils.reset_ds_emulator()
    self.maxDiff = None  # pylint: disable=invalid-name

  @mock.patch('build_lib.get_signed_url', return_value='test_url')
  @mock.patch('datetime.datetime')
  def test_get_build_steps(self, mocked_url, mocked_time):
    """Test for get_build_steps."""
    del mocked_url, mocked_time
    datetime.datetime = test_utils.SpoofedDatetime
    project_yaml_contents = ('language: c++\n'
                             'sanitizers:\n'
                             '  - address\n'
                             'architectures:\n'
                             '  - x86_64\n')
    image_project = 'oss-fuzz'
    base_images_project = 'oss-fuzz-base'
    testcase_path = os.path.join(os.path.dirname(__file__),
                                 'expected_build_steps.json')
    with open(testcase_path) as testcase_file:
      expected_build_steps = json.load(testcase_file)

    with ndb.Client().context():
      Project(name='test-project',
              project_yaml_contents=project_yaml_contents,
              dockerfile_contents='test line').put()
      build_steps = get_build_steps('test-project', image_project,
                                    base_images_project)
    self.assertEqual(build_steps, expected_build_steps)

  def test_get_build_steps_no_project(self):
    """Test for when project isn't available in datastore."""
    with ndb.Client().context():
      self.assertRaises(RuntimeError, get_build_steps, 'test-project',
                        'oss-fuzz', 'oss-fuzz-base')

  def test_build_history(self):
    """Testing build history."""
    with ndb.Client().context():
      BuildsHistory(id='test-project-fuzzing',
                    build_tag='fuzzing',
                    project='test-project',
                    build_ids=[str(i) for i in range(1, 65)]).put()
      update_build_history('test-project', '65', 'fuzzing')
      expected_build_ids = [str(i) for i in range(2, 66)]

      self.assertEqual(BuildsHistory.query().get().build_ids,
                       expected_build_ids)

  def test_build_history_no_existing_project(self):
    """Testing build history when build history object is missing."""
    with ndb.Client().context():
      update_build_history('test-project', '1', 'fuzzing')
      expected_build_ids = ['1']

      self.assertEqual(BuildsHistory.query().get().build_ids,
                       expected_build_ids)

  def test_get_project_data(self):
    """Testing get project data."""
    with ndb.Client().context():
      self.assertRaises(RuntimeError, get_project_data, 'test-project')

  @classmethod
  def tearDownClass(cls):
    test_utils.cleanup_emulator(cls.ds_emulator)


if __name__ == '__main__':
  unittest.main(exit=False)
