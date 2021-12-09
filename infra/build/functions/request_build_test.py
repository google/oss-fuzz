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
import os
import sys
import unittest

from google.cloud import ndb

sys.path.append(os.path.dirname(__file__))
# pylint: disable=wrong-import-position

import datastore_entities
import request_build
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

  def test_get_build_steps_no_project(self):
    """Test for when project isn't available in datastore."""
    with ndb.Client().context():
      self.assertRaises(RuntimeError, request_build.get_build_steps,
                        'test-project', 'oss-fuzz', 'oss-fuzz-base')

  def test_build_history(self):
    """Testing build history."""
    with ndb.Client().context():
      datastore_entities.BuildsHistory(id='test-project-fuzzing',
                                       build_tag='fuzzing',
                                       project='test-project',
                                       build_ids=[str(i) for i in range(1, 65)
                                                 ]).put()
      request_build.update_build_history('test-project', '65', 'fuzzing')
      expected_build_ids = [str(i) for i in range(2, 66)]

      self.assertEqual(datastore_entities.BuildsHistory.query().get().build_ids,
                       expected_build_ids)

  def test_build_history_no_existing_project(self):
    """Testing build history when build history object is missing."""
    with ndb.Client().context():
      request_build.update_build_history('test-project', '1', 'fuzzing')
      expected_build_ids = ['1']

      self.assertEqual(datastore_entities.BuildsHistory.query().get().build_ids,
                       expected_build_ids)

  def test_get_project_data(self):
    """Testing get project data."""
    with ndb.Client().context():
      self.assertRaises(RuntimeError, request_build.get_project_data,
                        'test-project')

  @classmethod
  def tearDownClass(cls):
    test_utils.cleanup_emulator(cls.ds_emulator)


if __name__ == '__main__':
  unittest.main(exit=False)
