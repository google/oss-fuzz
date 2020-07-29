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
"""Unit tests for Cloud Function update builds status."""
import unittest
from unittest import mock

import test_utils
import update_build_status


# pylint: disable=too-few-public-methods
class SpoofedGetBuild:
  """Spoofing get_builds function."""

  def __init__(self, builds):
    self.builds = builds

  def get_build(self, cloudbuild, image_project, build_id):
    """Mimic build object retrieval."""
    del cloudbuild, image_project
    for build in self.builds:
      if build['build_id'] == build_id:
        return build

    return None


@mock.patch('google.auth.default', return_value=['temp', 'temp'])
@mock.patch('update_build_status.build', return_value='cloudbuild')
@mock.patch('builds_status.upload_log')
class TestGetBuildHistory(unittest.TestCase):
  """Unit tests for get_build_history."""

  @classmethod
  def setUpClass(cls):
    cls.ds_emulator = test_utils.start_datastore_emulator()
    test_utils.wait_for_emulator_ready(cls.ds_emulator, 'datastore',
                                       test_utils.DATASTORE_READY_INDICATOR)
    test_utils.set_gcp_environment()

  def setUp(self):
    test_utils.reset_ds_emulator()

  def test_get_build_history(self, mocked_upload_log, mocked_cloud_build,
                             mocked_get_build):
    """Test for get_build_steps."""
    del mocked_cloud_build, mocked_get_build
    mocked_upload_log.return_value = True
    builds = [{'build_id': '1', 'finishTime': 'test_time', 'status': 'SUCCESS'}]
    spoofed_get_build = SpoofedGetBuild(builds)
    update_build_status.get_build = spoofed_get_build.get_build

    expected_projects = {
        'history': [{
            'build_id': '1',
            'finish_time': 'test_time',
            'success': True
        }],
        'last_successful_build': {
            'build_id': '1',
            'finish_time': 'test_time'
        }
    }
    self.assertDictEqual(update_build_status.get_build_history(['1']),
                         expected_projects)

  def test_get_build_history_missing_log(self, mocked_upload_log,
                                         mocked_cloud_build, mocked_get_build):
    """Test for missing build log file."""
    del mocked_cloud_build, mocked_get_build
    builds = [{'build_id': '1', 'finishTime': 'test_time', 'status': 'SUCCESS'}]
    spoofed_get_build = SpoofedGetBuild(builds)
    update_build_status.get_build = spoofed_get_build.get_build
    mocked_upload_log.return_value = False
    self.assertRaises(update_build_status.MissingBuildLogError,
                      update_build_status.get_build_history, ['1'])

  def test_get_build_history_no_last_success(self, mocked_upload_log,
                                             mocked_cloud_build,
                                             mocked_get_build):
    """Test when there is no last successful build."""
    del mocked_cloud_build, mocked_get_build
    builds = [{'build_id': '1', 'finishTime': 'test_time', 'status': 'FAILED'}]
    spoofed_get_build = SpoofedGetBuild(builds)
    update_build_status.get_build = spoofed_get_build.get_build
    mocked_upload_log.return_value = True

    expected_projects = {
        'history': [{
            'build_id': '1',
            'finish_time': 'test_time',
            'success': False
        }]
    }
    self.assertDictEqual(update_build_status.get_build_history(['1']),
                         expected_projects)

  @classmethod
  def tearDownClass(cls):
    test_utils.cleanup_emulator(cls.ds_emulator)


class TestSortProjects(unittest.TestCase):
  """Unit tests for testing sorting functionality."""

  def test_sort_projects(self):
    """Test sorting functionality."""
    projects = [{'name': '1'}, {'name': '2'}, {'name': '3'}]
    statuses = {'2': True, '3': False}
    expected_order = ['3', '2', '1']
    sorted_projects = update_build_status.sort_projects(projects, statuses)
    self.assertEqual(expected_order,
                     [project['name'] for project in sorted_projects])


if __name__ == '__main__':
  unittest.main(exit=False)
