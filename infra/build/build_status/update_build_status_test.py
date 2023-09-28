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
import os
import sys
import unittest
from unittest import mock

from google.cloud import ndb

sys.path.append(os.path.dirname(__file__))
# pylint: disable=wrong-import-position

import datastore_entities
import test_utils
import update_build_status

# pylint: disable=no-member


# pylint: disable=too-few-public-methods
class MockGetBuild:
  """Spoofing get_builds function."""

  def __init__(self, builds):
    self.builds = builds

  def get_build(self, build_id):
    """Mimic build object retrieval."""
    for build in self.builds:
      if build['build_id'] == build_id:
        return build

    return None


@mock.patch('google.auth.default', return_value=['temp', 'temp'])
@mock.patch('update_build_status.build', return_value='cloudbuild')
@mock.patch('update_build_status.upload_log')
class TestGetBuildHistory(unittest.TestCase):
  """Unit tests for get_build_history."""

  def test_get_build_history(self, mock_upload_log, mock_cloud_build,
                             mock_google_auth):
    """Test for get_build_steps."""
    del mock_cloud_build, mock_google_auth
    mock_upload_log.return_value = True
    builds = [{'build_id': '1', 'finishTime': 'test_time', 'status': 'SUCCESS'}]
    mock_get_build = MockGetBuild(builds)
    update_build_status.BuildGetter.get_build = mock_get_build.get_build

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

  def test_get_build_history_no_last_success(self, mock_upload_log,
                                             mock_cloud_build,
                                             mock_google_auth):
    """Test when there is no last successful build."""
    del mock_cloud_build, mock_google_auth
    builds = [{'build_id': '1', 'finishTime': 'test_time', 'status': 'FAILURE'}]
    mock_get_build = MockGetBuild(builds)
    update_build_status.BuildGetter.get_build = mock_get_build.get_build
    mock_upload_log.return_value = True

    expected_projects = {
        'history': [{
            'build_id': '1',
            'finish_time': 'test_time',
            'success': False
        }]
    }
    self.assertDictEqual(update_build_status.get_build_history(['1']),
                         expected_projects)


class TestSortProjects(unittest.TestCase):
  """Unit tests for testing sorting functionality."""

  def test_sort_projects(self):
    """Test sorting functionality."""
    projects = [{
        'name': '1',
        'history': []
    }, {
        'name': '2',
        'history': [{
            'success': True
        }]
    }, {
        'name': '3',
        'history': [{
            'success': False
        }]
    }]
    expected_order = ['3', '2', '1']
    update_build_status.sort_projects(projects)
    self.assertEqual(expected_order, [project['name'] for project in projects])


class TestUpdateLastSuccessfulBuild(unittest.TestCase):
  """Unit tests for updating last successful build."""

  @classmethod
  def setUpClass(cls):
    cls.ds_emulator = test_utils.start_datastore_emulator()
    test_utils.wait_for_emulator_ready(cls.ds_emulator, 'datastore',
                                       test_utils.DATASTORE_READY_INDICATOR)
    test_utils.set_gcp_environment()

  def setUp(self):
    test_utils.reset_ds_emulator()

  def test_update_last_successful_build_new(self):
    """When last successful build isn't available in datastore."""
    with ndb.Client().context():
      project = {
          'name': 'test-project',
          'last_successful_build': {
              'build_id': '1',
              'finish_time': 'test_time'
          }
      }
      update_build_status.update_last_successful_build(project, 'fuzzing')
      expected_build_id = '1'
      self.assertEqual(
          expected_build_id,
          ndb.Key(datastore_entities.LastSuccessfulBuild,
                  'test-project-fuzzing').get().build_id)

  def test_update_last_successful_build_datastore(self):
    """When last successful build is only available in datastore."""
    with ndb.Client().context():
      project = {'name': 'test-project'}
      datastore_entities.LastSuccessfulBuild(id='test-project-fuzzing',
                                             build_tag='fuzzing',
                                             project='test-project',
                                             build_id='1',
                                             finish_time='test_time').put()

      update_build_status.update_last_successful_build(project, 'fuzzing')
      expected_project = {
          'name': 'test-project',
          'last_successful_build': {
              'build_id': '1',
              'finish_time': 'test_time'
          }
      }
      self.assertDictEqual(project, expected_project)

  def test_update_last_successful_build(self):
    """When last successful build is available at both places."""
    with ndb.Client().context():
      project = {
          'name': 'test-project',
          'last_successful_build': {
              'build_id': '2',
              'finish_time': 'test_time'
          }
      }
      datastore_entities.LastSuccessfulBuild(id='test-project-fuzzing',
                                             build_tag='fuzzing',
                                             project='test-project',
                                             build_id='1',
                                             finish_time='test_time').put()

      update_build_status.update_last_successful_build(project, 'fuzzing')
      expected_build_id = '2'
      self.assertEqual(
          expected_build_id,
          ndb.Key(datastore_entities.LastSuccessfulBuild,
                  'test-project-fuzzing').get().build_id)

  @classmethod
  def tearDownClass(cls):
    test_utils.cleanup_emulator(cls.ds_emulator)


class TestUpdateBuildStatus(unittest.TestCase):
  """Unit test for update build status."""

  @classmethod
  def setUpClass(cls):
    cls.ds_emulator = test_utils.start_datastore_emulator()
    test_utils.wait_for_emulator_ready(cls.ds_emulator, 'datastore',
                                       test_utils.DATASTORE_READY_INDICATOR)
    test_utils.set_gcp_environment()

  def setUp(self):
    test_utils.reset_ds_emulator()

  # pylint: disable=no-self-use
  @mock.patch('google.auth.default', return_value=['temp', 'temp'])
  @mock.patch('update_build_status.build', return_value='cloudbuild')
  @mock.patch('update_build_status.upload_log')
  def test_update_build_status(self, mock_upload_log, mock_cloud_build,
                               mock_google_auth):
    """Testing update build status as a whole."""
    del self, mock_cloud_build, mock_google_auth
    update_build_status.upload_status = mock.MagicMock()
    mock_upload_log.return_value = True
    status_filename = 'status.json'
    with ndb.Client().context():
      datastore_entities.Project(
          name='test-project-1',
          project_yaml_contents=(
              'main_repo: "https://github/com/main/repo1"')).put()
      datastore_entities.Project(
          name='test-project-2',
          project_yaml_contents=(
              'main_repo: "https://github/com/main/repo2"')).put()
      datastore_entities.Project(
          name='test-project-3',
          project_yaml_contents=(
              'main_repo: "https://github/com/main/repo3"')).put()

      datastore_entities.BuildsHistory(id='test-project-1-fuzzing',
                                       build_tag='fuzzing',
                                       project='test-project-1',
                                       build_ids=['1']).put()

      datastore_entities.BuildsHistory(id='test-project-2-fuzzing',
                                       build_tag='fuzzing',
                                       project='test-project-2',
                                       build_ids=['2']).put()

      datastore_entities.BuildsHistory(id='test-project-3-fuzzing',
                                       build_tag='fuzzing',
                                       project='test-project-3',
                                       build_ids=['3']).put()

      builds = [{
          'build_id': '1',
          'finishTime': 'test_time',
          'status': 'SUCCESS'
      }, {
          'build_id': '2',
          'finishTime': 'test_time',
          'status': 'FAILURE'
      }, {
          'build_id': '3',
          'status': 'WORKING'
      }]
      mock_get_build = MockGetBuild(builds)
      update_build_status.BuildGetter.get_build = mock_get_build.get_build

      expected_data = {
          'projects': [{
              'history': [{
                  'build_id': '2',
                  'finish_time': 'test_time',
                  'success': False
              }],
              'name': 'test-project-2',
              'main_repo': 'https://github/com/main/repo2',
          }, {
              'history': [{
                  'build_id': '1',
                  'finish_time': 'test_time',
                  'success': True
              }],
              'last_successful_build': {
                  'build_id': '1',
                  'finish_time': 'test_time'
              },
              'name': 'test-project-1',
              'main_repo': 'https://github/com/main/repo1',
          }, {
              'history': [],
              'name': 'test-project-3',
              'main_repo': 'https://github/com/main/repo3',
          }]
      }

      update_build_status.update_build_status('fuzzing', 'status.json')
      update_build_status.upload_status.assert_called_with(
          expected_data, status_filename)

  @classmethod
  def tearDownClass(cls):
    test_utils.cleanup_emulator(cls.ds_emulator)


if __name__ == '__main__':
  unittest.main(exit=False)
