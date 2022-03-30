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
"""Unit tests for Cloud Function sync, which syncs the list of github projects
and uploads them to the Cloud Datastore."""

import os
import sys
import unittest

from google.cloud import ndb

sys.path.append(os.path.dirname(__file__))
# pylint: disable=wrong-import-position

from datastore_entities import Project
from project_sync import get_github_creds
from project_sync import get_projects
from project_sync import ProjectMetadata
from project_sync import sync_projects
import test_utils

# pylint: disable=no-member


# pylint: disable=too-few-public-methods
class Repository:
  """Mocking Github Repository."""

  def __init__(self, name, file_type, path, contents=None):
    self.contents = contents or []
    self.name = name
    self.type = file_type
    self.path = path
    self.decoded_content = b"name: test"

  def get_contents(self, path):
    """"Get contents of repository."""
    if self.path == path:
      return self.contents

    for content_file in self.contents:
      if content_file.path == path:
        return content_file.contents

    return None

  def set_yaml_contents(self, decoded_content):
    """Set yaml_contents."""
    self.decoded_content = decoded_content


class CloudSchedulerClient:
  """Mocking cloud scheduler client."""

  def __init__(self):
    self.schedulers = []

  # pylint: disable=no-self-use
  def location_path(self, project_id, location_id):
    """Return project path."""
    return f'projects/{project_id}/location/{location_id}'

  def create_job(self, parent, job):
    """Simulate create job."""
    del parent
    self.schedulers.append(job)

  def get_job(self, name):
    """Simulate get_job."""
    for scheduler in self.schedulers:
      if scheduler['name'] == name:
        return scheduler

    return None

  # pylint: disable=no-self-use
  def job_path(self, project_id, location_id, name):
    """Return job path."""
    return f'projects/{project_id}/location/{location_id}/jobs/{name}'

  def delete_job(self, name):
    """Simulate delete jobs."""
    for job in self.schedulers:
      if job['name'] == name:
        self.schedulers.remove(job)
        break

  def update_job(self, job, update_mask):
    """Simulate update jobs."""
    for existing_job in self.schedulers:
      if existing_job == job and 'schedule' in update_mask:
        job['schedule'] = update_mask['schedule']


class TestDataSync(unittest.TestCase):
  """Unit tests for sync."""

  @classmethod
  def setUpClass(cls):
    cls.ds_emulator = test_utils.start_datastore_emulator()
    test_utils.wait_for_emulator_ready(cls.ds_emulator, 'datastore',
                                       test_utils.DATASTORE_READY_INDICATOR)
    test_utils.set_gcp_environment()

  def setUp(self):
    test_utils.reset_ds_emulator()

  def test_sync_projects_update(self):
    """Testing sync_projects() updating a schedule."""
    cloud_scheduler_client = CloudSchedulerClient()

    with ndb.Client().context():
      Project(name='test1',
              schedule='0 8 * * *',
              project_yaml_contents='',
              dockerfile_contents='').put()
      Project(name='test2',
              schedule='0 9 * * *',
              project_yaml_contents='',
              dockerfile_contents='').put()

      projects = {
          'test1': ProjectMetadata('0 8 * * *', '', ''),
          'test2': ProjectMetadata('0 7 * * *', '', '')
      }
      sync_projects(cloud_scheduler_client, projects)

      projects_query = Project.query()
      self.assertEqual({
          'test1': '0 8 * * *',
          'test2': '0 7 * * *'
      }, {project.name: project.schedule for project in projects_query})

  def test_sync_projects_create(self):
    """"Testing sync_projects() creating new schedule."""
    cloud_scheduler_client = CloudSchedulerClient()

    with ndb.Client().context():
      Project(name='test1',
              schedule='0 8 * * *',
              project_yaml_contents='',
              dockerfile_contents='').put()

      projects = {
          'test1': ProjectMetadata('0 8 * * *', '', ''),
          'test2': ProjectMetadata('0 7 * * *', '', '')
      }
      sync_projects(cloud_scheduler_client, projects)

      projects_query = Project.query()
      self.assertEqual({
          'test1': '0 8 * * *',
          'test2': '0 7 * * *'
      }, {project.name: project.schedule for project in projects_query})

      self.assertCountEqual([
          {
              'name': 'projects/test-project/location/us-central1/jobs/'
                      'test1-scheduler-fuzzing',
              'pubsub_target': {
                  'topic_name': 'projects/test-project/topics/request-build',
                  'data': b'test1'
              },
              'schedule': '0 8 * * *'
          },
          {
              'name': 'projects/test-project/location/us-central1/jobs/'
                      'test1-scheduler-coverage',
              'pubsub_target': {
                  'topic_name':
                      'projects/test-project/topics/request-coverage-build',
                  'data':
                      b'test1'
              },
              'schedule': '0 6 * * *'
          },
          {
              'name': 'projects/test-project/location/us-central1/jobs/'
                      'test1-scheduler-introspector',
              'pubsub_target': {
                  'topic_name':
                      'projects/test-project/topics/request-introspector-build',
                  'data':
                      b'test1'
              },
              'schedule': '0 10 * * *'
          },
          {
              'name': 'projects/test-project/location/us-central1/jobs/'
                      'test2-scheduler-fuzzing',
              'pubsub_target': {
                  'topic_name': 'projects/test-project/topics/request-build',
                  'data': b'test2'
              },
              'schedule': '0 7 * * *'
          },
          {
              'name': 'projects/test-project/location/us-central1/jobs/'
                      'test2-scheduler-coverage',
              'pubsub_target': {
                  'topic_name':
                      'projects/test-project/topics/request-coverage-build',
                  'data':
                      b'test2'
              },
              'schedule': '0 6 * * *'
          },
          {
              'name': 'projects/test-project/location/us-central1/jobs/'
                      'test2-scheduler-introspector',
              'pubsub_target': {
                  'topic_name':
                      'projects/test-project/topics/request-introspector-build',
                  'data':
                      b'test2'
              },
              'schedule': '0 10 * * *'
          },
      ], cloud_scheduler_client.schedulers)

  def test_sync_projects_delete(self):
    """Testing sync_projects() deleting."""
    cloud_scheduler_client = CloudSchedulerClient()

    with ndb.Client().context():
      Project(name='test1',
              schedule='0 8 * * *',
              project_yaml_contents='',
              dockerfile_contents='').put()
      Project(name='test2',
              schedule='0 9 * * *',
              project_yaml_contents='',
              dockerfile_contents='').put()

      projects = {'test1': ProjectMetadata('0 8 * * *', '', '')}
      sync_projects(cloud_scheduler_client, projects)

      projects_query = Project.query()
      self.assertEqual(
          {'test1': '0 8 * * *'},
          {project.name: project.schedule for project in projects_query})

  def test_get_projects_yaml(self):
    """Testing get_projects() yaml get_schedule()."""

    repo = Repository('oss-fuzz', 'dir', 'projects', [
        Repository('test0', 'dir', 'projects/test0', [
            Repository('Dockerfile', 'file', 'projects/test0/Dockerfile'),
            Repository('project.yaml', 'file', 'projects/test0/project.yaml')
        ]),
        Repository('test1', 'dir', 'projects/test1', [
            Repository('Dockerfile', 'file', 'projects/test1/Dockerfile'),
            Repository('project.yaml', 'file', 'projects/test1/project.yaml')
        ])
    ])
    repo.contents[0].contents[1].set_yaml_contents(b'builds_per_day: 2')
    repo.contents[1].contents[1].set_yaml_contents(b'builds_per_day: 3')

    self.assertEqual(
        get_projects(repo), {
            'test0':
                ProjectMetadata('0 6,18 * * *', 'builds_per_day: 2',
                                'name: test'),
            'test1':
                ProjectMetadata('0 6,14,22 * * *', 'builds_per_day: 3',
                                'name: test')
        })

  def test_get_projects_no_docker_file(self):
    """Testing get_projects() with missing dockerfile"""

    repo = Repository('oss-fuzz', 'dir', 'projects', [
        Repository('test0', 'dir', 'projects/test0', [
            Repository('Dockerfile', 'file', 'projects/test0/Dockerfile'),
            Repository('project.yaml', 'file', 'projects/test0/project.yaml')
        ]),
        Repository('test1', 'dir', 'projects/test1')
    ])

    self.assertEqual(
        get_projects(repo),
        {'test0': ProjectMetadata('0 6 * * *', 'name: test', 'name: test')})

  def test_get_projects_invalid_project_name(self):
    """Testing get_projects() with invalid project name"""

    repo = Repository('oss-fuzz', 'dir', 'projects', [
        Repository('test0', 'dir', 'projects/test0', [
            Repository('Dockerfile', 'file', 'projects/test0/Dockerfile'),
            Repository('project.yaml', 'file', 'projects/test0/project.yaml')
        ]),
        Repository('test1@', 'dir', 'projects/test1', [
            Repository('Dockerfile', 'file', 'projects/test1/Dockerfile'),
            Repository('project.yaml', 'file', 'projects/test0/project.yaml')
        ])
    ])

    self.assertEqual(
        get_projects(repo),
        {'test0': ProjectMetadata('0 6 * * *', 'name: test', 'name: test')})

  def test_get_projects_non_directory_type_project(self):
    """Testing get_projects() when a file in projects/ is not of type 'dir'."""

    repo = Repository('oss-fuzz', 'dir', 'projects', [
        Repository('test0', 'dir', 'projects/test0', [
            Repository('Dockerfile', 'file', 'projects/test0/Dockerfile'),
            Repository('project.yaml', 'file', 'projects/test0/project.yaml')
        ]),
        Repository('test1', 'file', 'projects/test1')
    ])

    self.assertEqual(
        get_projects(repo),
        {'test0': ProjectMetadata('0 6 * * *', 'name: test', 'name: test')})

  def test_invalid_yaml_format(self):
    """Testing invalid yaml schedule parameter argument."""

    repo = Repository('oss-fuzz', 'dir', 'projects', [
        Repository('test0', 'dir', 'projects/test0', [
            Repository('Dockerfile', 'file', 'projects/test0/Dockerfile'),
            Repository('project.yaml', 'file', 'projects/test0/project.yaml')
        ])
    ])
    repo.contents[0].contents[1].set_yaml_contents(
        b'builds_per_day: some-string')

    self.assertEqual(get_projects(repo), {})

  def test_yaml_out_of_range(self):
    """Testing invalid yaml schedule parameter argument."""

    repo = Repository('oss-fuzz', 'dir', 'projects', [
        Repository('test0', 'dir', 'projects/test0', [
            Repository('Dockerfile', 'file', 'projects/test0/Dockerfile'),
            Repository('project.yaml', 'file', 'projects/test0/project.yaml')
        ])
    ])
    repo.contents[0].contents[1].set_yaml_contents(b'builds_per_day: 5')

    self.assertEqual(get_projects(repo), {})

  def test_get_github_creds(self):
    """Testing get_github_creds()."""
    with ndb.Client().context():
      self.assertRaises(RuntimeError, get_github_creds)

  @classmethod
  def tearDownClass(cls):
    test_utils.cleanup_emulator(cls.ds_emulator)


if __name__ == '__main__':
  unittest.main(exit=False)
