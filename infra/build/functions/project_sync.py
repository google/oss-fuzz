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
"""Cloud functions for build scheduling."""

from collections import namedtuple
import logging
import os
import re
import yaml

from github import Github
from google.api_core import exceptions
from google.cloud import ndb
from google.cloud import scheduler_v1

import build_and_run_coverage
import build_project
from datastore_entities import GithubCreds
from datastore_entities import Project

VALID_PROJECT_NAME = re.compile(r'^[a-zA-Z0-9_-]+$')
DEFAULT_BUILDS_PER_DAY = 1
MAX_BUILDS_PER_DAY = 4
COVERAGE_SCHEDULE = '0 6 * * *'
INTROSPECTOR_SCHEDULE = '0 10 * * *'
FUZZING_BUILD_TOPIC = 'request-build'
COVERAGE_BUILD_TOPIC = 'request-coverage-build'
INTROSPECTOR_BUILD_TOPIC = 'request-introspector-build'

ProjectMetadata = namedtuple(
    'ProjectMetadata', 'schedule project_yaml_contents dockerfile_contents')

logging.basicConfig(level=logging.INFO)


class ProjectYamlError(Exception):
  """Error in project.yaml format."""


def create_scheduler(cloud_scheduler_client, project_name, schedule, tag,
                     topic):
  """Creates schedulers for new projects."""
  project_id = os.environ.get('GCP_PROJECT')
  location_id = os.environ.get('FUNCTION_REGION')
  parent = cloud_scheduler_client.location_path(project_id, location_id)
  job = {
      'name': parent + '/jobs/' + project_name + '-scheduler-' + tag,
      'pubsub_target': {
          'topic_name': 'projects/' + project_id + '/topics/' + topic,
          'data': project_name.encode()
      },
      'schedule': schedule
  }

  try:
    existing_job = cloud_scheduler_client.get_job(job['name'])
  except exceptions.NotFound:
    existing_job = None

  if existing_job:
    if existing_job.schedule != schedule:
      update_mask = {'paths': ['schedule']}
      cloud_scheduler_client.update_job(job, update_mask)
  else:
    cloud_scheduler_client.create_job(parent, job)


def delete_scheduler(cloud_scheduler_client, project_name, tag):
  """Deletes schedulers for projects that were removed."""
  project_id = os.environ.get('GCP_PROJECT')
  location_id = os.environ.get('FUNCTION_REGION')
  name = cloud_scheduler_client.job_path(project_id, location_id,
                                         project_name + '-scheduler-' + tag)
  cloud_scheduler_client.delete_job(name)


def delete_project(cloud_scheduler_client, project):
  """Delete the given project."""
  logging.info('Deleting project %s', project.name)
  for tag in (build_project.FUZZING_BUILD_TYPE,
              build_and_run_coverage.COVERAGE_BUILD_TYPE,
              build_and_run_coverage.INTROSPECTOR_BUILD_TYPE):
    try:
      delete_scheduler(cloud_scheduler_client, project.name, tag)
    except exceptions.NotFound:
      # Already deleted.
      continue
    except exceptions.GoogleAPICallError as error:
      logging.error('Scheduler deletion for %s failed with %s', project.name,
                    error)
      return

  project.key.delete()


# pylint: disable=too-many-branches
def sync_projects(cloud_scheduler_client, projects):
  """Sync projects with cloud datastore."""
  for project in Project.query():
    if project.name not in projects:
      delete_project(cloud_scheduler_client, project)

  existing_projects = {project.name for project in Project.query()}
  for project_name in projects:
    try:
      create_scheduler(cloud_scheduler_client, project_name,
                       projects[project_name].schedule,
                       build_project.FUZZING_BUILD_TYPE, FUZZING_BUILD_TOPIC)
      create_scheduler(cloud_scheduler_client, project_name, COVERAGE_SCHEDULE,
                       build_and_run_coverage.COVERAGE_BUILD_TYPE,
                       COVERAGE_BUILD_TOPIC)
      create_scheduler(cloud_scheduler_client, project_name,
                       INTROSPECTOR_SCHEDULE,
                       build_and_run_coverage.INTROSPECTOR_BUILD_TYPE,
                       INTROSPECTOR_BUILD_TOPIC)
    except exceptions.GoogleAPICallError as error:
      logging.error('Scheduler creation for %s failed with %s', project_name,
                    error)
      continue

    if project_name in existing_projects:
      continue

    project_metadata = projects[project_name]
    Project(name=project_name,
            schedule=project_metadata.schedule,
            project_yaml_contents=project_metadata.project_yaml_contents,
            dockerfile_contents=project_metadata.dockerfile_contents).put()

  for project in Project.query():
    if project.name not in projects:
      continue

    logging.info('Setting up project %s', project.name)
    project_metadata = projects[project.name]
    project_changed = False
    if project.schedule != project_metadata.schedule:
      try:
        logging.info('Schedule changed.')
        project.schedule = project_metadata.schedule
        project_changed = True
      except exceptions.GoogleAPICallError as error:
        logging.error('Updating scheduler for %s failed with %s', project.name,
                      error)
    if project.project_yaml_contents != project_metadata.project_yaml_contents:
      project.project_yaml_contents = project_metadata.project_yaml_contents
      project_changed = True

    if project.dockerfile_contents != project_metadata.dockerfile_contents:
      project.dockerfile_contents = project_metadata.dockerfile_contents
      project_changed = True

    if project_changed:
      project.put()


def _has_docker_file(project_contents):
  """Checks if project has a Dockerfile."""
  return any(
      content_file.name == 'Dockerfile' for content_file in project_contents)


def get_project_metadata(project_contents):
  """Checks for schedule parameter in yaml file else uses DEFAULT_SCHEDULE."""
  for content_file in project_contents:
    if content_file.name == 'project.yaml':
      project_yaml_contents = content_file.decoded_content.decode('utf-8')

    if content_file.name == 'Dockerfile':
      dockerfile_contents = content_file.decoded_content.decode('utf-8')

  project_yaml = yaml.safe_load(project_yaml_contents)
  builds_per_day = project_yaml.get('builds_per_day', DEFAULT_BUILDS_PER_DAY)
  if not isinstance(builds_per_day, int) or builds_per_day not in range(
      1, MAX_BUILDS_PER_DAY + 1):
    raise ProjectYamlError('Parameter is not an integer in range [1-4]')

  # Starting at 6:00 am, next build schedules are added at 'interval' slots
  # Example for interval 2, hours = [6, 18] and schedule = '0 6,18 * * *'
  interval = 24 // builds_per_day
  hours = []
  for hour in range(6, 30, interval):
    hours.append(hour % 24)
  schedule = '0 ' + ','.join(str(hour) for hour in hours) + ' * * *'

  return ProjectMetadata(schedule, project_yaml_contents, dockerfile_contents)


def get_projects(repo):
  """Get project list from git repository."""
  projects = {}
  contents = repo.get_contents('projects')
  for content_file in contents:
    if content_file.type != 'dir' or not VALID_PROJECT_NAME.match(
        content_file.name):
      continue

    project_contents = repo.get_contents(content_file.path)
    if not _has_docker_file(project_contents):
      continue

    try:
      projects[content_file.name] = get_project_metadata(project_contents)
    except ProjectYamlError as error:
      logging.error(
          'Incorrect format for project.yaml file of %s with error %s',
          content_file.name, error)

  return projects


def get_github_creds():
  """Retrieves GitHub client credentials."""
  git_creds = GithubCreds.query().get()
  if git_creds is None:
    raise RuntimeError('Git credentials not available.')
  return git_creds


def sync(event, context):
  """Sync projects with cloud datastore."""
  del event, context  # Unused.

  with ndb.Client().context():
    git_creds = get_github_creds()
    github_client = Github(git_creds.client_id, git_creds.client_secret)
    repo = github_client.get_repo('google/oss-fuzz')
    projects = get_projects(repo)
    cloud_scheduler_client = scheduler_v1.CloudSchedulerClient()
    sync_projects(cloud_scheduler_client, projects)
