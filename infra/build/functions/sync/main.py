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

import re
import os
import yaml

from github import Github
from google.cloud import ndb
from google.cloud import scheduler_v1
from google.api_core import exceptions

VALID_PROJECT_NAME = re.compile(r'^[a-zA-Z0-9_-]+$')
DEFAULT_SCHEDULE = '0 6 * * *'


# pylint: disable=too-few-public-methods
class Project(ndb.Model):
  """Represents an integrated OSS-Fuzz project."""
  name = ndb.StringProperty()
  schedule = ndb.StringProperty()


# pylint: disable=too-few-public-methods
class GitAuth(ndb.Model):
  """Represents Github access token entity."""
  access_token = ndb.StringProperty()


def create_scheduler(cloud_scheduler_client, project_name, schedule):
  """Creates schedulers for new projects."""
  project_id = os.environ.get('GCP_PROJECT')
  location_id = os.environ.get('FUNCTION_REGION')
  parent = cloud_scheduler_client.location_path(project_id, location_id)
  job = {
      'name': parent + '/jobs/' + project_name + '-scheduler',
      'pubsub_target': {
          'topic_name': 'projects/' + project_id + '/topics/request-build',
          'data': bytes(project_name, 'utf-8')
      },
      'schedule': schedule
  }

  try:
    cloud_scheduler_client.create_job(parent, job)
    return True

  except exceptions.GoogleAPICallError as error:
    print(error.message)

  except exceptions.RetryError as error:
    print(error.message)

  except ValueError:
    print("Incorrect parameters passed")

  return False


def delete_schedulers(cloud_scheduler_client, project_list):
  """Deletes schedulers for projects that were removed."""
  project_id = os.environ.get('GCP_PROJECT')
  location_id = os.environ.get('FUNCTION_REGION')
  for project in project_list:
    name = cloud_scheduler_client.job_path(project_id, location_id,
                                           project + '-scheduler')
    try:
      cloud_scheduler_client.delete_job(name)
    except exceptions.GoogleAPICallError as error:
      print(error.message)

    except exceptions.RetryError as error:
      print(error.message)

    except ValueError:
      print("Incorrect parameters passed")


def update_scheduler(cloud_scheduler_client, project, schedule):
  """Updates schedule in case schedule was changed."""
  project_id = os.environ.get('GCP_PROJECT')
  location_id = os.environ.get('FUNCTION_REGION')
  parent = cloud_scheduler_client.location_path(project_id, location_id)
  job = {
      'name': parent + '/jobs/' + project.name + '-scheduler',
      'pubsub_target': {
          'topic_name': 'projects/' + project_id + '/topics/request-build',
          'data': bytes(project.name, 'utf-8')
      },
      'schedule': project.schedule
  }

  update_mask = {'schedule': schedule}

  try:
    cloud_scheduler_client.update(job, update_mask)

  except exceptions.GoogleAPICallError as error:
    print(error.message)

  except exceptions.RetryError as error:
    print(error.message)

  except ValueError:
    print("Incorrect parameters passed")


def sync_projects(cloud_scheduler_client, projects):
  """Sync projects with cloud datastore."""
  project_query = Project.query()
  projects_to_remove = [
      project.key for project in project_query if project.name not in projects
  ]
  schedulers_to_remove = [
      project.name for project in project_query if project.name not in projects
  ]

  ndb.delete_multi(projects_to_remove)
  delete_schedulers(cloud_scheduler_client, schedulers_to_remove)

  existing_projects = {project.name for project in project_query}

  new_projects = [
      Project(name=project_name, schedule=projects[project_name])
      for project_name in projects
      if project_name not in existing_projects
  ]

  for project_name in projects:
    if project_name not in existing_projects:
      create_scheduler(cloud_scheduler_client, project_name,
                       projects[project_name])

  ndb.put_multi(new_projects)

  for project in project_query:
    if project.name in projects and project.schedule != projects[project.name]:
      update_scheduler(cloud_scheduler_client, project, projects[project.name])
      project.schedule = projects[project.name]
      project.put()


def _has_docker_file(project_contents):
  """Checks if project has a Dockerfile."""
  return any(
      content_file.name == 'Dockerfile' for content_file in project_contents)


def get_schedule(project_contents):
  """Checks for schedule parameter in yaml file else uses DEFAULT_SCHEDULE."""
  for content_file in project_contents:
    if content_file.name == 'project.yaml':
      yaml_str = content_file.decoded_content.decode('utf-8')
      project_yaml = yaml.safe_load(yaml_str)
      if 'schedule' not in project_yaml:
        schedule = DEFAULT_SCHEDULE
      else:
        times_per_day = int(project_yaml['schedule'])
        interval = 24 // times_per_day
        hours = []
        for hour in range(6, 30, interval):
          hours.append(hour % 24)
        schedule = '0 ' + ','.join(str(hour) for hour in hours) + ' * * *'

  return schedule


def get_projects(repo):
  """Get project list from git repository."""
  projects = {}
  contents = repo.get_contents('projects')
  for content_file in contents:
    if content_file.type == 'dir' and VALID_PROJECT_NAME.match(
        content_file.name):
      project_contents = repo.get_contents(content_file.path)
      if _has_docker_file(project_contents):
        projects[content_file.name] = get_schedule(project_contents)

  return projects


def get_access_token():
  """Retrieves Github's Access token from Cloud Datastore."""
  token = GitAuth.query().get()
  if token is None:
    raise RuntimeError('No access token available')
  return token.access_token


def sync(event, context):
  """Sync projects with cloud datastore."""
  del event, context  #unused
  client = ndb.Client()

  with client.context():
    github_client = Github(get_access_token())
    repo = github_client.get_repo('google/oss-fuzz')
    projects = get_projects(repo)
    cloud_scheduler_client = scheduler_v1.CloudSchedulerClient()
    sync_projects(cloud_scheduler_client, projects)
