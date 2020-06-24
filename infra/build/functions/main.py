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

from github import Github
from google.cloud import ndb

VALID_PROJECT_NAME = re.compile(r'^[a-zA-Z0-9_-]+$')


# pylint: disable=too-few-public-methods
class Project(ndb.Model):
  """Represents an integrated OSS-Fuzz project."""
  name = ndb.StringProperty()


# pylint: disable=too-few-public-methods
class GitAuth(ndb.Model):
  """Represents Github access token entity."""
  access_token = ndb.StringProperty()


def sync_projects(projects):
  """Sync projects with cloud datastore."""
  project_query = Project.query()
  projects_to_remove = [
      project.key for project in project_query if project.name not in projects
  ]

  ndb.delete_multi(projects_to_remove)

  existing_projects = {project.name for project in project_query}

  new_projects = [
      Project(name=project)
      for project in projects
      if project not in existing_projects
  ]
  ndb.put_multi(new_projects)


def _has_docker_file(repo, project_path):
  """Checks if project has a Dockerfile."""
  return any(content_file.name == 'Dockerfile'
             for content_file in repo.get_contents(project_path))


def get_projects(repo):
  """Get project list from git repository."""
  contents = repo.get_contents('projects')
  projects = {
      content_file.name
      for content_file in contents
      if content_file.type == 'dir' and
      _has_docker_file(repo, content_file.path) and
      VALID_PROJECT_NAME.match(content_file.name)
  }
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

    sync_projects(projects)
