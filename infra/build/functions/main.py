#!/bin/bash -eu
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

import re

from github import Github
from google.cloud import ndb

VALID_PROJECT_NAME = re.compile(r'^[a-zA-Z0-9_-]+$')

class Project(ndb.Model):
  """Datastore Entity Project"""
  name = ndb.StringProperty()

class GitAuth(ndb.Model):
  """Datastore Entity GitAuth"""
  access_token = ndb.StringProperty()

def sync_projects(projects):
  """Sync projects with cloud datastore"""
  to_remove = [
      project for project in Project.query()
      if project.name not in projects
  ]

  for project in to_remove:
    project.key.delete()

  already_exist = {
      project.name for project in Project.query()
      if project.name in projects
    }

  for project in projects:
    if project not in already_exist:
      Project(name=project).put()

def _has_docker_file(repo, project_path):
  return any(content_file.name == "Dockerfile"
             for content_file in repo.get_contents(project_path))

def get_projects(repo):
  """get projects from git repo"""
  contents = repo.get_contents("projects")
  projects = {
      content_file.name
      for content_file in contents
      if content_file.type == "dir" and _has_docker_file(repo, content_file.path)
      and VALID_PROJECT_NAME.match(content_file.name)
  }
  return projects

def sync(event, context):
  """sync with cloud datastore"""
  client = ndb.Client()

  with client.context():
    token = iter(GitAuth.query()).next()
    access_token = token.access_token

  github_client = Github(access_token)
  repo = github_client.get_repo("google/oss-fuzz")
  projects = get_projects(repo)

  with client.context():
    sync_projects(projects)
