#!/usr/bin/env python
# Copyright 2023 Google LLC
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
"""Adds comments for PR to provide more information for approvers."""
import base64
import os

import requests
import yaml

OWNER = 'google'
REPO = 'oss-fuzz'
GITHUB_URL = 'https://github.com/'
BASE_URL = f'https://api.github.com/repos/{OWNER}/{REPO}'
BRANCH = 'master'


def get_projects_path(pr_number, headers):
  """Gets the current project path."""
  response = requests.get(f'{BASE_URL}/pulls/{pr_number}/files',
                          headers=headers)

  projects_path = set()
  for file in response.json():
    file_path = file['filename']
    dir_path = os.path.dirname(file_path)
    projects_path.add(dir_path)
  return list(projects_path)


def get_author_email(pr_number, headers):
  """Retrieves the author's email address for a pull request,
  including non-public emails."""
  commits_response = requests.get(f'{BASE_URL}/pulls/{pr_number}/commits',
                                  headers=headers)
  email = commits_response.json()[0]['commit']['author']['email']
  return email


def get_project_yaml(project_path, headers):
  """Gets the project yaml file."""
  project_response = requests.get(
      f'{BASE_URL}/contents/{project_path}/project.yaml', headers=headers)
  if project_response.status_code != 200:
    return None

  content = base64.b64decode(project_response.json()['content']).decode('UTF-8')
  return yaml.safe_load(content)


def has_author_modified_project(project_path, pr_author, headers):
  """Checks if the author has modified this project before."""
  commits_response = requests.get(
      f'{BASE_URL}/commits?path={project_path}&author={pr_author}',
      headers=headers)

  if commits_response.status_code != 200:
    return False

  commit = commits_response.json()[0]
  return True, commit['sha']


def get_pull_request_url(commit, headers):
  """Gets the pull request url."""
  pr_response = requests.get(f'{BASE_URL}/commits/{commit}/pulls',
                             headers=headers)
  if pr_response.status_code != 200:
    return None
  return pr_response.json()[0]['html_url']


def is_author_internal_member(pr_author):
  """Returns if the author is an internal member."""
  internal_members = []
  if pr_author in internal_members:
    save_env(None, None, True)
    return True
  return False


def save_env(message, is_ready_for_merge, is_internal=False):
  """Saves the outputs as environment variables."""
  with open(os.environ['GITHUB_ENV'], 'a') as github_env:
    github_env.write(f'MESSAGE={message}\n')
    github_env.write(f'IS_READY_FOR_MERGE={is_ready_for_merge}\n')
    github_env.write(f'IS_INTERNAL={is_internal}')


def main():
  """Verifies if a PR is ready for merge."""
  token = os.environ['GITHUBTOKEN']
  pr_author = os.environ['PRAUTHOR']
  pr_number = os.environ['PRNUMBER']
  headers = {
      'Authorization': f'Bearer {token}',
      'X-GitHub-Api-Version': '2022-11-28'
  }
  message = ''
  is_ready_for_merge = True

  # Bypasses PRs of the internal members.
  if is_author_internal_member(pr_author):
    return

  # Gets all modified projects path.
  projects_path = get_projects_path(pr_number, headers)
  email = get_author_email(pr_number, headers)

  for project_path in projects_path:
    project_url = f'{GITHUB_URL}/{OWNER}/{REPO}/tree/{BRANCH}/{project_path}'
    content_dict = get_project_yaml(project_path, headers)
    if content_dict is None:
      message += (f'@{pr_author} is integrating a new project. '
                  'The PR will be evaluated by the internal team '
                  'before it can be merged.<br/>')
      is_ready_for_merge = False
      continue

    primary_contact = content_dict['primary_contact']

    # Checks if the author is in contact list.
    if email == primary_contact or email in content_dict.get('auto_ccs'):
      message += (
          f'@{pr_author} is either the primary contact or '
          f'is in the auto CCs list for [{project_path}]({project_url}).<br/>')
      continue

    # Checks the previous commits.
    has_commit = has_author_modified_project(project_path, pr_author, headers)
    if not has_commit:
      message += (
          f'@{pr_author} is a new contributor to '
          f'[{project_path}]({project_url}). The PR must be approved by known '
          'contributors before it can be merged. '
          f'The primary contact is {primary_contact}.<br/>')
      is_ready_for_merge = False
      continue

    commit = has_commit[1]
    pr_message = (f'@{pr_author} has previously contributed to '
                  f'[{project_path}]({project_url}). The previous commit was '
                  f'{GITHUB_URL}/{OWNER}/{REPO}/commit/{commit}<br/>')

    pr_url = get_pull_request_url(commit, headers)
    if pr_url is not None:
      pr_message = (f'@{pr_author} has previously contributed to '
                    f'[{project_path}]({project_url}). '
                    f'The previous PR was {pr_url}<br/>')
    message += pr_message

  save_env(message, is_ready_for_merge, False)


if __name__ == '__main__':
  main()
