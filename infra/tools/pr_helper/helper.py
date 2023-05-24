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
"""Script for implement PR helper."""
import os
import base64
import requests
import yaml

OWNER = 'google'
REPO = 'oss-fuzz'
BASE_URL = f'https://api.github.com/repos/{OWNER}/{REPO}'

def get_project_path(pr_number, headers):
  """Gets the current project path."""
  response = requests.get(f'{BASE_URL}/pulls/{pr_number}/files',
                          headers=headers)
  file = response.json()[0]
  file_path = file['filename']
  project_path = os.path.dirname(file_path)
  return project_path


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

  content = base64.b64decode(
      project_response.json()['content']).decode('UTF-8')
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


def get_pulls_url(commit, headers):
  """Gets the pull request url."""
  pr_response = requests.get(
      f'{BASE_URL}/commits/{commit}/pulls', headers=headers)
  if pr_response.status_code != 200:
    return None
  return pr_response.json()[0]['html_url']


def save_output(message, is_ready_for_merge):
  """Saves the github output."""
  with open(os.environ['GITHUB_OUTPUT'], 'a') as fh:
    print(f'message={message}', file=fh)
    print(f'is_ready_for_merge={is_ready_for_merge}', file=fh)


def main():
  """Verifies if a PR is ready for merge."""
  token = os.environ["INPUT_GITHUBTOKEN"]
  pr_author = os.environ["INPUT_PRAUTHOR"]
  pr_number = os.environ["INPUT_PRNUMBER"]
  headers = {'Authorization': 'Bearer ' + token,
             'X-GitHub-Api-Version': '2022-11-28'
             }

  # Gets the current project path.
  project_path = get_project_path(pr_number, headers)
  email = get_author_email(pr_number, headers)

  content_dict = get_project_yaml(project_path, headers)
  if content_dict is None:
    message = (f'@{pr_author} is adding a new project. '
    f'The PR will be evaluated by the internal team before it can be merged. '
    f'Please make sure to fill out all required information.')
    save_output(message, False)
    return

  primary_contact = content_dict['primary_contact']
  cc_contact = content_dict.get('auto_ccs')

  # Checks if the author is in contact list.
  if email == primary_contact or email in cc_contact:
    message = (f'@{pr_author} is either the primary contact or '
    f'is in the auto CCs list.')
    save_output(message, True)
    return

  # Checks the previous commits.
  has_commit =  has_author_modified_project(project_path, pr_author, headers)
  if not has_commit:
    message = (f'@{pr_author} is a new contributor to this project. '
    f'The PR must be approved by known contributors before it can be merged. '
    f'The primary contact is {primary_contact}.')
    save_output(message, False)
    return

  commit = has_commit[1]
  message = (f'@{pr_author} has previously contributed to this project. '
  f'The previous commit was https://github.com/{OWNER}/{REPO}/commit/{commit}')

  pr_url = get_pulls_url(commit, headers)
  if pr_url is not None:
    message = (f'@{pr_author} has previously contributed to this project. '
    f'The previous PR was {pr_url}')
  save_output(message, True)


if __name__ == "__main__":
  main()
