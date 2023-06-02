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
import json
import os
import subprocess

import requests
import yaml

OWNER = 'google'
REPO = 'oss-fuzz'
GITHUB_URL = 'https://github.com/'
API_URL = 'https://api.github.com'
BASE_URL = f'{API_URL}/repos/{OWNER}/{REPO}'
BRANCH = 'master'


def get_projects_path(pr_number, headers):
  """Gets the current project path."""
  response = requests.get(f'{BASE_URL}/pulls/{pr_number}/files',
                          headers=headers)

  projects_path = set()
  for file in response.json():
    file_path = file['filename']
    dir_path = os.path.dirname(file_path)
    if 'projects' in dir_path:
      projects_path.add(dir_path)
  return list(projects_path)


def get_author_email(pr_number, headers):
  """Retrieves the author's email address for a pull request,
  including non-public emails."""
  commits_response = requests.get(f'{BASE_URL}/pulls/{pr_number}/commits',
                                  headers=headers)
  if not commits_response.ok:
    return None
  email = commits_response.json()[0]['commit']['author']['email']
  return email


def get_project_yaml(project_path, headers):
  """Gets the project yaml file."""
  contents_url = f'{BASE_URL}/contents/{project_path}/project.yaml'
  return get_yaml_file_content(contents_url, headers)


def get_yaml_file_content(contents_url, headers):
  """Gets yaml file content."""
  response = requests.get(contents_url, headers=headers)
  if not response.ok:
    return {}
  content = base64.b64decode(response.json()['content']).decode('UTF-8')
  return yaml.safe_load(content)


def get_integrated_project_info(pr_number, headers):
  """Gets the new integrated project."""
  response = requests.get(f'{BASE_URL}/pulls/{pr_number}/files',
                          headers=headers)

  for file in response.json():
    file_path = file['filename']
    if 'project.yaml' in file_path:
      return get_yaml_file_content(file['contents_url'], headers)

  return None


def get_criticality_score(repo_url):
  """Gets the criticality score of the project."""
  report = subprocess.run([
      '/home/runner/go/bin/criticality_score', '--format', 'json',
      '-gcp-project-id=clusterfuzz-external', '-depsdev-disable', repo_url
  ],
                          capture_output=True,
                          text=True)

  report_dict = json.loads(report.stdout)
  return report_dict.get('default_score', 'N/A')


def is_known_contributor(content, email):
  """Checks if the author is in the contact list."""
  return (email == content.get('primary_contact') or
          email in content.get('vendor_ccs', []) or
          email in content.get('auto_ccs', []))


def has_author_modified_project(project_path, pr_author, headers):
  """Checks if the author has modified this project before."""
  commits_response = requests.get(
      f'{BASE_URL}/commits?path={project_path}&author={pr_author}',
      headers=headers)

  if not commits_response.ok or not commits_response.json():
    return False

  commit = commits_response.json()[0]
  return True, commit['sha']


def get_pull_request_url(commit, headers):
  """Gets the pull request url."""
  pr_response = requests.get(f'{BASE_URL}/commits/{commit}/pulls',
                             headers=headers)
  if not pr_response.ok:
    return None
  return pr_response.json()[0]['html_url']


def is_author_internal_member(pr_author, headers):
  """Returns if the author is an internal member."""
  response = requests.get(f'{BASE_URL}/contents/infra/MAINTAINERS.csv',
                          headers=headers)
  if not response.ok:
    return False

  maintainers = base64.b64decode(response.json()['content']).decode('UTF-8')
  for line in maintainers.split('\n'):
    print(f"username: {line.split(',')[2]}")
    if pr_author == line.split(',')[2]:
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
  os.environ['GITHUB_AUTH_TOKEN'] = token
  headers = {
      'Authorization': f'Bearer {token}',
      'X-GitHub-Api-Version': '2022-11-28'
  }
  message = ''
  is_ready_for_merge = True

  # Bypasses PRs of the internal members.
  if is_author_internal_member(pr_author, headers):
    return

  # Gets all modified projects path.
  projects_path = get_projects_path(pr_number, headers)
  email = get_author_email(pr_number, headers)

  for project_path in projects_path:
    project_url = f'{GITHUB_URL}/{OWNER}/{REPO}/tree/{BRANCH}/{project_path}'
    content_dict = get_project_yaml(project_path, headers)

    # Gets information for the new integrating project
    if not content_dict:
      is_ready_for_merge = False
      new_project = get_integrated_project_info(pr_number, headers)
      repo_url = new_project.get('main_repo')
      if repo_url is not None:
        message += (f'@{pr_author} is integrating a new project:<br/>'
                    f'- Main repo: {repo_url}<br/> - Criticality score: '
                    f'{get_criticality_score(repo_url)}<br/>')
      continue

    # Checks if the author is in the contact list.
    if is_known_contributor(content_dict, email):
      message += (
          f'@{pr_author} is either the primary contact or '
          f'is in the CCs list of [{project_path}]({project_url}).<br/>')
      continue

    # Checks the previous commits.
    has_commit = has_author_modified_project(project_path, pr_author, headers)
    if not has_commit:
      message += (
          f'@{pr_author} is a new contributor to '
          f'[{project_path}]({project_url}). The PR must be approved by known '
          'contributors before it can be merged.<br/>')
      is_ready_for_merge = False
      continue
    commit_sha = has_commit[1]

    # If the previous commit is not associated with a pull request.
    pr_message = (f'@{pr_author} has previously contributed to '
                  f'[{project_path}]({project_url}). The previous commit was '
                  f'{GITHUB_URL}/{OWNER}/{REPO}/commit/{commit_sha}<br/>')

    pr_url = get_pull_request_url(commit_sha, headers)
    if pr_url is not None:
      pr_message = (f'@{pr_author} has previously contributed to '
                    f'[{project_path}]({project_url}). '
                    f'The previous PR was {pr_url}<br/>')
    message += pr_message

  save_env(message, is_ready_for_merge, False)


if __name__ == '__main__':
  main()
