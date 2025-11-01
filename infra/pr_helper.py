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
GITHUB_NONREF_URL = f'https://www.github.com/{OWNER}/{REPO}'  # Github URL that doesn't send emails on linked issues.
API_URL = 'https://api.github.com'
BASE_URL = f'{API_URL}/repos/{OWNER}/{REPO}'
BRANCH = 'master'
CRITICALITY_SCORE_PATH = '/home/runner/go/bin/criticality_score'
COMMITS_LIMIT = 50  # Only process the most recent 50 commits.


def get_criticality_score(repo_url):
  """Gets the criticality score of the project."""
  # Criticality score does not support repo url ends with '.git'
  if repo_url.endswith('.git'):
    repo_url = repo_url[:-4]
  report = subprocess.run([
      CRITICALITY_SCORE_PATH, '--format', 'json',
      '-gcp-project-id=clusterfuzz-external', '-depsdev-disable', repo_url
  ],
                          capture_output=True,
                          text=True)

  try:
    report_dict = json.loads(report.stdout)
  except:
    print(f'Criticality score failed with stdout: {report.stdout}')
    print(f'Criticality score failed with stderr: {report.stderr}')
    return 'N/A'
  return report_dict.get('default_score', 'N/A')


def is_known_contributor(content, email):
  """Checks if the author is in the contact list."""
  return (email == content.get('primary_contact') or
          email in content.get('vendor_ccs', []) or
          email in content.get('auto_ccs', []))


def save_env(message, is_ready_for_merge, is_internal=False):
  """Saves the outputs as environment variables."""
  with open(os.environ['GITHUB_ENV'], 'a') as github_env:
    github_env.write(f'MESSAGE={message}\n')
    github_env.write(f'IS_READY_FOR_MERGE={is_ready_for_merge}\n')
    github_env.write(f'IS_INTERNAL={is_internal}')


def main():
  """Verifies if a PR is ready to merge."""
  github = GithubHandler()

  # Bypasses PRs of the internal members.
  if github.is_author_internal_member():
    save_env(None, None, True)
    return

  message = ''
  is_ready_for_merge = True
  pr_author = github.get_pr_author()
  # Gets all modified projects path.
  projects_path = github.get_projects_path()
  verified, email = github.get_author_email()

  for project_path in projects_path:
    project_url = f'{GITHUB_URL}/{OWNER}/{REPO}/tree/{BRANCH}/{project_path}'
    content_dict = github.get_project_yaml(project_path)

    # Gets information for the new integrating project.
    if not content_dict:
      is_ready_for_merge = False
      new_project = github.get_integrated_project_info()
      repo_url = new_project.get('main_repo')
      if repo_url is None:
        message += (f'{pr_author} is integrating a new project, '
                    'but the `main_repo` is missing. '
                    'The criticality score cannot be computed.<br/>')
      else:
        message += (f'{pr_author} is integrating a new project:<br/>'
                    f'- Main repo: {repo_url}<br/> - Criticality score: '
                    f'{get_criticality_score(repo_url)}<br/>')
      continue

    # Checks if the author is in the contact list.
    if email:
      if is_known_contributor(content_dict, email):
        # Checks if the email is verified.
        verified_marker = ' (verified)' if verified else ''
        message += (
            f'{pr_author}{verified_marker} is either the primary contact or '
            f'is in the CCs list of [{project_path}]({project_url}).<br/>')
        if verified:
          continue

    # Checks the previous commits.
    commit_sha = github.has_author_modified_project(project_path)
    if commit_sha is None:
      history_message = ''
      contributors = github.get_past_contributors(project_path)
      if contributors:
        history_message = 'The past contributors are: '
        history_message += ', '.join(contributors)
      message += (
          f'{pr_author} is a new contributor to '
          f'[{project_path}]({project_url}). The PR must be approved by known '
          f'contributors before it can be merged. {history_message}<br/>')
      is_ready_for_merge = False
      continue

    # If the previous commit is not associated with a pull request.
    pr_message = (f'{pr_author} has previously contributed to '
                  f'[{project_path}]({project_url}). The previous commit was '
                  f'{GITHUB_NONREF_URL}/commit/{commit_sha}<br/>')

    previous_pr_number = github.get_pull_request_number(commit_sha)
    if previous_pr_number is not None:
      pr_message = (f'{pr_author} has previously contributed to '
                    f'[{project_path}]({project_url}). '
                    f'The previous PR was [#{previous_pr_number}]'
                    f'({GITHUB_NONREF_URL}/pull/{previous_pr_number})<br/>')
    message += pr_message

  save_env(message, is_ready_for_merge, False)


class GithubHandler:
  """Github requests handler."""

  def __init__(self):
    self._pr_author = os.environ['PRAUTHOR']
    self._token = os.environ['GITHUBTOKEN']
    self._pr_number = os.environ['PRNUMBER']
    self._headers = {
        'Authorization': f'Bearer {self._token}',
        'X-GitHub-Api-Version': '2022-11-28'
    }
    self._maintainers = set()
    os.environ['GITHUB_AUTH_TOKEN'] = self._token

  def get_pr_author(self):
    """Gets the pr author user name."""
    return self._pr_author

  def get_projects_path(self):
    """Gets the current project path."""
    response = requests.get(f'{BASE_URL}/pulls/{self._pr_number}/files',
                            headers=self._headers)
    if not response.ok:
      return []

    projects_path = set()
    for file in response.json():
      file_path = file['filename']
      dir_path = file_path.split(os.sep)
      if len(dir_path) > 1 and dir_path[0] == 'projects':
        projects_path.add(os.sep.join(dir_path[0:2]))
    return list(projects_path)

  def get_author_email(self):
    """Retrieves the author's email address for a pull request,
    including non-public emails."""
    user_response = requests.get(f'{API_URL}/users/{self._pr_author}')
    if user_response.ok:
      email = user_response.json()['email']
      if email:
        return True, email

    commits_response = requests.get(
        f'{BASE_URL}/pulls/{self._pr_number}/commits', headers=self._headers)
    if not commits_response.ok:
      return False, None
    email = commits_response.json()[0]['commit']['author']['email']
    verified = commits_response.json()[0]['commit']['verification']['verified']
    return verified, email

  def get_project_yaml(self, project_path):
    """Gets the project yaml file."""
    contents_url = f'{BASE_URL}/contents/{project_path}/project.yaml'
    return self.get_yaml_file_content(contents_url)

  def get_yaml_file_content(self, contents_url):
    """Gets yaml file content."""
    response = requests.get(contents_url, headers=self._headers)
    if not response.ok:
      return {}
    content = base64.b64decode(response.json()['content']).decode('UTF-8')
    return yaml.safe_load(content)

  def get_integrated_project_info(self):
    """Gets the new integrated project."""
    response = requests.get(f'{BASE_URL}/pulls/{self._pr_number}/files',
                            headers=self._headers)

    for file in response.json():
      file_path = file['filename']
      if 'project.yaml' in file_path:
        return self.get_yaml_file_content(file['contents_url'])

    return {}

  def get_pull_request_number(self, commit):
    """Gets the pull request number."""
    pr_response = requests.get(f'{BASE_URL}/commits/{commit}/pulls',
                               headers=self._headers)
    if not pr_response.ok:
      return None
    return pr_response.json()[0]['number']

  def get_past_contributors(self, project_path):
    """Returns a list of past contributors of a certain project."""
    commits_response = requests.get(f'{BASE_URL}/commits?path={project_path}',
                                    headers=self._headers)

    if not commits_response.ok:
      return []
    commits = commits_response.json()
    contributors: dict[str, bool] = {}
    for i, commit in enumerate(commits):
      if i >= COMMITS_LIMIT:
        break

      if not commit['author'] or not commit['commit']:
        continue

      login = commit['author']['login']
      verified = commit['commit']['verification']['verified']
      if login in self._maintainers:
        continue
      if login not in contributors:
        contributors[login] = verified
      if verified:
        # Override previous verification bit.
        contributors[login] = True

    all_contributors = []
    for login, verified in contributors.items():
      login_verify = login if verified else f'{login} (unverified)'
      all_contributors.append(login_verify)

    return all_contributors

  def get_maintainers(self):
    """Get a list of internal members."""
    if self._maintainers:
      return self._maintainers

    response = requests.get(f'{BASE_URL}/contents/infra/MAINTAINERS.csv',
                            headers=self._headers)
    if not response.ok:
      return self._maintainers

    maintainers_file = base64.b64decode(
        response.json()['content']).decode('UTF-8')
    for line in maintainers_file.split(os.linesep):
      self._maintainers.add(line.split(',')[2])
    return self._maintainers

  def is_author_internal_member(self):
    """Returns if the author is an internal member."""
    return self._pr_author in self.get_maintainers()

  def has_author_modified_project(self, project_path):
    """Checks if the author has modified this project before."""
    commits_response = requests.get(
        f'{BASE_URL}/commits?path={project_path}&author={self._pr_author}',
        headers=self._headers)

    if not commits_response.ok or not commits_response.json():
      return None

    commit = commits_response.json()[0]
    return commit['sha']


if __name__ == '__main__':
  main()
