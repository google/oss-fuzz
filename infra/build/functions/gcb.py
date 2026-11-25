# Copyright 2022 Google LLC
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
"""Entrypoint for CI into trial_build. This script will get the command from
the last PR comment containing "/gcbrun" and pass it to trial_build.py, which
builds test versions of base-images, pushes them and then does test builds using
those images.
"""

import logging
import os
import sys

import github

import build_lib
import trial_build

TRIGGER_COMMAND = '/gcbrun'
TRIAL_BUILD_COMMAND_STR = f'{TRIGGER_COMMAND} trial_build.py '
OSS_FUZZ_ON_DEMAND_COMMAND_STR = f'{TRIGGER_COMMAND} oss_fuzz_on_demand.py '
SKIP_COMMAND_STR = f'{TRIGGER_COMMAND} skip'

# Cloud Build only starts this build when someone with write access comments
# /gcbrun, but anyone can comment on a pull request. Only take commands from
# these authors. Without GITHUB_TOKEN, GitHub reports private members of the
# organization as CONTRIBUTOR, so their commands are ignored.
TRUSTED_AUTHOR_ASSOCIATIONS = ('OWNER', 'MEMBER', 'COLLABORATOR')


def get_comments(pull_request_number):
  """Returns comments on the GitHub Pull request referenced by
  |pull_request_number|."""
  token = os.environ.get('GITHUB_TOKEN')
  if token:
    github_obj = github.Github(auth=github.Auth.Token(token))
  else:
    github_obj = github.Github()
  repo = github_obj.get_repo('google/oss-fuzz')
  pull = repo.get_pull(pull_request_number)
  pull_comments = list(pull.get_comments())
  issue = repo.get_issue(pull_request_number)
  issue_comments = list(issue.get_comments())
  # Github only returns comments if from the pull object when a pull request is
  # open. If it is a draft, it will only return comments from the issue object.
  return pull_comments + issue_comments


def get_latest_gcbrun_command(comments):
  """Gets the last /gcbrun comment from a trusted author in |comments|."""
  for comment in reversed(comments):
    # This seems to get comments on code too.
    body = comment.body
    if not body or not body.startswith(TRIGGER_COMMAND):
      continue
    if comment.author_association not in TRUSTED_AUTHOR_ASSOCIATIONS:
      # |user| is None for deleted accounts.
      logging.info('Ignoring %s comment by %s (%s).', TRIGGER_COMMAND,
                   getattr(comment.user, 'login', None),
                   comment.author_association)
      continue
    if body.startswith(SKIP_COMMAND_STR):
      return None
    if not body.startswith(TRIAL_BUILD_COMMAND_STR) and (
        not body.startswith(OSS_FUZZ_ON_DEMAND_COMMAND_STR)):
      continue
    if len(body) == len(TRIAL_BUILD_COMMAND_STR) or (
        len(body) == len(OSS_FUZZ_ON_DEMAND_COMMAND_STR)):
      return None
    return body[len(TRIGGER_COMMAND):].strip().split(' ')
  return None


def exec_command_from_github(args):
  """Executes the most recent gcbrun command for trial_build.py on
  |pull_request_number|. Returns True on success, False on failure."""
  pull_request_number = int(os.environ['PULL_REQUEST_NUMBER'])
  branch = os.environ['BRANCH']
  repo = os.environ['REPO']
  # The commit Cloud Build checked out for this build, i.e. the head of the PR
  # when someone with write access commented /gcbrun. Pushes after that comment
  # must not change what gets built.
  commit = os.environ.get('COMMIT_SHA', '')

  comments = get_comments(pull_request_number)
  full_command = get_latest_gcbrun_command(comments)

  if full_command is None:
    logging.info('Trial build not requested.')
    # Create a flag file to indicate that the build was skipped.
    with open('trial_build_skipped.flag', 'w') as f:
      pass
    return None
  command_file = full_command[0]
  command = full_command[1:]

  if command_file == OSS_FUZZ_ON_DEMAND_COMMAND_STR.split(' ')[1]:
    # Unlike trial builds, OSS-Fuzz on Demand builds aren't pinned to the
    # approved commit, so they can't run from PR comments.
    logging.error('%s oss_fuzz_on_demand.py is disabled.', TRIGGER_COMMAND)
    return False

  if not build_lib.COMMIT_SHA_REGEX.fullmatch(commit):
    logging.error('Missing or invalid COMMIT_SHA: %r.', commit)
    return False
  command.extend(args)
  logging.info('Executing command: %s on %s, branch %s, commit %s.', command,
               repo, branch, commit)
  # Build the projects from the PR commit. Pass the source separately so the
  # comment can't override it.
  return trial_build.trial_build_main(command,
                                      local_base_build=False,
                                      source=(repo, branch, commit))


def main():
  """Entrypoint for GitHub CI into trial_build.py"""
  logging.basicConfig(level=logging.INFO)
  logging.getLogger('oauth2client').setLevel(logging.WARNING)

  args = sys.argv[1:]

  result = exec_command_from_github(args)
  if result or result is None:
    return 0
  return 1


if __name__ == '__main__':
  sys.exit(main())
