import logging
import os

import github

import trial_build

TRIGGER_COMMAND = '/gcbrun '


def get_comments(pull_request_number):
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
  for comment in reversed(comments):
    # This seems to get comments on code too.
    body = comment.body
    print('body', body)
    if not body.startswith(TRIGGER_COMMAND):
      continue
    if len(body) <= len(TRIGGER_COMMAND):
      return None
    # Add an extra for white space.
    return body[len(TRIGGER_COMMAND):]
  return None


def exec_command_from_github(pull_request_number):
  comments = get_comments(pull_request_number)
  print('comments', comments)
  command = get_latest_gcbrun_command(comments)
  if command is None:
    logging.info('Trial build not requested.')
    return None
  command = command.split(' ')
  logging.info('Command: %s.', command)
  # command = ['trial_build.py', 'skcms', '--sanitizer', 'address', '--fuzzing-engine', 'libfuzzer']
  return trial_build.trial_build_main(command)


def main():
  logging.basicConfig(level=logging.INFO)
  pull_request_number = int(os.environ['PULL_REQUEST_NUMBER'])
  return 0 if exec_command_from_github(pull_request_number) else 1


if __name__ == '__main__':
  main()
