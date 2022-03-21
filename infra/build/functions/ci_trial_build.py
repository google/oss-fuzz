import sys
import logging

import requests

import trial_build

TRIGGER_COMMAND = '/gcbrun '

def get_comments(pull_request_number):
  url = ('https://api.github.com/repos/google/oss-fuzz/pulls/'
         f'{pull_request_number}/comments')
  # !!! Does this handle pagination?
  request = requests.get(url)
  return request.json()

def get_latest_gcbrun_command(comments):
  for comment in reversed(comments):
    # This seems to get comments on code too.
    body = comment['body']
    if not body.startswith(TRIGGER_COMMAND):
      continue
    if len(body) <= TRIGGER_COMMAND:
      return None
    # Add an extra for white space.
    return body[len(TRIGGER_COMMAND):]
  return None

def exec_command_from_github(pull_request_number):
  comments = get_comments(pull_request_number)
  command = get_latest_gcbrun_command(comments)
  command = command.split(' ')
  if command is None:
    logging.info('Trial build not requested.')
    return None
  return trial_build.trial_build_main(command)

def main():
  logging.basicConfig(level=logging.INFO)
  pull_request_number = os.environ['PULL_REQUEST_NUMBER']
  return 0 if exec_command_from_github(pull_request_number) else 1

if __name__ == '__main__':
  main()
