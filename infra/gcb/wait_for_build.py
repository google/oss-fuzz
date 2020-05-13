#!/usr/bin/python2
"""Waits for project build on Google Cloud Builder.

Usage: wait_for_build.py <build_id>
"""

import argparse
import sys
import time
import datetime

from googleapiclient.discovery import build
from oauth2client.client import GoogleCredentials

POLL_INTERVAL = 15
cloudbuild = None


def _print(msg):
  # Print helper writing to stdout and instantly flushing it to ensure the
  # output is visible in Jenkins console viewer as soon as possible.
  sys.stdout.write(msg)
  sys.stdout.write('\n')
  sys.stdout.flush()


def get_build(build_id, cloudbuild, project):
  return cloudbuild.projects().builds().get(projectId=project,
                                            id=build_id).execute()


def wait_for_build(build_id, project):
  DONE_STATUSES = [
      'SUCCESS',
      'FAILURE',
      'INTERNAL_ERROR',
      'CANCELLED',
      'TIMEOUT',
  ]

  status = None
  while True:
    build_info = get_build(build_id, cloudbuild, project)

    current_status = build_info['status']
    if current_status != status:
      _print('%s %s' % (str(datetime.datetime.now()), current_status))
    status = current_status
    if status in DONE_STATUSES:
      return status == 'SUCCESS'

    time.sleep(POLL_INTERVAL)


def main():
  global cloudbuild

  parser = argparse.ArgumentParser(description='Wait for build to complete')
  parser.add_argument('-p',
                      '--project',
                      help='Cloud Project',
                      default='oss-fuzz')
  parser.add_argument('build_id', help='The Container Builder build ID.')

  args = parser.parse_args()

  credentials = GoogleCredentials.get_application_default()
  cloudbuild = build('cloudbuild', 'v1', credentials=credentials)

  if wait_for_build(args.build_id, args.project):
    return

  _print('The build failed. Retrying the same build one more time.')
  retry_info = cloudbuild.projects().builds().retry(projectId=args.project,
                                                    id=args.build_id).execute()
  new_build_id = retry_info['metadata']['build']['id']
  if not wait_for_build(new_build_id, args.project):
    sys.exit(1)


if __name__ == '__main__':
  main()
