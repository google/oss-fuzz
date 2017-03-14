#!/usr/bin/python2

"""Waits for project build on Google Cloud Builder.

Usage: wait_for_build.py <build_id>
"""

import sys
import time
import datetime

from googleapiclient.discovery import build
from oauth2client.client import GoogleCredentials


POLL_INTERVAL = 15
cloudbuild = None


def usage():
  sys.stderr.write(
    "Usage: " + sys.argv[0] + " <build_id>\n")
  exit(1)


def get_build(build_id, cloudbuild):
  return cloudbuild.projects().builds().get(
      projectId='clusterfuzz-external', id=build_id).execute()


def wait_for_build(build_id):
  global cloudbuild

  status = None
  while True:
    build_info = get_build(build_id, cloudbuild)
    current_status = build_info['status']
    if current_status != status:
        print datetime.datetime.now(), current_status
    status = current_status
    if status == 'SUCCESS' or status == 'FAILURE':
      return status == 'SUCCESS'

    print build_info['logUrl']

    time.sleep(POLL_INTERVAL)


def main():
  global cloudbuild

  if len(sys.argv) != 2:
    usage()

  credentials = GoogleCredentials.get_application_default()
  cloudbuild = build('cloudbuild', 'v1', credentials=credentials)

  build_id = sys.argv[1]
  success = wait_for_build(build_id)

  if not success:
    sys.exit(1)


if __name__ == "__main__":
  main()
