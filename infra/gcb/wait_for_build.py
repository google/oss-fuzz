#!/usr/bin/python2

"""Waits for project build on Google Cloud Builder.

Usage: wait_for_build.py <build_id>
"""

import sys
import time

from oauth2client.client import GoogleCredentials
from googleapiclient.discovery import build

POLL_INTERVAL = 30


def usage():
  sys.stderr.write(
    "Usage: " + sys.argv[0] + " <build_id>\n")
  exit(1)


def main():
  if len(sys.argv) != 2:
    usage()

  credentials = GoogleCredentials.get_application_default()
  cloudbuild = build('cloudbuild', 'v1', credentials=credentials)

  while True:
    build_info = cloudbuild.projects().builds().get(projectId='clusterfuzz-external', id=sys.argv[1]).execute()
    status = build_info['status']
    if status == 'SUCCESS':
      print status
      exit(0)

    if status == 'FAILURE':
      print status
      exit(1)

    time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
  main()
