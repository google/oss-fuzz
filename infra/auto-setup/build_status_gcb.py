#!/usr/bin/env python2

import os
import sys

from oauth2client.client import GoogleCredentials
from googleapiclient.discovery import build as gcb_build

def usage():
  sys.stderr.write(
    "Usage: " + sys.argv[0] + " <projects_dir>\n")
  exit(1)


def scan_project_names(projects_dir):
  projects = []
  for root, dirs, files in os.walk(projects_dir):
    for f in files:
      if f == "Dockerfile":
        projects.append(os.path.basename(root))
  return sorted(projects)


def main():
  if len(sys.argv) != 2:
    usage()

  projects_dir = sys.argv[1]

  credentials = GoogleCredentials.get_application_default()
  cloudbuild = gcb_build('cloudbuild', 'v1', credentials=credentials)


  for project in scan_project_names(projects_dir):
    print project
    query_filter = ('(status="SUCCESS" OR status="FAILURE") AND ' + 
        'images="gcr.io/clusterfuzz-external/oss-fuzz/{0}"'.format(project))
    response = cloudbuild.projects().builds().list(
        projectId='clusterfuzz-external',
        filter=query_filter).execute()
    if not 'builds' in response:
      continue

    builds = sorted(response['builds'], key=lambda b: b['startTime'])
    last_build = builds[-1]
    print last_build['startTime'], last_build['status']


if __name__ == "__main__":
  main()

