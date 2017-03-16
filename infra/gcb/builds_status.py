#!/usr/bin/env python2

import datetime
import os
import sys
import jinja2
import json

from oauth2client.client import GoogleCredentials
from googleapiclient.discovery import build as gcb_build
from google.cloud import storage
from jinja2 import Environment, FileSystemLoader


LOGS_BUCKET = 'oss-fuzz-gcb-logs'
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))


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


def upload_status(successes, failures, unstable):
  """Upload main status page."""
  env = Environment(loader=FileSystemLoader(os.path.join(SCRIPT_DIR,
                                                         'templates')))
  data = {
      'projects': failures + successes + unstable,
      'failures': failures,
      'successes': successes,
      'unstable': unstable,
      'last_updated': datetime.datetime.utcnow().ctime()
  }

  storage_client = storage.Client()
  bucket = storage_client.get_bucket(LOGS_BUCKET)

  blob = bucket.blob('status.html')
  blob.cache_control = 'no-cache'
  blob.upload_from_string(
          env.get_template('status_template.html').render(data),
          content_type='text/html')

  blob = bucket.blob('status.json')
  blob.cache_control = 'no-cache'
  blob.upload_from_string(
          json.dumps(data),
          content_type='text/html')


def main():
  if len(sys.argv) != 2:
    usage()

  projects_dir = sys.argv[1]

  credentials = GoogleCredentials.get_application_default()
  cloudbuild = gcb_build('cloudbuild', 'v1', credentials=credentials)

  successes = []
  failures = []
  for project in scan_project_names(projects_dir):
    print project
    query_filter = ('(status="SUCCESS" OR status="FAILURE") AND ' + 
        'images="gcr.io/clusterfuzz-external/oss-fuzz/{0}"'.format(project))
    response = cloudbuild.projects().builds().list(
        projectId='clusterfuzz-external',
        filter=query_filter).execute()
    if not 'builds' in response:
      continue

    builds = response['builds']
    last_build = builds[0]
    print last_build['startTime'], last_build['status'], last_build['id']
    if last_build['status'] == 'SUCCESS':
        successes.append({
            'name': project,
            'build_id': last_build['id'],
        })
    else:
        failures.append({
            'name': project,
            'build_id': last_build['id'],
        })

  upload_status(successes, failures, [])

if __name__ == "__main__":
  main()

