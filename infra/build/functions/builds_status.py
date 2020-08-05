# Copyright 2020 Google Inc.
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
#!/usr/bin/env python2
"""Upload log files and update build statuses, badges for projects."""

from __future__ import print_function
from builtins import range

import datetime
import os
import sys
import json
import time

import dateutil.parser
from oauth2client.client import GoogleCredentials
from googleapiclient.discovery import build as gcb_build
from google.cloud import storage

import build_and_run_coverage
import build_project

STATUS_BUCKET = 'oss-fuzz-build-logs'
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BADGE_DIR = 'badges'
RETRY_COUNT = 3
RETRY_WAIT = 5
MAX_BUILD_RESULTS = 2000
BUILDS_PAGE_SIZE = 256
BADGE_IMAGE_TYPES = {'svg': 'image/svg+xml', 'png': 'image/png'}

# pylint: disable=invalid-name
_client = None


# pylint: disable=global-statement
def get_storage_client():
  """Return storage client."""
  global _client
  if not _client:
    _client = storage.Client()

  return _client


def usage():
  """Output usage syntax."""
  sys.stderr.write('Usage: ' + sys.argv[0] + ' <projects_dir>\n')
  sys.exit(1)


# pylint: disable=unused-variable
def scan_project_names(projects_dir):
  """Scan and return project list from directory."""
  projects = []
  for root, dirs, files in os.walk(projects_dir):
    for file in files:
      if file == 'Dockerfile':
        projects.append(os.path.basename(root))
  return sorted(projects)


def upload_status(successes, failures, status_filename):
  """Upload main status page."""
  data = {
      'projects': failures + successes,
      'failures': failures,
      'successes': successes,
      'last_updated': datetime.datetime.utcnow().ctime()
  }

  bucket = get_storage_client().get_bucket(STATUS_BUCKET)
  blob = bucket.blob(status_filename)
  blob.cache_control = 'no-cache'
  blob.upload_from_string(json.dumps(data), content_type='application/json')


def is_build_successful(build):
  """Check build success."""
  return build['status'] == 'SUCCESS'


def upload_log(build_id):
  """Uploads log file oss-fuzz-build-logs."""
  status_bucket = get_storage_client().get_bucket(STATUS_BUCKET)
  gcb_bucket = get_storage_client().get_bucket(build_project.GCB_LOGS_BUCKET)
  log_name = 'log-{0}.txt'.format(build_id)
  log = gcb_bucket.blob(log_name)
  dest_log = status_bucket.blob(log_name)

  if not log.exists():
    print('Failed to find build log {0}'.format(log_name), file=sys.stderr)
    return False

  if dest_log.exists():
    return True

  gcb_bucket.copy_blob(log, status_bucket)
  return True


def find_last_build(builds, project, build_tag_suffix):
  """Find last finished build of project."""
  delay_minutes = 40
  tag = project + '-' + build_tag_suffix

  builds = builds.get(tag)
  if not builds:
    print('Failed to find builds with tag {0}'.format(tag), file=sys.stderr)
    return None

  for build in builds:
    if build['status'] == 'WORKING':
      continue

    if tag not in build['tags']:
      continue

    if not 'finishTime' in build:
      continue

    finish_time = dateutil.parser.parse(build['finishTime'], ignoretz=True)
    if (datetime.datetime.utcnow() - finish_time >=
        datetime.timedelta(minutes=delay_minutes)):

      if not upload_log(build['id']):
        continue

      return build

  return None


def execute_with_retries(request):
  """Execute request with retries."""
  for i in range(RETRY_COUNT + 1):
    try:
      return request.execute()
    except Exception as error:
      print('request failed with {0}, retrying...'.format(str(error)))
      if i < RETRY_COUNT:
        time.sleep(RETRY_WAIT)
        continue

      raise


def get_builds(cloudbuild):
  """Get a batch of the latest builds (up to MAX_BUILD_RESULTS), grouped by
  tag."""
  ungrouped_builds = []
  next_page_token = None

  while True:
    page_size = min(BUILDS_PAGE_SIZE, MAX_BUILD_RESULTS - len(ungrouped_builds))
    response = execute_with_retries(cloudbuild.projects().builds().list(
        projectId='oss-fuzz', pageSize=page_size, pageToken=next_page_token))

    if not 'builds' in response:
      print('Invalid response from builds list: {0}'.format(response),
            file=sys.stderr)
      return None

    ungrouped_builds.extend(response['builds'])
    if len(ungrouped_builds) >= MAX_BUILD_RESULTS:
      break

    next_page_token = response.get('nextPageToken')

  builds = {}
  for build in ungrouped_builds:
    for tag in build['tags']:
      builds.setdefault(tag, []).append(build)

  return builds


def update_build_status(builds, projects, build_tag_suffix, status_filename):
  """Update build statuses of projects as a json to cloud storage."""
  successes = []
  failures = []

  for project in projects:
    print(project)

    last_build = find_last_build(builds, project, build_tag_suffix)
    if not last_build:
      print('Failed to get build for {0}'.format(project), file=sys.stderr)
      continue

    print(last_build['startTime'], last_build['status'], last_build['id'])
    if is_build_successful(last_build):
      successes.append({
          'name': project,
          'build_id': last_build['id'],
          'finish_time': last_build['finishTime'],
          'success': True,
      })
    else:
      failures.append({
          'name': project,
          'build_id': last_build['id'],
          'finish_time': last_build['finishTime'],
          'success': False,
      })

  upload_status(successes, failures, status_filename)


def update_build_badges(builds, projects, build_tag, coverage_tag):
  """Update build badges of projects."""
  for project in projects:
    last_build = find_last_build(builds, project, build_tag)
    last_coverage_build = find_last_build(builds, project, coverage_tag)
    if not last_build or not last_coverage_build:
      continue

    badge = 'building'
    if not is_build_successful(last_coverage_build):
      badge = 'coverage_failing'
    if not is_build_successful(last_build):
      badge = 'failing'

    print("[badge] {}: {}".format(project, badge))

    for extension, mime_type in BADGE_IMAGE_TYPES.items():
      badge_name = '{badge}.{extension}'.format(badge=badge,
                                                extension=extension)
      # Retrieve the image relative to this script's location
      badge_file = os.path.join(SCRIPT_DIR, 'badge_images', badge_name)

      # The uploaded blob name should look like `badges/project.png`
      blob_name = '{badge_dir}/{project_name}.{extension}'.format(
          badge_dir=BADGE_DIR, project_name=project, extension=extension)

      status_bucket = get_storage_client().get_bucket(STATUS_BUCKET)
      badge_blob = status_bucket.blob(blob_name)
      badge_blob.upload_from_filename(badge_file, content_type=mime_type)


def main():
  """Update build statuses and badges."""
  if len(sys.argv) != 2:
    usage()

  projects_dir = sys.argv[1]
  projects = scan_project_names(projects_dir)

  credentials = GoogleCredentials.get_application_default()
  cloudbuild = gcb_build('cloudbuild', 'v1', credentials=credentials)

  builds = get_builds(cloudbuild)
  update_build_status(builds,
                      projects,
                      build_project.FUZZING_BUILD_TAG,
                      status_filename='status.json')
  update_build_status(builds,
                      projects,
                      build_and_run_coverage.COVERAGE_BUILD_TAG,
                      status_filename='status-coverage.json')

  update_build_badges(builds,
                      projects,
                      build_tag=build_project.FUZZING_BUILD_TAG,
                      coverage_tag=build_and_run_coverage.COVERAGE_BUILD_TAG)


if __name__ == '__main__':
  main()
