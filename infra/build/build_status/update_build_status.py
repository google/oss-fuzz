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
"""Cloud function to request builds."""
import concurrent.futures
import logging
import json
import sys
import os

import google.auth
from googleapiclient.discovery import build
import googleapiclient.errors
from google.cloud import ndb
from google.cloud import storage
import yaml

import build_and_run_coverage
import build_lib
import build_project
import datastore_entities
import fuzz_introspector_page_gen

BADGE_DIR = 'badge_images'
BADGE_IMAGE_TYPES = {'svg': 'image/svg+xml', 'png': 'image/png'}
DESTINATION_BADGE_DIR = 'badges'
MAX_BUILD_LOGS = 7

STATUS_BUCKET = 'oss-fuzz-build-logs'
INTROSPECTOR_BUCKET = 'oss-fuzz-introspector'
INTROSPECTOR_BUCKET_URL = 'https://storage.googleapis.com/oss-fuzz-introspector'
INTROSPECTOR_DOC_URL = 'https://fuzz-introspector.readthedocs.io/en/latest/'
INTROSPECTOR_INDEX_JSON = 'build_status.json'
INTROSPECTOR_INDEX_HTML = 'index.html'

FUZZING_STATUS_FILENAME = 'status.json'
COVERAGE_STATUS_FILENAME = 'status-coverage.json'
INTROSPECTOR_STATUS_FILENAME = 'status-introspector.json'

# pylint: disable=invalid-name
_client = None

logging.basicConfig(level=logging.INFO)


# pylint: disable=global-statement
def get_storage_client():
  """Return storage client."""
  global _client
  if not _client:
    _client = storage.Client()

  return _client


def is_build_successful(build_obj):
  """Check build success."""
  return build_obj['status'] == 'SUCCESS'


def upload_status(data, status_filename):
  """Upload json file to cloud storage."""
  bucket = get_storage_client().get_bucket(STATUS_BUCKET)
  blob = bucket.blob(status_filename)
  blob.cache_control = 'no-cache'
  blob.upload_from_string(json.dumps(data), content_type='application/json')


def sort_projects(projects):
  """Sort projects in order Failures, Successes, Not yet built."""

  def key_func(project):
    if not project['history']:
      return 2  # Order projects without history last.

    if project['history'][0]['success']:
      # Successful builds come second.
      return 1

    # Build failures come first.
    return 0

  projects.sort(key=key_func)


def update_last_successful_build(project, build_tag):
  """Update last successful build."""
  last_successful_build = ndb.Key(datastore_entities.LastSuccessfulBuild,
                                  project['name'] + '-' + build_tag).get()
  if not last_successful_build and 'last_successful_build' not in project:
    return

  if 'last_successful_build' not in project:
    project['last_successful_build'] = {
        'build_id': last_successful_build.build_id,
        'finish_time': last_successful_build.finish_time
    }
  else:
    if last_successful_build:
      last_successful_build.build_id = project['last_successful_build'][
          'build_id']
      last_successful_build.finish_time = project['last_successful_build'][
          'finish_time']
    else:
      last_successful_build = datastore_entities.LastSuccessfulBuild(
          id=project['name'] + '-' + build_tag,
          project=project['name'],
          build_id=project['last_successful_build']['build_id'],
          finish_time=project['last_successful_build']['finish_time'])
    last_successful_build.put()


class BuildGetter:  # pylint: disable=too-few-public-methods
  """Class for getting builds. This is a hack because builds were previously run
  in the global region while builds going forward have been run in us-central1.
  This class will try looking for the build from the global region, until that
  fails, at which point it will look for builds in the us-central1 region."""

  def __init__(self):
    self._credentials, self._image_project = google.auth.default()
    self._global_cloudbuild = build('cloudbuild',
                                    'v1',
                                    credentials=self._credentials,
                                    cache_discovery=False)
    self._central_cloudbuild = build(
        'cloudbuild',
        'v1',
        credentials=self._credentials,
        cache_discovery=False,
        client_options=build_lib.REGIONAL_CLIENT_OPTIONS)
    self._cloudbuilds = [self._global_cloudbuild, self._central_cloudbuild]
    self._swapped = False

  def _swap_cloudbuild_order_once(self):
    """Swap the region order after one failure since the global build region was
    first used before being switched to us-central1."""
    if self._swapped:
      return
    new_last, new_first = self._cloudbuilds
    self._cloudbuilds = [new_first, new_last]
    self._swapped = True

  def get_build(self, build_id):
    """Get the build from global or us-central1 region."""
    for cloudbuild in self._cloudbuilds[:]:
      try:
        return cloudbuild.projects().builds().get(projectId=self._image_project,
                                                  id=build_id).execute()
      except googleapiclient.errors.HttpError:
        self._swap_cloudbuild_order_once()
        continue
    assert None


# pylint: disable=no-member
def get_build_history(build_ids):
  """Returns build object for the last finished build of project."""

  build_getter = BuildGetter()

  history = []
  last_successful_build = None

  for build_id in reversed(build_ids):
    project_build = build_getter.get_build(build_id)
    if project_build['status'] not in ('SUCCESS', 'FAILURE', 'TIMEOUT'):
      continue

    if (not last_successful_build and is_build_successful(project_build)):
      last_successful_build = {
          'build_id': build_id,
          'finish_time': project_build['finishTime'],
      }

    if not upload_log(build_id):
      log_name = f'log-{build_id}'
      logging.error('Missing build log file %s', log_name)
      continue

    history.append({
        'build_id': build_id,
        'finish_time': project_build['finishTime'],
        'success': is_build_successful(project_build)
    })

    if len(history) == MAX_BUILD_LOGS:
      break

  project = {'history': history}
  if last_successful_build:
    project['last_successful_build'] = last_successful_build
  return project


def _get_main_repo(project_name):
  """Get the main repo for a project."""
  project = datastore_entities.Project.query(
      datastore_entities.Project.name == project_name).get()
  if not project:
    return None

  project_yaml = yaml.safe_load(project.project_yaml_contents)
  return project_yaml.get('main_repo')


# pylint: disable=too-many-locals
def update_build_status(build_tag, status_filename):
  """Update build statuses."""
  projects = []

  def process_project(project_build):
    """Process a project."""
    # We need a new context for every thread.
    with ndb.Client().context():
      project = get_build_history(project_build.build_ids)
      project['name'] = project_build.project
      project['main_repo'] = _get_main_repo(project_build.project)
      print('Processing project', project['name'])
      return project

  with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
    futures = []
    for project_build in datastore_entities.BuildsHistory.query(
        datastore_entities.BuildsHistory.build_tag == build_tag).order(
            'project'):
      futures.append(executor.submit(process_project, project_build))

    for future in concurrent.futures.as_completed(futures):
      project = future.result()
      update_last_successful_build(project, build_tag)
      projects.append(project)

  sort_projects(projects)
  data = {'projects': projects}
  upload_status(data, status_filename)


def update_build_badges(project, last_build_successful,
                        last_coverage_build_successful):
  """Upload badges of given project."""
  badge = 'building'
  # last_coverage_build_successful is False if there was an unsuccessful build
  # and None if the target does not support coverage (e.g. Python or Java
  # targets).
  if last_coverage_build_successful is False:
    badge = 'coverage_failing'
  if not last_build_successful:
    badge = 'failing'

  print(f'[badge] {project}: {badge}')

  for extension in BADGE_IMAGE_TYPES:
    badge_name = f'{badge}.{extension}'

    # Copy blob from badge_images/badge_name to badges/project/
    blob_name = f'{BADGE_DIR}/{badge_name}'

    destination_blob_name = f'{DESTINATION_BADGE_DIR}/{project}.{extension}'

    status_bucket = get_storage_client().get_bucket(STATUS_BUCKET)
    badge_blob = status_bucket.blob(blob_name)
    status_bucket.copy_blob(badge_blob,
                            status_bucket,
                            new_name=destination_blob_name)


def upload_log(build_id):
  """Upload log file to GCS."""
  status_bucket = get_storage_client().get_bucket(STATUS_BUCKET)
  gcb_bucket = get_storage_client().get_bucket(build_project.GCB_LOGS_BUCKET)
  log_name = f'log-{build_id}.txt'
  log = gcb_bucket.blob(log_name)
  dest_log = status_bucket.blob(log_name)

  if not log.exists():
    print('Failed to find build log', log_name, file=sys.stderr)
    return False

  if dest_log.exists():
    return True

  gcb_bucket.copy_blob(log, status_bucket)
  return True


def load_status_from_gcs(filename):
  """Load statuses from bucket."""
  status_bucket = get_storage_client().get_bucket(STATUS_BUCKET)
  status = json.loads(status_bucket.blob(filename).download_as_string())
  result = {}

  for project in status['projects']:
    if project['history']:
      result[project['name']] = project['history'][0]['success']

  return result


def update_badges():
  """Update badges."""
  project_build_statuses = load_status_from_gcs(FUZZING_STATUS_FILENAME)
  coverage_build_statuses = load_status_from_gcs(COVERAGE_STATUS_FILENAME)

  with concurrent.futures.ThreadPoolExecutor(max_workers=32) as executor:
    futures = []
    for project in datastore_entities.Project.query():
      if project.name not in project_build_statuses:
        continue
      # Certain projects (e.g. JVM and Python) do not have any coverage
      # builds, but should still receive a badge.
      coverage_build_status = None
      if project.name in coverage_build_statuses:
        coverage_build_status = coverage_build_statuses[project.name]

      futures.append(
          executor.submit(update_build_badges, project.name,
                          project_build_statuses[project.name],
                          coverage_build_status))
    concurrent.futures.wait(futures)


def upload_index(json_index, html_string):
  """Upload json and html file to introspector bucket."""
  introspector_bucket = get_storage_client().get_bucket(INTROSPECTOR_BUCKET)
  json_blob = introspector_bucket.blob(INTROSPECTOR_INDEX_JSON)
  html_blob = introspector_bucket.blob(INTROSPECTOR_INDEX_HTML)

  json_blob.cache_control = 'no-cache'
  json_blob.upload_from_string(json.dumps(json_index),
                               content_type='application/json')

  html_blob.cache_control = 'no-cache'
  html_blob.upload_from_string(html_string, content_type='text/html')


def generate_introspector_index():
  """Generate index.html for successful Fuzz Introspector projects"""
  status_bucket = get_storage_client().get_bucket(STATUS_BUCKET)
  status = json.loads(
      status_bucket.blob(INTROSPECTOR_STATUS_FILENAME).download_as_string())

  introspector_bucket = get_storage_client().get_bucket(INTROSPECTOR_BUCKET)
  index_blob = introspector_bucket.blob(INTROSPECTOR_INDEX_JSON)
  if index_blob.exists():
    introspector_index = json.loads(index_blob.download_as_string())
  else:
    introspector_index = {}

  for project in status['projects']:
    if project['history'] and project['history'][0]['success']:
      project_name = project['name']
      build_date = project['history'][0]['finish_time'].split('T')[0].replace(
          '-', '')
      introspector_index[project_name] = os.path.join(INTROSPECTOR_BUCKET_URL,
                                                      project_name,
                                                      'inspector-report',
                                                      build_date,
                                                      'fuzz_report.html')

  html_string = fuzz_introspector_page_gen.get_fuzz_introspector_html_page(
      introspector_index)
  upload_index(introspector_index, html_string)


def main():
  """Entry point for cloudbuild"""
  with ndb.Client().context():
    configs = ((build_project.FUZZING_BUILD_TYPE, FUZZING_STATUS_FILENAME),
               (build_and_run_coverage.COVERAGE_BUILD_TYPE,
                COVERAGE_STATUS_FILENAME),
               (build_and_run_coverage.INTROSPECTOR_BUILD_TYPE,
                INTROSPECTOR_STATUS_FILENAME))

    for tag, filename in configs:
      update_build_status(tag, filename)

    update_badges()
    generate_introspector_index()


if __name__ == '__main__':
  main()
