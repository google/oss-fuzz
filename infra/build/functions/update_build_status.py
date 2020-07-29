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
import json

import google.auth
from googleapiclient.discovery import build
from google.cloud import ndb

import build_and_run_coverage
import build_project
import builds_status
from datastore_entities import BuildsHistory
from datastore_entities import LastSuccessfulBuild
from datastore_entities import Project

BADGE_DIR = 'badge_images'
DESTINATION_BADGE_DIR = 'badges'
MAX_BUILD_LOGS = 7


class MissingBuildLogError(Exception):
  """Missing build log file in cloud storage."""


# pylint: disable=no-member
def get_build_history(build_ids):
  """Returns build object for the last finished build of project."""
  credentials, image_project = google.auth.default()
  cloudbuild = build('cloudbuild',
                     'v1',
                     credentials=credentials,
                     cache_discovery=False)

  history = []

  for build_id in reversed(build_ids):
    project_build = cloudbuild.projects().builds().get(projectId=image_project,
                                                       id=build_id).execute()
    if project_build['status'] == 'WORKING':
      continue

    if not builds_status.upload_log(build_id):
      log_name = 'log-{0}'.format(build_id)
      raise MissingBuildLogError('Missing build log file {0}'.format(log_name))

    history.append({
        'build_id': build_id,
        'finish_time': project_build['finishTime'],
        'success': builds_status.is_build_successful(project_build)
    })

    if len(history) == MAX_BUILD_LOGS:
      break

  return history


# pylint: disable=too-many-locals
def update_build_status(build_tag, status_filename):
  """Update build statuses."""
  build_history = []
  last_successful_build = []
  statuses = {}
  successes = []
  failures = []
  not_yet_built = []
  for project_build in BuildsHistory.query(
      BuildsHistory.build_tag == build_tag).order('project'):

    history = get_build_history(project_build.build_ids)
    if not history:
      not_yet_built.append({'name': project_build.project, 'history': history})
      continue

    if history[0].success:
      statuses[project_build.project] = True
      successes.append({'name': project_build.project, 'history': history})
    else:
      statuses[project_build.project] = False
      failures.append({'name': project_build.project, 'history': history})

  for project in failures:
    build_history.append(project)
    last_success = ndb.Key(LastSuccessfulBuild,
                           project.name + '-' + build_tag).get()
    if not last_success:
      continue
    last_successful_build.append({
        'name': project.name,
        'build_id': last_success.build_id,
        'finish_time': last_success.finish_time
    })

  for project in not_yet_built:
    build_history.append(project)

  for project in successes:
    last_success = ndb.Key(LastSuccessfulBuild,
                           project.name + '-' + build_tag).get()

    if last_success:
      last_success.build_id = project.history[0].build_id
      last_success.finish_time = project.history[0].finish_time
    else:
      last_success = LastSuccessfulBuild(
          id=project.name + '-' + build_tag,
          project=project.name,
          build_id=project.history[0].build_id,
          finish_time=project.history[0].finish_time)

    last_success.put()
    build_history.append(project)
    last_successful_build.append({
        'name': project.name,
        'build_id': last_success.build_id,
        'finish_time': last_success.finish_time
    })

  data = {
      'last_successful_build': last_successful_build,
      'build_history': build_history
  }
  bucket = builds_status.get_storage_client().get_bucket(
      builds_status.STATUS_BUCKET)
  blob = bucket.blob(status_filename)
  blob.cache_control = 'no-cache'
  blob.upload_from_string(json.dumps(data), content_type='application/json')

  return statuses


def update_build_badges(project, last_build_successful,
                        last_coverage_build_successful):
  """Upload badges of given project."""
  badge = 'building'
  if not last_coverage_build_successful:
    badge = 'coverage_failing'
  if not last_build_successful:
    badge = 'failing'

  print("[badge] {}: {}".format(project, badge))

  for extension in builds_status.BADGE_IMAGE_TYPES:
    badge_name = '{badge}.{extension}'.format(badge=badge, extension=extension)

    # Copy blob from badge_images/badge_name to badges/project/
    blob_name = '{badge_dir}/{badge_name}'.format(badge_dir=BADGE_DIR,
                                                  badge_name=badge_name)

    destination_blob_name = '{badge_dir}/{project_name}.{extension}'.format(
        badge_dir=DESTINATION_BADGE_DIR,
        project_name=project,
        extension=extension)

    status_bucket = builds_status.get_storage_client().get_bucket(
        builds_status.STATUS_BUCKET)
    badge_blob = status_bucket.blob(blob_name)
    status_bucket.copy_blob(badge_blob,
                            status_bucket,
                            new_name=destination_blob_name)


# pylint: disable=no-member
def update_status(event, context):
  """Entry point for cloud function to update build statuses and badges."""
  del event, context  #unused

  with ndb.Client().context():
    project_build_statuses = update_build_status(
        build_project.FUZZING_BUILD_TAG, status_filename='status.json')
    coverage_build_statuses = update_build_status(
        build_and_run_coverage.COVERAGE_BUILD_TAG,
        status_filename='status-coverage.json')

    for project in Project.query():
      if (project.name not in project_build_statuses or
          project.name not in coverage_build_statuses):
        continue

      update_build_badges(project.name, project_build_statuses[project.name],
                          coverage_build_statuses[project.name])
