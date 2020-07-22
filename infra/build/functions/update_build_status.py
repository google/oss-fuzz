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
import logging

import google.auth
from googleapiclient.discovery import build
from google.cloud import ndb

import build_and_run_coverage
import build_project
import builds_status
from datastore_entities import BuildsHistory
from datastore_entities import Project


# pylint: disable=no-member
def get_last_build(build_ids):
  """Returns build object for the last finished build of project."""
  credentials, image_project = google.auth.default()
  cloudbuild = build('cloudbuild', 'v1', credentials=credentials)

  for build_id in reversed(build_ids):
    project_build = cloudbuild.projects().builds().get(projectId=image_project,
                                                       id=build_id).execute()
    if project_build['status'] == 'WORKING':
      continue

    if not builds_status.upload_log(build_id):
      continue
    return project_build

  return None


def update_build_status(build_tag_suffix, status_filename):
  """Update build statuses."""
  successes = []
  failures = []
  builds = BuildsHistory.query()
  for project_build in builds:
    if project_build.build_tag_suffix != build_tag_suffix:
      continue
    last_build = get_last_build(project_build.build_ids)
    if not last_build:
      logging.error('Failed to get last build for project %s',
                    project_build.project)
      continue

    if last_build['status'] == 'SUCCESS':
      successes.append({
          'name': project_build.project,
          'build_id': last_build['id'],
          'finish_time': last_build['finishTime'],
          'success': True,
      })
    else:
      failures.append({
          'name': project_build.project,
          'build_id': last_build['id'],
          'finish_time': last_build['finishTime'],
          'success': False,
      })

  builds_status.upload_status(successes, failures, status_filename)


# pylint: disable=no-member
def update_status(event, context):
  """Entry point for cloud function to update build statuses and badges."""
  del event, context  #unused

  with ndb.Client().context():
    update_build_status(build_project.FUZZING_BUILD_TAG,
                        status_filename='status.json')
    update_build_status(build_and_run_coverage.COVERAGE_BUILD_TAG,
                        status_filename='status-coverage.json')

    for project in Project.query():
      build_history_key = ndb.Key(
          BuildsHistory, project.name + build_project.FUZZING_BUILD_TAG)
      build_history = build_history_key.get()
      if not build_history:
        continue
      last_build = get_last_build(build_history.build_ids)

      if not last_build:
        continue

      coverage_build_history_key = ndb.Key(
          BuildsHistory,
          project.name + build_and_run_coverage.COVERAGE_BUILD_TAG)
      coverage_build_history = coverage_build_history_key.get()
      if not coverage_build_history:
        continue

      last_coverage_build = get_last_build(coverage_build_history.build_ids)
      if not last_coverage_build:
        continue

      builds_status.update_build_badges(project.name, last_build,
                                        last_coverage_build)
