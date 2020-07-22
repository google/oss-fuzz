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
import tempfile

import google.auth
from googleapiclient.discovery import build
from google.cloud import ndb
from google.cloud import storage

import build_and_run_coverage
import build_project
import builds_status
from datastore_entities import BuildsHistory


# TODO: update function in builds_status.py after migration.
def get_last_build(builds, project, build_tag_suffix):
  """Returns build object for the last finished build of project."""
  with ndb.Client().context():
    build_history = builds.filter(BuildsHistory.project == project)
    build_history_with_tag = build_history.filter(BuildsHistory.tag == tag)
  
  project_build_history = build_history_with_tag.get()
  if not project_build_history:
    return None

  credentials, image_project = google.auth.default()
  cloudbuild = build('cloudbuild', 'v1', credentials=credentials)

  for build_id in reversed(project_build_history.build_ids):
    build = cloudbuild.projects().builds().get(projectId=image_project, id=build_id).execute()
    if build['status'] == 'WORKING':
      continue

    if not builds_status.upload_log(build_id):
      continue
    return build

  return None


# pylint: disable=no-member
def update_status(event, context):
  """Entry point for cloud function to update build statuses and badges."""
  with ndb.Client().context():
    builds = BuildsHistory.query()

  projects = [build.project for build in builds if build.tag=='-fuzzing']

  #TODO; Cleanup after infrastructure migration
  builds_status.find_last_build = get_last_build

  builds_status.update_build_status(
      builds
      projects,
      build_project.FUZZING_BUILD_TAG,
      status_filename='status.json')
  builds_status.update_build_status(
      builds
      projects,
      build_and_run_coverage.COVERAGE_BUILD_TAG,
      status_filename='status-coverage.json')

  for project in projects:
    last_co
    update_build_badges(
        projects,
        build_tag=build_project.FUZZING_BUILD_TAG,
        coverage_tag=build_and_run_coverage.COVERAGE_BUILD_TAG)
