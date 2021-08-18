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
import base64
import logging

import google.auth
from googleapiclient.discovery import build
from google.cloud import ndb

import build_lib
import build_project
from datastore_entities import BuildsHistory
from datastore_entities import Project

BASE_PROJECT = 'oss-fuzz-base'
MAX_BUILD_HISTORY_LENGTH = 64
QUEUE_TTL_SECONDS = 60 * 60 * 24  # 24 hours.


def update_build_history(project_name, build_id, build_tag):
  """Update build history of project."""
  project_key = ndb.Key(BuildsHistory, project_name + '-' + build_tag)
  project = project_key.get()

  if not project:
    project = BuildsHistory(id=project_name + '-' + build_tag,
                            build_tag=build_tag,
                            project=project_name,
                            build_ids=[])

  if len(project.build_ids) >= MAX_BUILD_HISTORY_LENGTH:
    project.build_ids.pop(0)

  project.build_ids.append(build_id)
  project.put()


def get_project_data(project_name):
  """Retrieve project metadata from datastore."""
  query = Project.query(Project.name == project_name)
  project = query.get()
  if not project:
    raise RuntimeError(
        f'Project {project_name} not available in cloud datastore')
  project_yaml_contents = project.project_yaml_contents
  dockerfile_lines = project.dockerfile_contents.split('\n')

  return (project_yaml_contents, dockerfile_lines)


def get_build_steps(project_name, image_project, base_images_project):
  """Retrieve build steps."""
  project_yaml_contents, dockerfile_lines = get_project_data(project_name)
  return build_project.get_build_steps(project_name, project_yaml_contents,
                                       dockerfile_lines, image_project,
                                       base_images_project)


# pylint: disable=no-member
def run_build(project_name, image_project, build_steps, credentials, tag):
  """Execute build on cloud build."""
  build_body = {
      'steps': build_steps,
      'timeout': str(build_lib.BUILD_TIMEOUT) + 's',
      'options': {
          'machineType': 'N1_HIGHCPU_32'
      },
      'logsBucket': build_project.GCB_LOGS_BUCKET,
      'tags': [project_name + '-' + tag,],
      'queueTtl': str(QUEUE_TTL_SECONDS) + 's',
  }

  cloudbuild = build('cloudbuild',
                     'v1',
                     credentials=credentials,
                     cache_discovery=False)
  build_info = cloudbuild.projects().builds().create(projectId=image_project,
                                                     body=build_body).execute()
  build_id = build_info['metadata']['build']['id']

  update_build_history(project_name, build_id, tag)
  logging.info('Build ID: %s', build_id)
  logging.info('Logs: %s', build_project.get_logs_url(build_id, image_project))


# pylint: disable=no-member
def request_build(event, context):
  """Entry point for cloud function to request builds."""
  del context  #unused
  if 'data' in event:
    project_name = base64.b64decode(event['data']).decode('utf-8')
  else:
    raise RuntimeError('Project name missing from payload')

  with ndb.Client().context():
    credentials, image_project = google.auth.default()
    build_steps = get_build_steps(project_name, image_project, BASE_PROJECT)
    if not build_steps:
      return
    run_build(project_name, image_project, build_steps, credentials,
              build_project.FUZZING_BUILD_TAG)
