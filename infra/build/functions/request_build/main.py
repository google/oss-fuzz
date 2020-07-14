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
import sys
import yaml

import google.auth
from googleapiclient.discovery import build
from google.cloud import ndb

import build_project
import build_lib

BASE_PROJECT = 'oss-fuzz-base'


class Project(ndb.Model):
  """Represents an integrated OSS-Fuzz project."""
  name = ndb.StringProperty()
  schedule = ndb.StringProperty()
  project_yaml_contents = ndb.StringProperty()
  dockerfile_lines = ndb.StringProperty(repeated=True)


def request_build(event, context):
  if 'data' in event:
    project_name = base64.b64decode(event['data']).decode('utf-8')
  else:
    logging.error('Project name missing from payload')
    sys.exit(1)
  client = ndb.Client()
  with client.context():
    query = Project.query(Project.name == project_name)
    if not query:
      logging.error(
          f'Missing project metadata for project {project_name} in cloud datastore'
      )
      sys.exit(1)

    project = query.get()
    project_yaml = yaml.safe_load(project.project_yaml_contents)
    dockerfile_lines = project.dockerfile_lines

  credentials, image_project = google.auth.default()

  build_steps = build_project.get_build_steps(project_name, project_yaml,
                                              dockerfile_lines, image_project,
                                              BASE_PROJECT)
  build_body = {
      'steps': build_steps,
      'timeout': str(build_lib.BUILD_TIMEOUT) + 's',
      'options': {
          'machineType': 'N1_HIGHCPU_32'
      },
      'tags': [project_name + '-fuzzing',],
  }

  cloudbuild = build('cloudbuild',
                     'v1',
                     credentials=credentials,
                     cache_discovery=False)
  build_info = cloudbuild.projects().builds().create(projectId=image_project,
                                                     body=build_body).execute()
  build_id = build_info['metadata']['build']['id']

  logging.info('Build ID: %s', build_id)
  logging.info('Logs: %s', build_project.get_logs_url(build_id, image_project))
