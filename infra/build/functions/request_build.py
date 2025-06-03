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

import google.auth
from google.cloud import ndb
import yaml

import build_project
import datastore_entities

BASE_PROJECT = 'oss-fuzz-base'
MAX_BUILD_HISTORY_LENGTH = 64
QUEUE_TTL_SECONDS = 60 * 60 * 24  # 24 hours.


def update_build_history(project_name, build_id, build_tag):
  """Update build history of project."""
  project_key = ndb.Key(datastore_entities.BuildsHistory,
                        project_name + '-' + build_tag)
  project = project_key.get()

  if not project:
    project = datastore_entities.BuildsHistory(id=project_name + '-' +
                                               build_tag,
                                               build_tag=build_tag,
                                               project=project_name,
                                               build_ids=[])

  if len(project.build_ids) >= MAX_BUILD_HISTORY_LENGTH:
    project.build_ids.pop(0)

  project.build_ids.append(build_id)
  project.put()


def get_project_data(project_name):
  """Retrieve project metadata from datastore."""
  query = datastore_entities.Project.query(
      datastore_entities.Project.name == project_name)
  project = query.get()
  if not project:
    raise RuntimeError(
        f'Project {project_name} not available in cloud datastore')

  project_yaml = yaml.safe_load(project.project_yaml_contents)
  return project_yaml, project.dockerfile_contents


def get_empty_config():
  """Returns an empty build config."""
  return build_project.Config()


def get_build_steps(project_name, timestamp=None):
  """Retrieve build steps."""
  project_yaml, dockerfile_lines = get_project_data(project_name)
  build_config = build_project.Config(
      build_type=build_project.FUZZING_BUILD_TYPE)
  return build_project.get_build_steps(project_name,
                                       project_yaml,
                                       dockerfile_lines,
                                       build_config,
                                       timestamp=timestamp)


def get_indexer_build_steps(project_name, timestamp=None):
  """Retrieve build steps."""
  project_yaml, dockerfile_lines = get_project_data(project_name)
  build_config = build_project.Config(
      build_type=build_project.INDEXER_BUILD_TYPE)
  return build_project.get_indexer_build_steps(project_name,
                                               project_yaml,
                                               dockerfile_lines,
                                               build_config,
                                               timestamp=timestamp)


def run_build(oss_fuzz_project,
              build_steps,
              credentials,
              build_type,
              cloud_project,
              update_history=True):
  """Execute build on cloud build. Wrapper around build_project.py that also
  updates the db."""
  build_id = build_project.run_build(oss_fuzz_project, build_steps, credentials,
                                     build_type, cloud_project)
  if update_history:
    update_build_history(oss_fuzz_project, build_id, build_type)


# pylint: disable=no-member
def request_build(event, context):
  """Entry point for cloud function to request builds."""
  del context  #unused
  if 'data' in event:
    project_name = base64.b64decode(event['data']).decode('utf-8')
  else:
    raise RuntimeError('Project name missing from payload')

  timestamp = build_project.get_datetime_now()
  with ndb.Client().context():
    credentials, cloud_project = google.auth.default()
    build_steps = get_build_steps(project_name, timestamp)
    if not build_steps:
      return
    run_build(
        project_name,
        build_steps,
        credentials,
        build_project.FUZZING_BUILD_TYPE,
        cloud_project=cloud_project,
    )

    indexer_build_steps = get_indexer_build_steps(project_name, timestamp)
    if not indexer_build_steps:
      return
    run_build(
        project_name,
        indexer_build_steps,
        credentials,
        build_project.INDEXER_BUILD_TYPE,
        cloud_project=cloud_project,
        update_history=False,
    )
