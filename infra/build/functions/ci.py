# Copyright 2022 Google LLC
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
"""Tool for testing changes to base-images in OSS-Fuzz. This script builds test
versions of all base images and the builds projects using those test images."""
import argparse
import collections
import logging
import sys

from googleapiclient.discovery import build as cloud_build
import oauth2client.client
import requests

import build_and_push_test_images
import build_and_run_coverage
import build_project

IMAGE_PROJECT = 'oss-fuzz'
BASE_IMAGES_PROJECT = 'oss-fuzz-base'
TEST_IMAGE_SUFFIX = 'testing'
FINISHED_BUILD_STATUSES = ('SUCCESS', 'FAILURE', 'TIMEOUT', 'CANCELLED',
                           'EXPIRED')


class ProjectStatus:
  """Class that holds info about project builds."""

  def __init__(self, name):
    self.name = name
    self.production_build = {'coverage': None, 'fuzzing': None}
    self.build_result = {'coverage': None, 'fuzzing': None}
    self.build_finished = {'coverage': True, 'fuzzing': True}
    self.build_id = {'coverage': None, 'fuzzing': None}

  def set_build_id(self, build_id, build_type):
    """Sets the build id of |build_type| to |build_id|."""
    self.build_id[build_type] = build_id
    if build_id:
      self.build_finished[build_type] = False

  def set_build_result(self, result, build_type):
    """Sets the result of |build_type| to |result|."""
    self.build_result[build_type] = result
    self.build_finished[build_type] = True


def _get_production_build_statuses(build_type, statuses=None):
  """Gets the statuses for |build_type| that is reported by build-status.
  |statuses| is an optional dictionary mapping projects to dictionaries
  containing the status of coverage and fuzzing builds. If provided, the
  dictionary is appended to, otherwise a new dictionary is created and
  returned."""
  if statuses is None:
    statuses = {}
  if build_type == 'fuzzing':
    filename = 'status.json'
  elif build_type == 'coverage':
    filename = 'status-coverage.json'
  else:
    assert None

  request = requests.get(
      f'https://oss-fuzz-build-logs.storage.googleapis.com/{filename}')
  project_statuses = request.json()['projects']
  for project in project_statuses:
    name = project['name']
    history = project['history']
    if len(history) == 0:
      continue
    success = history[0]['success']

    if name in statuses:
      project_status = statuses[name]
    else:
      project_status = ProjectStatus(name)
      statuses[name] = project_status

    project_status.production_build[build_type] = success
  return statuses


def get_args():
  """Parses command line arguments."""
  parser = argparse.ArgumentParser(sys.argv[0], description='Test projects')
  parser.add_argument('projects', help='Projects.', nargs='*')
  parser.add_argument('--testing',
                      action='store_true',
                      required=False,
                      default=False,
                      help='Upload to testing buckets.')
  parser.add_argument('--sanitizers',
                      required=True,
                      nargs='+',
                      help='Sanitizers.')
  parser.add_argument('--fuzzing-engines',
                      required=True,
                      nargs='+',
                      help='Fuzzing engines.')
  parser.add_argument('--branch',
                      required=False,
                      default=None,
                      help='Use specified OSS-Fuzz branch.')
  return parser.parse_args()


def get_production_build_statuses():
  """Returns the status of the last build done in production for each
  project."""
  statuses = _get_production_build_statuses('fuzzing')
  statuses = _get_production_build_statuses('coverage', statuses)
  return statuses


def get_projects(specified_projects, project_statuses, build_type):
  """Returns the list of projects that should be built based on the projects
  specified by the user (|specified_projects|) the |project_statuses| of the
  last builds and the |build_type|."""
  buildable_projects = []

  for project in specified_projects:
    if project not in project_statuses:
      buildable_projects.append(project)
      continue
    if project_statuses[project].production_build[build_type]:
      buildable_projects.append(project)
      continue

    logging.info('Skipping %s, last build failed.', project)

  return buildable_projects


def _do_build(args, config, credentials, build_type, project_statuses):
  """Does test builds of the type specified by |build_type|."""
  if build_type == 'fuzzing':
    get_build_steps_func = build_project.get_build_steps
    sanitizers = args.sanitizers
  else:
    get_build_steps_func = build_and_run_coverage.get_build_steps
    sanitizers = ['coverage']

  projects = get_projects(args.projects, project_statuses, build_type)
  for project_name in projects:
    logging.info('Getting steps for: "%s".', project_name)
    try:
      project_yaml, dockerfile_contents = (
          build_project.get_project_data(project_name))
    except FileNotFoundError:
      logging.error('Couldn\'t get project data. Skipping %s.', project_name)
      continue

    project_yaml['sanitizers'] = list(
        set(project_yaml['sanitizers']).intersection(set(sanitizers)))

    project_yaml['fuzzing_engines'] = list(
        set(project_yaml['fuzzing_engines']).intersection(
            set(args.fuzzing_engines)))

    if not project_yaml['sanitizers'] or not project_yaml['fuzzing_engines']:
      logging.info('Nothing to build for this project: %s.', project_name)
      continue

    steps = get_build_steps_func(project_name, project_yaml,
                                 dockerfile_contents, IMAGE_PROJECT,
                                 BASE_IMAGES_PROJECT, config)
    if not steps:
      logging.error('No steps. Skipping %s.', project_name)
      continue

    project_statuses[project_name].set_build_id(
        build_project.run_build(project_name, steps, credentials, build_type),
        build_type)

  return project_statuses


def get_build_status_from_gcb(cloudbuild_api, build_id):
  """Returns the status of the build: |build_id| from cloudbuild_api."""
  build_result = cloudbuild_api.get(projectId=IMAGE_PROJECT,
                                    id=build_id).execute()
  return build_result['status']


def check_finished(project_status, build_type, cloudbuild_api):
  """Checks that the |build_type| build is complete. Updates |project_status| if
  complete."""
  build_id = project_status.build_id[build_type]
  if not build_id:
    return
  print('build_id', build_id)
  build_status = get_build_status_from_gcb(cloudbuild_api, build_id)
  if build_status not in FINISHED_BUILD_STATUSES:
    return
  project_status.set_build_result(build_status == 'SUCCESS', build_type)


def wait_on_builds(project_statuses, credentials):
  """Waits on |builds|. Returns True if all builds succeed."""
  results = collections.defaultdict(lambda: {
      'coverage': False,
      'fuzzing': False
  })

  cloudbuild = cloud_build('cloudbuild',
                           'v1',
                           credentials=credentials,
                           cache_discovery=False)
  cloudbuild_api = cloudbuild.projects().builds()  # pylint: disable=no-member

  wait_projects = project_statuses.copy()
  while wait_projects:
    logging.info('Polling')
    for project, project_status in list(wait_projects.items()):
      check_finished(project_status, 'fuzzing', cloudbuild_api)
      check_finished(project_status, 'coverage', cloudbuild_api)
      if all(project_status.build_finished.values()):
        del wait_projects[project]

  print('Printing results')
  print('Project, Statuses')
  for project, project_status in project_statuses.items():
    print(project, project_status.build_result)

  return all(all(statuses) for statuses in results.values())


def do_test_builds(args):
  """Does test coverage and fuzzing builds."""
  config = build_project.Config(True, TEST_IMAGE_SUFFIX, args.branch, False)
  credentials = oauth2client.client.GoogleCredentials.get_application_default()
  project_statuses = get_production_build_statuses()
  _do_build(args, config, credentials, 'fuzzing', project_statuses)
  _do_build(args, config, credentials, 'coverage', project_statuses)
  return wait_on_builds(project_statuses, credentials)


def main():
  """Builds and pushes test images of the base images. Then does test coverage
  and fuzzing builds using the test images."""
  logging.basicConfig(level=logging.INFO)
  args = get_args()
  # build_and_push_test_images.build_and_push_images(TEST_IMAGE_SUFFIX)
  return 0 if do_test_builds(args) else 1


if __name__ == '__main__':
  main()
