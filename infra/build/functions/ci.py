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

BuildType = collections.namedtuple(
    'BuildType', ['type_name', 'get_build_steps_func', 'status_filename'])

BUILD_TYPES = {
    'coverage':
        BuildType('coverage', build_project.get_build_steps,
                  'status-coverage.json'),
    'fuzzing':
        BuildType('fuzzing', build_and_run_coverage.get_build_steps,
                  'status.json'),
}


class ProjectStatus:
  """Class that holds info about project builds."""

  def __init__(self, name):
    self.name = name
    self.build_result = {'coverage': None, 'fuzzing': None}
    self.build_finished = {'coverage': True, 'fuzzing': True}
    self.build_id = {'coverage': None, 'fuzzing': None}

  def set_build_id(self, build_id, build_type):
    """Sets the build id of |build_type| to |build_id|."""
    self.build_id[build_type] = build_id
    if build_id:
      self.build_finished[build_type] = False

  def set_build_result(self, result):
    """Sets the result of |build_type| to |result|."""
    self.build_result = result
    self.build_finished = True


def _get_production_build_statuses(build_type):
  """Gets the statuses for |build_type| that is reported by build-status.
  Returns a dictionary mapping projects to bools indicating whether the last
  build of |build_type| succeeded."""
  request = requests.get('https://oss-fuzz-build-logs.storage.googleapis.com/'
                         f'{build_type.status_filename}')
  project_statuses = request.json()['projects']
  results = {}
  for project in project_statuses:
    name = project['name']
    history = project['history']
    if len(history) == 0:
      continue
    success = history[0]['success']

    results[name] = bool(success)
  return results


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


def get_projects_to_build(specified_projects, build_type):
  """Returns the list of projects that should be built based on the projects
  specified by the user (|specified_projects|) the |project_statuses| of the
  last builds and the |build_type|."""
  buildable_projects = []

  project_statuses = _get_production_build_statuses(build_type)
  for project in specified_projects:
    if project not in project_statuses:
      buildable_projects.append(project)
      continue
    if project_statuses[project]:
      buildable_projects.append(project)
      continue

    logging.info('Skipping %s, last build failed.', project)

  return buildable_projects


def _do_builds(args, config, credentials, build_type, projects):
  """Does |build_type| test builds of |projects|."""
  build_ids = {}
  for project_name in projects:
    logging.info('Getting steps for: "%s".', project_name)
    try:
      project_yaml, dockerfile_contents = (
          build_project.get_project_data(project_name))
    except FileNotFoundError:
      logging.error('Couldn\'t get project data. Skipping %s.', project_name)
      continue

    project_yaml['sanitizers'] = list(
        set(project_yaml['sanitizers']).intersection(set(args.sanitizers)))

    project_yaml['fuzzing_engines'] = list(
        set(project_yaml['fuzzing_engines']).intersection(
            set(args.fuzzing_engines)))

    if not project_yaml['sanitizers'] or not project_yaml['fuzzing_engines']:
      logging.info('Nothing to build for this project: %s.', project_name)
      continue

    steps = build_type.get_build_steps_func(project_name, project_yaml,
                                            dockerfile_contents, IMAGE_PROJECT,
                                            BASE_IMAGES_PROJECT, config)
    if not steps:
      logging.error('No steps. Skipping %s.', project_name)
      continue

    build_ids[project_name] = (build_project.run_build(project_name, steps,
                                                       credentials,
                                                       build_type.type_name))

  return build_ids


def get_build_status_from_gcb(cloudbuild_api, build_id):
  """Returns the status of the build: |build_id| from cloudbuild_api."""
  build_result = cloudbuild_api.get(projectId=IMAGE_PROJECT,
                                    id=build_id).execute()
  return build_result['status']


def check_finished(build_id, project, cloudbuild_api, build_results):
  """Checks that the |build_type| build is complete. Updates |project_status| if
  complete."""
  build_status = get_build_status_from_gcb(cloudbuild_api, build_id)
  if build_status not in FINISHED_BUILD_STATUSES:
    return False
  build_results[project] = build_status == 'SUCCESS'
  return True


def wait_on_builds(build_ids, credentials):
  """Waits on |builds|. Returns True if all builds succeed."""
  cloudbuild = cloud_build('cloudbuild',
                           'v1',
                           credentials=credentials,
                           cache_discovery=False)
  cloudbuild_api = cloudbuild.projects().builds()  # pylint: disable=no-member

  wait_builds = build_ids.copy()
  build_results = {}
  while wait_builds:
    logging.info('Polling')
    for project, build_id in list(wait_builds.items()):
      if check_finished(build_id, project, cloudbuild_api, build_results):
        del wait_builds[project]
    print(wait_builds)

  print('Printing results')
  print('Project, Statuses')
  for project, build_result in build_results.items():
    print(project, build_result)

  return all(build_results.items())


def do_test_builds(args):
  """Does test coverage and fuzzing builds."""
  build_types = []
  if list(args.sanitizers) == ['coverage']:
    build_types.append(BUILD_TYPES['coverage'])
    if len(build_types) > 1:
      build_types.append(BUILD_TYPES['fuzzing'])
  else:
    build_types.append(BUILD_TYPES['fuzzing'])
  for build_type in build_types:
    projects = get_projects_to_build(list(args.projects), build_type)
    config = build_project.Config(testing=True,
                                  test_image_suffix=TEST_IMAGE_SUFFIX,
                                  branch=args.branch,
                                  parallel=False)
    credentials = (
        oauth2client.client.GoogleCredentials.get_application_default())
    build_ids = _do_builds(args, config, credentials, build_type, projects)
  return wait_on_builds(build_ids, credentials)


def main():
  """Builds and pushes test images of the base images. Then does test coverage
  and fuzzing builds using the test images."""
  logging.basicConfig(level=logging.INFO)
  args = get_args()
  build_and_push_test_images.build_and_push_images(TEST_IMAGE_SUFFIX)
  return 0 if do_test_builds(args) else 1


if __name__ == '__main__':
  main()
