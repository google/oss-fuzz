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


def _get_production_build_statuses(build_type, statuses=None):
  """Gets the statuses for |build_type| that is reported by build-status.
  |statuses| is an optional dictionary mapping projects to dictionaries
  containing the status of coverage and fuzzing builds. If provided, the
  dictionary is appended to, otherwise a new dictionary is created and
  returned."""
  if statuses is None:
    statuses = collections.defaultdict(lambda: {
        'coverage': False,
        'fuzzing': False
    })
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
    # !!! 0 len?
    success = project['history'][0]['success']
    statuses[name][build_type] = success
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


def get_projects(specified_projects, statuses, build_type):
  """Returns the list of projects that should be built based on the projects
  specified by the user (|specified_projects|) the |statuses| of the last builds
  and the |build_type|."""
  statuses = get_production_build_statuses()
  buildable_projects = []

  for project in specified_projects:
    if project not in statuses:
      buildable_projects.append(project)
      continue
    if statuses[project][build_type]:
      buildable_projects.append(project)
      continue

    logging.info('Skipping %s, last build failed.', project)

  return buildable_projects


def _do_type_builds(args, config, credentials, build_type, builds=None):
  """Does test builds of the type specified by |build_type|."""
  if builds is None:
    builds = collections.defaultdict(lambda: {
        'coverage': None,
        'fuzzing': None
    })
  if build_type == 'fuzzing':
    get_build_steps_func = build_project.get_build_steps
    sanitizers = args.sanitizers
  else:
    get_build_steps_func = build_and_run_coverage.get_build_steps
    sanitizers = ['coverage']

  statuses = get_production_build_statuses()
  projects = get_projects(args.projects, statuses, build_type)
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

    builds[project_name][build_type] = (build_project.run_build(
        project_name, steps, credentials, build_type))

  return builds


def get_build_status_from_gcb(cloudbuild_api, build_id):
  """Returns the status of the build: |build_id| from cloudbuild_api."""
  build_result = cloudbuild_api.get(projectId=IMAGE_PROJECT,
                                    id=build_id).execute()
  return build_result['status']


def wait_on_builds(builds, credentials):
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

  while builds:
    logging.info('Polling')
    for project, build_ids in list(builds.items()):
      fuzzing_build_id = build_ids['fuzzing']
      if fuzzing_build_id:
        status = get_build_status_from_gcb(cloudbuild_api, fuzzing_build_id)
        if status not in ('SUCCESS', 'FAILURE', 'TIMEOUT'):
          continue
        results[project]['fuzzing'] = status == 'SUCCESS'
      elif 'fuzzing' in results[project]:
        del results[project]['fuzzing']

      coverage_build_id = build_ids['coverage']
      if coverage_build_id:
        status = get_build_status_from_gcb(cloudbuild_api, coverage_build_id)
        if status not in ('SUCCESS', 'FAILURE', 'TIMEOUT'):
          continue
        results[project]['coverage'] = status == 'SUCCESS'
      elif 'coverage' in results[project]:
        del results[project]['coverage']

      if all(results[project]):
        del builds[project]

  print('Printing results')
  print('Project, Statuses')
  for project, statuses in results.items():
    print(project, statuses)

  return all(all(statuses) for statuses in results.values())


def do_test_builds(args):
  """Does test coverage and fuzzing builds."""
  config = build_project.Config(True, TEST_IMAGE_SUFFIX, args.branch, False)
  credentials = oauth2client.client.GoogleCredentials.get_application_default()
  builds = _do_type_builds(args, config, credentials, 'fuzzing')
  _do_type_builds(args, config, credentials, 'coverage', builds)
  return wait_on_builds(builds, credentials)


def main():
  """Builds and pushes test images of the base images. Then does test coverage
  and fuzzing builds using the test images."""
  logging.basicConfig(level=logging.INFO)
  args = get_args()
  build_and_push_test_images.build_and_push_images(TEST_IMAGE_SUFFIX)
  return 0 if do_test_builds(args) else 1


if __name__ == '__main__':
  main()
