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
import datetime
import functools
import json
import logging
import os
import sys
import time
import urllib.request

from googleapiclient.discovery import build as cloud_build
from googleapiclient.errors import HttpError
import oauth2client.client
import yaml

import build_and_push_test_images
import build_and_run_coverage
import build_lib
import build_project

# Warning time in minutes before build times out.
BUILD_TIMEOUT_WARNING_MINUTES = 15
# Default timeout in seconds, 7 hours.
DEFAULT_TIMEOUT = 25200
TEST_IMAGE_SUFFIX = 'testing'
FINISHED_BUILD_STATUSES = ('SUCCESS', 'FAILURE', 'TIMEOUT', 'CANCELLED',
                           'EXPIRED')

BuildType = collections.namedtuple(
    'BuildType', ['type_name', 'get_build_steps_func', 'status_filename'])

BUILD_TYPES = {
    'coverage':
        BuildType('coverage', build_and_run_coverage.get_build_steps,
                  'status-coverage.json'),
    'introspector':
        BuildType('introspector',
                  build_and_run_coverage.get_fuzz_introspector_steps,
                  'status-introspector.json'),
    'fuzzing':
        BuildType('fuzzing', build_project.get_build_steps, 'status.json'),
    'indexer':
        BuildType('indexer', build_project.get_indexer_build_steps,
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
  request = urllib.request.urlopen(
      'https://oss-fuzz-build-logs.storage.googleapis.com/'
      f'{build_type.status_filename}')
  project_statuses = json.load(request)['projects']
  results = {}
  for project in project_statuses:
    name = project['name']
    history = project['history']
    if len(history) == 0:
      continue
    success = history[0]['success']

    results[name] = bool(success)
  return results


def handle_special_projects(args):
  """Handles "special" projects that are not actually projects such as "all" or
  "c++"."""
  all_projects = get_all_projects()
  if 'all' in args.projects:  # Explicit opt-in for all.
    args.projects = all_projects
    return
  project_languages = get_project_languages()
  for project in args.projects[:]:
    if project in project_languages.keys():
      language = project
      args.projects.remove(language)
      args.projects.extend(project_languages[language])


def get_args(args=None):
  """Parses command line arguments."""
  parser = argparse.ArgumentParser(sys.argv[0], description='Test projects')
  parser.add_argument('projects',
                      help='Projects. "all" for all projects',
                      nargs='+')
  parser.add_argument(
      '--sanitizers',
      required=False,
      default=['address', 'memory', 'undefined', 'coverage', 'introspector'],
      nargs='+',
      help='Sanitizers.')
  parser.add_argument('--fuzzing-engines',
                      required=False,
                      default=['afl', 'libfuzzer', 'honggfuzz', 'centipede'],
                      nargs='+',
                      help='Fuzzing engines.')
  parser.add_argument('--repo',
                      required=False,
                      default=build_project.DEFAULT_OSS_FUZZ_REPO,
                      help='Use specified OSS-Fuzz repo.')
  parser.add_argument('--branch',
                      required=False,
                      default=None,
                      help='Use specified OSS-Fuzz branch.')
  parser.add_argument('--force-build',
                      action='store_true',
                      help='Build projects that failed to build on OSS-Fuzz\'s '
                      'production builder.')
  parsed_args = parser.parse_args(args)
  handle_special_projects(parsed_args)
  return parsed_args


@functools.lru_cache
def get_all_projects():
  """Returns a list of all OSS-Fuzz projects."""
  projects_dir = os.path.join(build_and_push_test_images.OSS_FUZZ_ROOT,
                              'projects')
  return sorted([
      project for project in os.listdir(projects_dir)
      if os.path.isdir(os.path.join(projects_dir, project))
  ])


@functools.lru_cache
def get_project_languages():
  """Returns a dictionary mapping languages to projects."""
  all_projects = get_all_projects()
  project_languages = collections.defaultdict(list)
  for project in all_projects:
    project_yaml_path = os.path.join(build_and_push_test_images.OSS_FUZZ_ROOT,
                                     'projects', project, 'project.yaml')
    if not os.path.exists(project_yaml_path):
      continue
    with open(project_yaml_path, 'r') as project_yaml_file_handle:
      project_yaml_contents = project_yaml_file_handle.read()
      project_yaml = yaml.safe_load(project_yaml_contents)
    language = project_yaml.get('language', 'c++')
    project_languages[language].append(project)
  return project_languages


def get_projects_to_build(specified_projects, build_type, force_build):
  """Returns the list of projects that should be built based on the projects
  specified by the user (|specified_projects|) the |project_statuses| of the
  last builds and the |build_type|."""
  buildable_projects = []

  project_statuses = _get_production_build_statuses(build_type)
  for project in specified_projects:
    if (project not in project_statuses or project_statuses[project] or
        force_build):
      # If we don't have data on the project, then we have no reason not to
      # build it.
      buildable_projects.append(project)
      continue

  return buildable_projects


def _do_build_type_builds(args, config, credentials, build_type, projects):
  """Does |build_type| test builds of |projects|."""
  build_ids = {}
  for project_name in projects:
    try:
      project_yaml, dockerfile_contents = (
          build_project.get_project_data(project_name))
    except FileNotFoundError:
      logging.error('Couldn\'t get project data. Skipping %s.', project_name)
      continue

    build_project.set_yaml_defaults(project_yaml)
    project_yaml_sanitizers = build_project.get_sanitizer_strings(
        project_yaml['sanitizers']) + ['coverage', 'indexer', 'introspector']
    project_yaml['sanitizers'] = list(
        set(project_yaml_sanitizers).intersection(set(args.sanitizers)))

    project_yaml['fuzzing_engines'] = list(
        set(project_yaml['fuzzing_engines']).intersection(
            set(args.fuzzing_engines)))

    if not project_yaml['sanitizers'] or not project_yaml['fuzzing_engines']:
      continue

    steps = build_type.get_build_steps_func(project_name, project_yaml,
                                            dockerfile_contents, config)
    if not steps:
      logging.error('No steps. Skipping %s.', project_name)
      continue

    try:
      build_ids[project_name] = (build_project.run_build(
          project_name,
          steps,
          credentials,
          build_type.type_name,
          extra_tags=['trial-build', f'branch-{args.branch}']))
      time.sleep(1)  # Avoid going over 75 requests per second limit.
    except Exception as error:  # pylint: disable=broad-except
      # Handle flake.
      print('Failed to start build', project_name, error)

  return build_ids


def get_build_status_from_gcb(cloudbuild_api, cloud_project, build_id):
  """Returns the status of the build: |build_id| from cloudbuild_api."""
  build_result = cloudbuild_api.get(projectId=cloud_project,
                                    id=build_id).execute()
  return build_result['status']


def check_finished(build_id, project, cloudbuild_api, cloud_project,
                   build_results):
  """Checks that the |build_type| build is complete. Updates |project_status| if
  complete."""

  try:
    build_status = get_build_status_from_gcb(cloudbuild_api, cloud_project,
                                             build_id)
  except HttpError:
    logging.debug('build: HttpError when getting build status from gcb')
    return False
  if build_status not in FINISHED_BUILD_STATUSES:
    logging.debug('build: %d not finished.', build_id)
    return False
  build_results[project] = build_status
  return True


def wait_on_builds(build_ids, credentials, cloud_project, end_time):  # pylint: disable=too-many-locals
  """Waits on |builds|. Returns True if all builds succeed."""
  cloudbuild = cloud_build('cloudbuild',
                           'v1',
                           credentials=credentials,
                           cache_discovery=False,
                           client_options=build_lib.REGIONAL_CLIENT_OPTIONS)
  cloudbuild_api = cloudbuild.projects().builds()  # pylint: disable=no-member

  wait_builds = build_ids.copy()
  build_results = {}
  failed_builds = {}
  builds_count = len(wait_builds)
  next_check_time = datetime.datetime.now() + datetime.timedelta(hours=1)
  timeout_warning_time = end_time - datetime.timedelta(
      minutes=BUILD_TIMEOUT_WARNING_MINUTES)
  notified_timeout = False
  logging.info(
      '----------------------------Build result----------------------------')
  logging.info(f'Trial build end time: {end_time}')
  logging.info('Failed project, Statuses, Logs')
  while wait_builds:
    current_time = datetime.datetime.now()
    # Update status every hour.
    if current_time >= next_check_time:
      logging.info(f'[{current_time}] Remaining builds: '
                   f'{len(wait_builds)}, {wait_builds}')
      next_check_time += datetime.timedelta(hours=1)

    # Warn users and write a summary if build is about to end.
    if not notified_timeout and current_time >= timeout_warning_time:
      notified_timeout = True
      logging.info(
          f'[{current_time}] Warning: trial build may time out in '
          f'{BUILD_TIMEOUT_WARNING_MINUTES} minutes.\n'
          f'Remaining builds: {len(wait_builds)}/{builds_count}, {wait_builds}.'
          f'\nFailed builds: {len(failed_builds)}/{builds_count}, '
          f'{failed_builds}')

    for project, project_build_ids in list(wait_builds.items()):
      for build_id in project_build_ids[:]:
        if check_finished(build_id, project, cloudbuild_api, cloud_project,
                          build_results):
          if build_results[project] != 'SUCCESS':
            logs_url = build_lib.get_logs_url(build_id)
            failed_builds[project] = logs_url
            logging.info(f'{project}, {build_results[project]}, {logs_url}')

          wait_builds[project].remove(build_id)
          if not wait_builds[project]:
            del wait_builds[project]

        time.sleep(1)  # Avoid rate limiting.

  # Return failure if any build fails or nothing is built.
  if failed_builds or not build_results:
    logging.info(
        'Summary: trial build failed\n'
        f'Failed builds: {len(failed_builds)}/{builds_count}, {failed_builds}')
    return False

  logging.info(f'Summary: trial build passed.')
  return True


def _do_test_builds(args, test_image_suffix, end_time):
  """Does test coverage and fuzzing builds."""
  logging.info(
      '---------------------------Trial build logs---------------------------')
  build_types = []
  sanitizers = list(args.sanitizers)
  if 'coverage' in sanitizers:
    sanitizers.pop(sanitizers.index('coverage'))
    build_types.append(BUILD_TYPES['coverage'])
  if 'introspector' in sanitizers:
    sanitizers.pop(sanitizers.index('introspector'))
    build_types.append(BUILD_TYPES['introspector'])
  if 'indexer' in sanitizers:
    sanitizers.pop(sanitizers.index('indexer'))
    build_types.append(BUILD_TYPES['indexer'])
  if sanitizers:
    build_types.append(BUILD_TYPES['fuzzing'])
  build_ids = collections.defaultdict(list)
  for build_type in build_types:
    projects = get_projects_to_build(list(args.projects), build_type,
                                     args.force_build)
    config = build_project.Config(testing=True,
                                  test_image_suffix=test_image_suffix,
                                  repo=args.repo,
                                  branch=args.branch,
                                  parallel=False,
                                  upload=False)
    credentials = (
        oauth2client.client.GoogleCredentials.get_application_default())
    project_builds = _do_build_type_builds(args, config, credentials,
                                           build_type, projects)
    for project, project_build_id in project_builds.items():
      build_ids[project].append(project_build_id)

  return wait_on_builds(build_ids, credentials, build_lib.IMAGE_PROJECT,
                        end_time)


def trial_build_main(args=None, local_base_build=True):
  """Main function for trial_build. Pushes test images and then does test
  builds."""
  args = get_args(args)
  timeout = int(os.environ.get('TIMEOUT', DEFAULT_TIMEOUT))
  end_time = datetime.datetime.now() + datetime.timedelta(seconds=timeout)
  logging.info(f'Timeout: {timeout}, trial build end time: {end_time}')
  if args.branch:
    test_image_suffix = f'{TEST_IMAGE_SUFFIX}-{args.branch.lower()}'
  else:
    test_image_suffix = TEST_IMAGE_SUFFIX
  if local_base_build:
    build_and_push_test_images.build_and_push_images(  # pylint: disable=unexpected-keyword-arg
        test_image_suffix)
  else:
    build_and_push_test_images.gcb_build_and_push_images(test_image_suffix)
  return _do_test_builds(args, test_image_suffix, end_time)


def main():
  """Builds and pushes test images of the base images. Then does test coverage
  and fuzzing builds using the test images."""
  logging.basicConfig(level=logging.INFO)
  return 0 if trial_build_main() else 1


if __name__ == '__main__':
  sys.exit(main())
