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
import subprocess
import sys
import textwrap
import time
import urllib.request
import yaml
import oauth2client.client
from googleapiclient.discovery import build as cloud_build
from googleapiclient.errors import HttpError

import build_and_push_test_images
import build_and_run_coverage
import build_lib
import build_project

# Default timeout for the entire script in seconds, 7 hours.
SCRIPT_DEFAULT_TIMEOUT = 25200

# Default timeout for a single project build in seconds, 4 hours.
PROJECT_BUILD_TIMEOUT = 14400

TEST_IMAGE_SUFFIX = 'testing'

# Warning time in minutes before build times out.
BUILD_TIMEOUT_WARNING_MINUTES = 15
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
}


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
    if not history:
      continue
    success = history[0]['success']
    results[name] = bool(success)
  return results


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
    with open(project_yaml_path, 'r', encoding='utf-8') as file_handle:
      project_yaml = yaml.safe_load(file_handle)
    language = project_yaml.get('language', 'c++')
    project_languages[language].append(project)
  return project_languages


def handle_special_projects(args):
  """Handles "special" projects that are not actually projects such as "all" or
  "c++"."""
  all_projects = get_all_projects()
  if 'all' in args.projects:
    args.projects = all_projects
    return
  project_languages = get_project_languages()
  for project in args.projects[:]:
    if project in project_languages:
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
  parser.add_argument('--version-tag',
                      required=False,
                      default=None,
                      help='Version tag to use for base images.')
  parser.add_argument('--skip-build-images',
                      action='store_true',
                      help='Skip the base image build phase.')
  parsed_args = parser.parse_args(args)
  handle_special_projects(parsed_args)
  return parsed_args


def get_projects_to_build(specified_projects, build_type, force_build):
  """Returns the list of projects that should be built."""
  buildable_projects = []
  project_statuses = _get_production_build_statuses(build_type)
  for project in specified_projects:
    if (project not in project_statuses or not project_statuses[project] or
        force_build):
      buildable_projects.append(project)
  return buildable_projects


def trial_build_main(args=None, local_base_build=True):
  """Main function for trial_build."""
  args = get_args(args)

  test_image_tag = TEST_IMAGE_SUFFIX
  if args.version_tag:
    test_image_tag = f'{test_image_tag}-{args.version_tag}'
  if args.branch:
    test_image_tag = f'{test_image_tag}-{args.branch.lower().replace("/", "-")}'

  if not args.skip_build_images:
    logging.info('Starting "Build and Push Images" phase...')
    if local_base_build:
      build_and_push_test_images.build_and_push_images(test_image_tag)
    else:
      if not build_and_push_test_images.gcb_build_and_push_images(
          test_image_tag, version_tag=args.version_tag):
        logging.error('Failed to build and push images.')
        return False
    logging.info('"Build and Push Images" phase completed.')
  else:
    logging.info(
        '================================================================')
    logging.info('                   PHASE 1: SKIPPED')
    logging.info(
        '================================================================')
    logging.info('Skipping "Build and Push Images" phase as requested.')

  timeout = int(os.environ.get('TIMEOUT', SCRIPT_DEFAULT_TIMEOUT))
  end_time = datetime.datetime.now() + datetime.timedelta(seconds=timeout)
  return _do_test_builds(args, test_image_tag, end_time)


def _do_test_builds(args, test_image_suffix, end_time):
  """Does test coverage and fuzzing builds."""
  build_types = []
  sanitizers = list(args.sanitizers)
  if 'coverage' in sanitizers:
    sanitizers.pop(sanitizers.index('coverage'))
    build_types.append(BUILD_TYPES['coverage'])
  if 'introspector' in sanitizers:
    sanitizers.pop(sanitizers.index('introspector'))
    build_types.append(BUILD_TYPES['introspector'])
  if sanitizers:
    build_types.append(BUILD_TYPES['fuzzing'])

  build_ids = collections.defaultdict(list)
  skipped_projects = []
  failed_to_start_builds = []
  projects_to_build_count = 0
  credentials = oauth2client.client.GoogleCredentials.get_application_default()

  logging.info(
      '================================================================')
  logging.info('            PHASE 2: STARTING TEST BUILDS')
  logging.info(
      '================================================================')

  for build_type in build_types:
    projects = get_projects_to_build(list(args.projects), build_type,
                                     args.force_build)
    if not args.force_build:
      logging.info('Build type: %s', build_type.type_name)
      logging.info(
          '  - Selected projects: %d / %d (due to failed production builds)',
          len(projects), len(args.projects))
      logging.info('  - To build all projects, use the --force-build flag.')
    else:
      logging.info('Build type: %s', build_type.type_name)
      logging.info('  - Building all %d projects (--force-build)',
                   len(projects))

    logging.info('Starting to create and trigger builds for build type: %s',
                 build_type.type_name)

    config = build_project.Config(testing=True,
                                  test_image_suffix=test_image_suffix,
                                  repo=args.repo,
                                  branch=args.branch,
                                  parallel=False,
                                  upload=False,
                                  build_type=build_type.type_name)
    project_builds, new_skipped, new_failed_to_start = _do_build_type_builds(
        args, config, credentials, build_type, projects)
    skipped_projects.extend(new_skipped)
    failed_to_start_builds.extend(new_failed_to_start)
    for project, project_build_id in project_builds.items():
      build_ids[project].append(project_build_id)
      projects_to_build_count += 1

  logging.info('Started builds for %d projects.', projects_to_build_count)

  if skipped_projects:
    logging.info(
        '================================================================')
    logging.info('               PHASE 2: SKIPPED PROJECTS')
    logging.info(
        '================================================================')
    logging.info('Total projects skipped: %d', len(skipped_projects))
    logging.info('--- SKIPPED PROJECTS ---')
    for project, reason in sorted(skipped_projects):
      logging.info('  - %s: %s', project, reason)
    logging.info('-----------------------')

  logging.info(
      '================================================================')
  logging.info('               PHASE 2: STARTED BUILDS')
  logging.info(
      '================================================================')
  logging.info('Total projects with builds: %d', len(build_ids))
  logging.info('--- STARTED BUILDS ---')
  for project, project_build_ids in sorted(build_ids.items()):
    logging.info('  - %s:', project)
    for build_id in project_build_ids:
      logging.info('    - Build ID: %s', build_id)
      logging.info('      GCB URL: %s',
                   build_lib.get_gcb_url(build_id, build_lib.IMAGE_PROJECT))
  logging.info('-----------------------')

  wait_result = wait_on_builds(build_ids, credentials, build_lib.IMAGE_PROJECT,
                               end_time, skipped_projects, args.version_tag)

  if failed_to_start_builds:
    logging.error(
        '================================================================')
    logging.error('           PHASE 2: FAILED TO START BUILDS')
    logging.error(
        '================================================================')
    logging.error('Total projects that failed to start: %d',
                  len(failed_to_start_builds))
    for project, reason in sorted(failed_to_start_builds):
      logging.error('  - %s: %s', project, reason)

  return wait_result and not failed_to_start_builds


def _do_build_type_builds(args, config, credentials, build_type, projects):
  """Does |build_type| test builds of |projects|."""
  build_ids = {}
  skipped_projects = []
  failed_to_start_builds = []
  for project_name in projects:
    try:
      project_yaml, dockerfile_contents = (
          build_project.get_project_data(project_name))
    except FileNotFoundError:
      skipped_projects.append((project_name, 'Missing Dockerfile'))
      continue

    build_project.set_yaml_defaults(project_yaml)
    if project_yaml['disabled']:
      skipped_projects.append((project_name, 'Disabled'))
      continue

    project_yaml_sanitizers = build_project.get_sanitizer_strings(
        project_yaml['sanitizers']) + ['coverage', 'introspector']
    project_yaml['sanitizers'] = list(
        set(project_yaml_sanitizers).intersection(set(args.sanitizers)))

    project_yaml['fuzzing_engines'] = list(
        set(project_yaml['fuzzing_engines']).intersection(
            set(args.fuzzing_engines)))

    if not project_yaml['sanitizers'] or not project_yaml['fuzzing_engines']:
      skipped_projects.append(
          (project_name, 'No compatible sanitizers or engines'))
      continue

    steps = build_type.get_build_steps_func(project_name, project_yaml,
                                            dockerfile_contents, config)
    if not steps:
      skipped_projects.append((project_name, 'No build steps generated'))
      continue

    try:
      build_ids[project_name] = (build_project.run_build(
          project_name,
          steps,
          credentials,
          build_type.type_name,
          extra_tags=['trial-build', f'branch-{args.branch.replace("/", "-")}'],
          timeout=PROJECT_BUILD_TIMEOUT))
      time.sleep(1)  # Avoid going over 75 requests per second limit.
    except Exception as error:  # pylint: disable=broad-except
      # Handle flake.
      logging.error('Failed to start build %s: %s', project_name, error)
      failed_to_start_builds.append((project_name, error))

  return build_ids, skipped_projects, failed_to_start_builds


def _print_summary_box(title, lines):
  """Prints a formatted box for summarizing build results."""
  box_width = 80
  title_line = f'║ {title.center(box_width - 4)} ║'
  separator = '╟' + '─' * (box_width - 2) + '╢'
  summary_lines = [
      '╔' + '═' * (box_width - 2) + '╗',
      title_line,
      '╠' + '═' * (box_width - 2) + '╣',
  ]
  for line in lines:
    wrapped_lines = textwrap.wrap(line, box_width - 6)
    for i, sub_line in enumerate(wrapped_lines):
      summary_lines.append(f'║  {sub_line.ljust(box_width - 6)}  ║')
  summary_lines.append('╚' + '═' * (box_width - 2) + '╝')
  print('\n'.join(summary_lines))


def get_build_status_from_gcb(cloudbuild_api, cloud_project, build_id):
  """Returns the status of the build: |build_id| from cloudbuild_api."""
  build_result = cloudbuild_api.get(projectId=cloud_project,
                                    id=build_id).execute()
  return build_result['status']


def check_finished(build_id, cloudbuild_api, cloud_project):
  """Checks that the build is complete. Returns status if complete, else None"""
  try:
    build_status = get_build_status_from_gcb(cloudbuild_api, cloud_project,
                                             build_id)
  except HttpError:
    logging.debug('build: HttpError when getting build status from gcb')
    return None
  if build_status not in FINISHED_BUILD_STATUSES:
    logging.debug('build: %d not finished.', build_id)
    return None
  return build_status


def wait_on_builds(build_ids, credentials, cloud_project, end_time,
                   skipped_projects, version_tag):  # pylint: disable=too-many-locals
  """Waits on |builds|. Returns True if all builds succeed."""
  cloudbuild = cloud_build('cloudbuild',
                           'v1',
                           credentials=credentials,
                           cache_discovery=False,
                           client_options=build_lib.REGIONAL_CLIENT_OPTIONS)
  cloudbuild_api = cloudbuild.projects().builds()  # pylylint: disable=no-member

  wait_builds = build_ids.copy()
  failed_builds = collections.defaultdict(list)
  successful_builds = collections.defaultdict(list)
  builds_count = sum(len(ids) for ids in build_ids.values())
  finished_builds_count = 0

  logging.info('Waiting for %d project builds to complete...', builds_count)

  timeout_warning_time = end_time - datetime.timedelta(
      minutes=BUILD_TIMEOUT_WARNING_MINUTES)
  notified_timeout = False

  while wait_builds:
    current_time = datetime.datetime.now()
    if not notified_timeout and current_time >= timeout_warning_time:
      notified_timeout = True
      logging.warning(
          'Nearing timeout: %d minutes remaining. Remaining builds: %d',
          BUILD_TIMEOUT_WARNING_MINUTES, len(wait_builds))

    for project, project_build_ids in list(wait_builds.items()):
      for build_id in project_build_ids[:]:
        status = check_finished(build_id, cloudbuild_api, cloud_project)
        if status:
          finished_builds_count += 1
          if status == 'SUCCESS':
            successful_builds[project].append(build_id)
          else:
            logs_url = build_lib.get_gcb_url(build_id, cloud_project)
            failed_builds[project].append((status, logs_url))

          wait_builds[project].remove(build_id)
          if not wait_builds[project]:
            del wait_builds[project]

        time.sleep(1)  # Avoid rate limiting.

  # Final Report
  total_projects = (len(successful_builds) + len(failed_builds) +
                    len(skipped_projects))
  results = {
      'total': total_projects,
      'successful': len(successful_builds),
      'failed': len(failed_builds),
      'skipped': len(skipped_projects),
      'failed_projects': sorted(list(failed_builds.keys())),
  }
  with open(f'{version_tag}-results.json', 'w') as f:
    json.dump(results, f)

  summary_title = f'BUILD REPORT: {version_tag.upper()}'
  summary_lines = [
      f"Total projects analyzed: {total_projects}",
      f"✅ Successful builds: {len(successful_builds)}",
      f"❌ Failed builds: {len(failed_builds)}",
      f"➖ Skipped projects: {len(skipped_projects)}",
  ]
  _print_summary_box(summary_title, summary_lines)

  if skipped_projects:
    logging.info('\n--- SKIPPED PROJECTS ---')
    for project, reason in sorted(skipped_projects):
      logging.info('  - %s: %s', project, reason)

  if failed_builds:
    logging.error('\n--- FAILED BUILDS ---')
    for project, failures in sorted(failed_builds.items()):
      logging.error('  - %s:', project)
      for status, gcb_url in failures:
        build_id = gcb_url.split('/')[-1].split('?')[0]
        logging.error('    - Build ID: %s', build_id)
        logging.error('    - Status: %s', status)
        logging.error('    - GCB URL: %s', gcb_url)
    logging.info('-----------------------')
    return False

  if not finished_builds_count and not skipped_projects:
    logging.warning('No builds were run.')
    return False

  logging.info('\nAll builds passed successfully!')
  logging.info('------------------------')
  return True


if __name__ == '__main__':
  sys.exit(main())
