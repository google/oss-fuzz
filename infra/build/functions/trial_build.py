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
import random
import logging
import os
import subprocess
import sys
import textwrap
import time
import urllib.request
import urllib.error
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
    'indexer':
        BuildType('indexer', build_project.get_indexer_build_steps,
                  'status.json'),
    'fuzzing':
        BuildType('fuzzing', build_project.get_build_steps, 'status.json'),
}


def _get_production_build_statuses(build_type):
  """Gets the statuses for |build_type| that is reported by build-status.
  Returns a dictionary mapping projects to bools indicating whether the last
  build of |build_type| succeeded."""
  try:
    request = urllib.request.urlopen(
        'https://oss-fuzz-build-logs.storage.googleapis.com/'
        f'{build_type.status_filename}')
    project_statuses = json.load(request)['projects']
  except urllib.error.URLError:
    # It is not a critical error if the status file cannot be found.
    # This is expected for indexer.
    return {}

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
  parser.add_argument('--sanitizers',
                      required=False,
                      default=[
                          'address', 'memory', 'undefined', 'coverage',
                          'introspector', 'indexer'
                      ],
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


def handle_phase1_failure(version_tag):
  """Handles the case where phase 1 (image build) fails."""
  all_projects = get_all_projects()
  results = {
      'total': len(all_projects),
      'successful': 0,
      'failed': len(all_projects),
      'skipped': 0,
      'failed_projects': all_projects,
  }
  if version_tag:
    with open(f'{version_tag}-results.json', 'w') as f:
      json.dump(results, f)
  logging.error(
      'Failed to build and push images. All projects for this version will be '
      'marked as failed.')
  return False


def get_projects_to_build(specified_projects, build_type, force_build):
  """Returns the list of projects that should be built."""
  buildable_projects = []
  project_statuses = _get_production_build_statuses(build_type)
  for project in specified_projects:
    if (project not in project_statuses or project_statuses[project] or
        force_build):
      buildable_projects.append(project)
  return buildable_projects


def trial_build_main(args=None, local_base_build=True):
  """Main function for trial_build."""
  args = get_args(args)

  if not args.skip_build_images:
    logging.info('Starting "Build and Push Images" phase...')

    versions_to_build = ([args.version_tag] if args.version_tag else
                         build_and_push_test_images.BASE_IMAGE_VERSIONS)

    for version in versions_to_build:
      logging.info(
          '================================================================')
      logging.info('      BUILDING BASE IMAGES FOR VERSION: %s',
                   version.upper())
      logging.info(
          '================================================================')
      version_test_image_tag = f'{TEST_IMAGE_SUFFIX}-{version}'
      if args.branch:
        version_test_image_tag = (
            f'{version_test_image_tag}-{args.branch.lower().replace("/", "-")}')

      if local_base_build:
        build_and_push_test_images.build_and_push_images(
            version_test_image_tag, version)
      else:
        if not build_and_push_test_images.gcb_build_and_push_images(
            version_test_image_tag, version_tag=version):
          return handle_phase1_failure(version)

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

  if local_base_build and not args.version_tag:
    versions_to_build = build_and_push_test_images.BASE_IMAGE_VERSIONS
    if not versions_to_build:
      return False

    overall_result = True
    for version in versions_to_build:
      logging.info(
          '================================================================')
      logging.info('      RUNNING TEST BUILDS FOR VERSION: %s', version.upper())
      logging.info(
          '================================================================')
      test_image_tag = f'{TEST_IMAGE_SUFFIX}-{version}'
      if args.branch:
        test_image_tag = (
            f'{test_image_tag}-{args.branch.lower().replace("/", "-")}')

      result = _do_test_builds(args, test_image_tag, end_time, version)
      overall_result = overall_result and result
    return overall_result

  # GCB or local single-version case
  test_image_tag = TEST_IMAGE_SUFFIX
  if args.version_tag:
    test_image_tag = f'{test_image_tag}-{args.version_tag}'
  if args.branch:
    test_image_tag = f'{test_image_tag}-{args.branch.lower().replace("/", "-")}'
  return _do_test_builds(args, test_image_tag, end_time, args.version_tag)


def _do_test_builds(args, test_image_suffix, end_time, version_tag):
  """Does test coverage and fuzzing builds."""
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
  skipped_projects = collections.defaultdict(list)
  failed_to_start_builds = []
  credentials = oauth2client.client.GoogleCredentials.get_application_default()

  logging.info(
      '================================================================')
  logging.info('            PHASE 2: STARTING TEST BUILDS')
  logging.info(
      '================================================================')

  for build_type in build_types:
    specified_projects = list(args.projects)
    projects_to_build = get_projects_to_build(specified_projects, build_type,
                                              args.force_build)
    if not args.force_build:
      unselected_projects = set(specified_projects) - set(projects_to_build)
      for project in unselected_projects:
        skipped_projects[build_type.type_name].append(
            (project, 'Production build failed'))

      logging.info('Build type: %s', build_type.type_name)
      logging.info(
          '  - Selected projects: %d / %d (due to successful production builds)',
          len(projects_to_build), len(args.projects))
      logging.info('  - To build all projects, use the --force-build flag.')
    else:
      logging.info('Build type: %s', build_type.type_name)
      logging.info('  - Building all %d projects (--force-build)',
                   len(projects_to_build))

    logging.info('Starting to create and trigger builds for build type: %s',
                 build_type.type_name)

    config = build_project.Config(testing=True,
                                  test_image_suffix=test_image_suffix,
                                  base_image_tag=version_tag,
                                  repo=args.repo,
                                  branch=args.branch,
                                  parallel=False,
                                  upload=False,
                                  build_type=build_type.type_name)
    project_builds, new_skipped, new_failed_to_start = _do_build_type_builds(
        args, config, credentials, build_type, projects_to_build)
    for project, reason in new_skipped:
      skipped_projects[build_type.type_name].append((project, reason))
    failed_to_start_builds.extend(new_failed_to_start)
    for project, project_build_id in project_builds.items():
      build_ids[project].append((project_build_id, build_type.type_name))

  logging.info('Triggered all builds.')
  if skipped_projects:
    logging.info(
        '================================================================')
    logging.info('               PHASE 2: SKIPPED BUILDS')
    logging.info(
        '================================================================')
    total_skipped_builds = sum(
        len(skips) for skips in skipped_projects.values())
    logging.info('Total skipped builds: %d', total_skipped_builds)
    logging.info('--- SKIPPED BUILDS ---')
    for build_type_name, skips in sorted(skipped_projects.items()):
      logging.info('  - %s:', build_type_name)
      for project, reason in sorted(skips):
        logging.info('    - %s: %s', project, reason)
    logging.info('-----------------------')

  logging.info(
      '================================================================')
  logging.info('               PHASE 2: STARTED BUILDS')
  logging.info(
      '================================================================')
  logging.info('Total projects with builds: %d', len(build_ids))
  logging.info('--- STARTED BUILDS ---')
  for project, project_builds in sorted(build_ids.items()):
    logging.info('  - %s:', project)
    for build_id, build_type in project_builds:
      logging.info('    - Build Type: %s', build_type)
      for line in build_lib.get_build_info_lines(build_id,
                                                 build_lib.IMAGE_PROJECT):
        logging.info('      %s', line)
  logging.info('-----------------------')

  wait_result = wait_on_builds(args, build_ids, credentials,
                               build_lib.IMAGE_PROJECT, end_time,
                               skipped_projects, version_tag)

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
        project_yaml['sanitizers']) + ['coverage', 'introspector', 'indexer']
    project_yaml['sanitizers'] = list(
        set(project_yaml_sanitizers).intersection(set(args.sanitizers)))

    project_yaml['fuzzing_engines'] = list(
        set(project_yaml['fuzzing_engines']).intersection(
            set(args.fuzzing_engines)))

    if not project_yaml['sanitizers'] or not project_yaml['fuzzing_engines']:
      skipped_projects.append(
          (project_name, 'No compatible sanitizers or engines'))
      continue

    # Check if project's base_os_version matches the current build version.
    project_base_os = project_yaml.get('base_os_version', 'legacy')
    current_build_version = config.base_image_tag or 'legacy'

    if project_base_os != current_build_version:
      skipped_projects.append(
          (project_name, f'Project requires {project_base_os}, but '
           f'build version is {current_build_version}'))
      continue

    steps, reason = build_type.get_build_steps_func(project_name, project_yaml,
                                                    dockerfile_contents, config)
    if reason:
      skipped_projects.append((project_name, reason))
      continue

    try:
      tags = ['trial-build']
      if args.branch:
        tags.append(f'branch-{args.branch.replace("/", "-")}')
      build_ids[project_name] = (build_project.run_build(
          project_name,
          steps,
          credentials,
          build_type.type_name,
          extra_tags=tags,
          timeout=PROJECT_BUILD_TIMEOUT))['id']
      time.sleep(1)  # Avoid going over 75 requests per second limit.
    except Exception as error:  # pylint: disable=broad-except
      # Handle flake.
      logging.error('Failed to start build %s: %s', project_name, error)
      failed_to_start_builds.append((project_name, error))

  return build_ids, skipped_projects, failed_to_start_builds


def _print_summary_box(title, lines):
  """Prints a formatted box for summarizing build results."""
  box_width = 80
  title_line = f'| {title.center(box_width - 4)} |'
  separator = '+' + '-' * (box_width - 2) + '+'
  summary_lines = [
      '+' + '-' * (box_width - 2) + '+',
      title_line,
      '+' + '-' * (box_width - 2) + '+',
  ]
  for line in lines:
    wrapped_lines = textwrap.wrap(line, box_width - 6)
    for i, sub_line in enumerate(wrapped_lines):
      summary_lines.append(f'|  {sub_line.ljust(box_width - 6)}  |')
  summary_lines.append('+' + '-' * (box_width - 2) + '+')
  print('\n'.join(summary_lines))


def get_build_status_from_gcb(cloudbuild_api, cloud_project, build_id):
  """Returns the status of the build: |build_id| from cloudbuild_api."""
  build_result = cloudbuild_api.get(projectId=cloud_project,
                                    id=build_id).execute()
  return build_result['status']


def check_finished(build_id, cloudbuild_api, cloud_project, retries_map):
  """Checks that the build is complete. Returns status if complete, else None"""
  try:
    build_status = get_build_status_from_gcb(cloudbuild_api, cloud_project,
                                             build_id)
  except HttpError:
    logging.debug('build: HttpError when getting build status from gcb')
    retries_map[build_id] = retries_map.get(build_id, 0) + 1
    return None
  if build_status not in FINISHED_BUILD_STATUSES:
    logging.debug('build: %d not finished.', build_id)
    return None
  return build_status


def wait_on_builds(args, build_ids, credentials, cloud_project, end_time,
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
  finished_builds_count = 0
  retries_map = {}
  next_retry_time = {}
  MAX_RETRIES = 5
  BASE_BACKOFF_SECONDS = 2

  builds_count = sum(len(v) for v in build_ids.values())
  projects_count = len(build_ids)
  logging.info('Waiting for %d builds from %d projects to complete...',
               builds_count, projects_count)

  timeout_warning_time = end_time - datetime.timedelta(
      minutes=BUILD_TIMEOUT_WARNING_MINUTES)
  notified_timeout = False

  while wait_builds:
    current_time = datetime.datetime.now()
    if current_time >= end_time:
      logging.error(
          'Coordinator timeout reached. Marking remaining builds as TIMEOUT.')
      break

    if not notified_timeout and current_time >= timeout_warning_time:
      notified_timeout = True
      logging.warning(
          'Nearing timeout: %d minutes remaining. Remaining builds: %d',
          BUILD_TIMEOUT_WARNING_MINUTES, len(wait_builds))

    processed_a_build_in_iteration = False
    for project, project_builds in list(wait_builds.items()):
      for build_id, build_type in project_builds[:]:
        if (build_id in next_retry_time and
            datetime.datetime.now() < next_retry_time[build_id]):
          continue  # In backoff period, skip for now.

        processed_a_build_in_iteration = True
        status = check_finished(build_id, cloudbuild_api, cloud_project,
                                retries_map)

        if status:
          # API call was successful, remove from backoff map if it exists.
          if build_id in next_retry_time:
            del next_retry_time[build_id]

          finished_builds_count += 1
          if status == 'SUCCESS':
            successful_builds[project].append(build_id)
          else:
            gcb_url = build_lib.get_gcb_url(build_id, cloud_project)
            log_url = build_lib.get_logs_url(build_id)
            failed_builds[project].append(
                (status, gcb_url, build_type, log_url))

          wait_builds[project].remove((build_id, build_type))
          if not wait_builds[project]:
            del wait_builds[project]

        elif retries_map.get(build_id, 0) >= MAX_RETRIES:
          # Max retries reached, mark as failed.
          logging.error('HttpError for build %s. Max retries reached.',
                        build_id)
          if build_id in next_retry_time:
            del next_retry_time[build_id]

          finished_builds_count += 1
          status = 'UNKNOWN (too many HttpErrors)'
          gcb_url = build_lib.get_gcb_url(build_id, cloud_project)
          log_url = build_lib.get_logs_url(build_id)
          failed_builds[project].append((status, gcb_url, build_type, log_url))
          wait_builds[project].remove((build_id, build_type))
          if not wait_builds[project]:
            del wait_builds[project]
        else:
          # API call failed, calculate and set next retry time.
          retry_count = retries_map.get(build_id, 0)
          backoff_time = (BASE_BACKOFF_SECONDS * (2**retry_count) +
                          random.uniform(0, 1))
          next_retry_time[build_id] = (datetime.datetime.now() +
                                       datetime.timedelta(seconds=backoff_time))

    if not processed_a_build_in_iteration and wait_builds:
      # All remaining builds are in backoff, sleep to prevent busy-waiting.
      time.sleep(1)
    else:
      # General rate limiting after one full pass.
      time.sleep(0.5)

  # Handle builds that were still running when the coordinator timed out.
  if wait_builds:
    for project, project_builds in list(wait_builds.items()):
      for build_id, build_type in project_builds:
        gcb_url = build_lib.get_gcb_url(build_id, cloud_project)
        log_url = build_lib.get_logs_url(build_id)
        failed_builds[project].append(
            ('TIMEOUT (Coordinator)', gcb_url, build_type, log_url))

  # Final Report
  successful_builds_count = sum(
      len(builds) for builds in successful_builds.values())
  failed_builds_count = sum(len(builds) for builds in failed_builds.values())
  skipped_builds_count = sum(len(skips) for skips in skipped_projects.values())

  # Note: To get all unique project names, we create a set from the keys of
  # successful_builds, failed_builds, and the project names in skipped_projects.
  all_projects_in_build = set(successful_builds.keys()) | set(
      failed_builds.keys()) | set(
          p for sl in skipped_projects.values() for p, r in sl)
  total_projects = len(all_projects_in_build)

  results = {
      'total_projects_analyzed':
          total_projects,
      'successful_builds':
          successful_builds_count,
      'failed_builds':
          failed_builds_count,
      'skipped_builds':
          skipped_builds_count,
      'failed_projects':
          sorted(list(failed_builds.keys())),
      'skipped_projects':
          sorted(list(set(p for sl in skipped_projects.values() for p, r in sl))
                ),
      'all_projects':
          sorted(list(all_projects_in_build)),
  }
  with open(f'{version_tag}-results.json', 'w') as f:
    json.dump(results, f)

  summary_title = f'BUILD REPORT: {version_tag.upper()}'
  summary_lines = [
      f"Total projects analyzed: {total_projects}",
      f"[PASSED]  Successful builds: {successful_builds_count}",
      f"[FAILED]  Failed builds: {failed_builds_count}",
      f"[SKIPPED] Skipped builds: {skipped_builds_count}",
  ]
  _print_summary_box(summary_title, summary_lines)

  if failed_builds:
    logging.error('--- FAILED BUILDS ---')
    for project, failures in sorted(failed_builds.items()):
      logging.error('  - %s:', project)
      for status, gcb_url, build_type, log_url in failures:
        build_id = gcb_url.split('/')[-1].split('?')[0]
        logging.error('    - Build Type: %s', build_type)
        logging.error('    - Status: %s', status)
        for line in build_lib.get_build_info_lines(build_id, cloud_project):
          logging.error('    - %s', line)
    logging.info('-----------------------')
    return False

  if not finished_builds_count and not skipped_builds_count:
    logging.warning('No builds were run.')
    if args.skip_build_images:
      return True
    return False

  logging.info('\nAll builds passed successfully!')
  logging.info('------------------------')
  return True


if __name__ == '__main__':
  sys.exit(trial_build_main())
