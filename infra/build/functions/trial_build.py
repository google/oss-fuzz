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
import time
import urllib.request
import yaml

import build_and_push_test_images
import build_and_run_coverage
import build_lib
import build_project


# Default timeout in seconds, 7 hours.
DEFAULT_TIMEOUT = 25200
TEST_IMAGE_SUFFIX = 'testing'
MAX_BUILD_STEPS = 300

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


def _gcb_build_and_run_project_tests(args, test_image_tag):
  """Submits and waits on the test phase build."""
  steps = []
  build_types = []
  sanitizers = list(args.sanitizers)
  if 'coverage' in sanitizers:
    sanitizers.remove('coverage')
    build_types.append(BUILD_TYPES['coverage'])
  if 'introspector' in sanitizers:
    sanitizers.remove('introspector')
    build_types.append(BUILD_TYPES['introspector'])
  if sanitizers:
    build_types.append(BUILD_TYPES['fuzzing'])

  for build_type in build_types:
    projects_to_build = get_projects_to_build(args.projects, build_type,
                                              args.force_build)
    for project_name in projects_to_build:
      try:
        project_yaml, dockerfile_contents = build_project.get_project_data(
            project_name)
      except FileNotFoundError:
        logging.error('Couldn\'t get project data for %s.', project_name)
        continue

      build_project.set_yaml_defaults(project_yaml)

      # Use a deep copy to avoid modifying the original args.
      project_args = argparse.Namespace(**vars(args))

      project_yaml_sanitizers = build_project.get_sanitizer_strings(
          project_yaml.get('sanitizers', []))
      project_args.sanitizers = list(
          set(project_yaml_sanitizers).intersection(set(args.sanitizers)))

      project_yaml_engines = project_yaml.get('fuzzing_engines', [])
      project_args.fuzzing_engines = list(
          set(project_yaml_engines).intersection(set(args.fuzzing_engines)))

      if not project_args.sanitizers or not project_args.fuzzing_engines:
        continue

      config = build_project.Config(testing=True,
                                    test_image_suffix=test_image_tag,
                                    repo=project_args.repo,
                                    branch=project_args.branch,
                                    parallel=False,
                                    upload=False)

      build_steps = build_type.get_build_steps_func(project_name, project_yaml,
                                                    dockerfile_contents,
                                                    config)
      if not build_steps:
        logging.error('No steps for %s.', project_name)
        continue

      for step in build_steps:
        step[
            'id'] = f'{project_name}-{build_type.type_name}-{step.get("id", "")}'
        step['allowFailure'] = True
        step['waitFor'] = ['-']
      steps.extend(build_steps)

  if not steps:
    logging.error('No projects to build.')
    return True

  batch_build_ids = []
  for i in range(0, len(steps), MAX_BUILD_STEPS):
    batch_steps = steps[i:i + MAX_BUILD_STEPS]
    tags = ['trial-build', 'testing-projects-batch']
    if args.branch:
      tags.append(f'branch-{args.branch.lower().replace("/", "-")}')
    if args.version_tag:
      tags.append(f'version-{args.version_tag}')

    build_body = build_lib.get_build_body(batch_steps,
                                          timeout=DEFAULT_TIMEOUT,
                                          body_overrides={},
                                          tags=tags)

    yaml_file = os.path.join(build_and_push_test_images.OSS_FUZZ_ROOT,
                             'cloudbuild-testing-batch.yaml')
    with open(yaml_file, 'w', encoding='utf-8') as file_handle:
      yaml.dump(build_body, file_handle)

    gcloud_command = [
        'gcloud', 'builds', 'submit', '--project=oss-fuzz-base',
        f'--config={yaml_file}', '--format=json', '--async'
    ]
    process = subprocess.Popen(gcloud_command,
                               cwd=build_and_push_test_images.OSS_FUZZ_ROOT,
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()
    if process.returncode != 0:
      logging.error('Error submitting build: %s', stderr.decode())
      return False

    if not stdout:
      logging.error('gcloud builds submit returned empty stdout.')
      return False

    build_info = json.loads(stdout)
    build_id = build_info['id']
    logging.info('Successfully submitted build with ID: %s', build_id)
    batch_build_ids.append(build_id)

  return _wait_on_builds_and_report_results(batch_build_ids)


def _wait_on_builds_and_report_results(build_ids):
  """Waits on a list of GCB builds, then analyzes and reports results."""
  print('\nWaiting for all batch builds to complete...')
  finished_builds = 0
  while finished_builds < len(build_ids):
    finished_builds = 0
    for build_id in build_ids:
      try:
        gcloud_command = [
            'gcloud', 'builds', 'describe', build_id, '--project=oss-fuzz-base',
            '--format=json', '--region=us-central1'
        ]
        build_info_raw = subprocess.check_output(gcloud_command)
        build_info = json.loads(build_info_raw)
        if build_info['status'] in ('SUCCESS', 'FAILURE', 'TIMEOUT',
                                    'CANCELLED', 'EXPIRED'):
          finished_builds += 1
      except (subprocess.CalledProcessError, json.JSONDecodeError) as error:
        print(f'Error checking status of build {build_id}: {error}')
        finished_builds += 1
    if finished_builds < len(build_ids):
      print(f'  {finished_builds} / {len(build_ids)} batches complete. '
            'Waiting 60 seconds...')
      time.sleep(60)

  print('\nAll batch builds finished. Analyzing results...')
  successful_builds = []
  failed_builds = {}

  for build_id in build_ids:
    try:
      gcloud_command = [
          'gcloud', 'builds', 'describe', build_id, '--project=oss-fuzz-base',
          '--format=json', '--region=us-central1'
      ]
      build_info_raw = subprocess.check_output(gcloud_command)
      build_info = json.loads(build_info_raw)
      for step in build_info.get('steps', []):
        build_name = step.get('id', 'unknown-step')
        status = step.get('status', 'UNKNOWN')
        if status == 'SUCCESS':
          successful_builds.append(build_name)
        else:
          failed_builds[build_name] = (status, build_info.get('logUrl', 'N/A'))
    except (subprocess.CalledProcessError, json.JSONDecodeError) as error:
      print(f'Error analyzing build {build_id}: {error}')

  print('\n--- FINAL BUILD REPORT ---')
  total_builds = len(successful_builds) + len(failed_builds)
  print(f'Total builds tested: {total_builds}')
  print(f'  - Successful: {len(successful_builds)}')
  print(f'  - Failed: {len(failed_builds)}')

  if failed_builds:
    print('\n--- FAILED BUILDS ---')
    for name, (status, log_url) in failed_builds.items():
      print(f'  - Build: {name}')
      print(f'    Status: {status}')
      print(f'    Logs: {log_url}')
    print('-----------------------')
    return False

  print('\nAll builds passed successfully!')
  print('------------------------')
  return True


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
      build_and_push_test_images.gcb_build_and_push_images(
          test_image_tag, version_tag=args.version_tag)
    logging.info('"Build and Push Images" phase completed.')
  else:
    logging.info('Skipping "Build and Push Images" phase as requested.')

  logging.info('Starting "Testing Projects" phase...')
  result = _gcb_build_and_run_project_tests(args, test_image_tag)
  logging.info('"Testing Projects" phase completed.')
  return result


def main():
  """Builds and pushes test images, then runs project tests."""
  logging.basicConfig(level=logging.INFO)
  return 0 if trial_build_main() else 1


if __name__ == '__main__':
  sys.exit(main())
