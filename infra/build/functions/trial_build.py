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
import logging
import os
import subprocess
import sys
import yaml

import build_and_push_test_images
import build_lib
import build_project

# Default timeout in seconds, 7 hours.
DEFAULT_TIMEOUT = 25200
TEST_IMAGE_SUFFIX = 'testing'


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


import json
import time

# ... (imports existentes) ...

def _gcb_build_and_run_project_tests(args):
  """Submits and waits on the test phase build."""
  # GCB has a limit of 255 steps per build.
  BATCH_SIZE = 100
  projects = args.projects
  batch_build_ids = []
  print('Starting parallel batch builds.')

  for i in range(0, len(projects), BATCH_SIZE):
    batch = projects[i:i + BATCH_SIZE]
    steps = []
    for project in batch:
      # Construct the args for the nested build.
      nested_args = [project] + [
          '--sanitizers'
      ] + args.sanitizers + ['--fuzzing-engines'] + args.fuzzing_engines + [
          '--repo', args.repo, '--branch', args.branch or 'main',
          f'--version-tag={args.version_tag}'
      ]
      if args.force_build:
        nested_args.append('--force-build')

      steps.append({
          'name': 'gcr.io/oss-fuzz-base/base-builder',
          'entrypoint': 'python3',
          'args': ['infra/build/functions/build_and_run_project_tests.py'
                  ] + nested_args,
          'id': f'test-{project}',
          'allowFailure': True,
          'waitFor': ['-']
      })

    tags = ['trial-build', 'testing-projects-batch']
    if args.branch:
      tags.append(f'branch-{args.branch.lower().replace("/", "-")}')
    if args.version_tag:
      tags.append(f'version-{args.version_tag}')

    build_body = build_lib.get_build_body(steps,
                                          timeout=DEFAULT_TIMEOUT,
                                          body_overrides={},
                                          tags=tags)

    yaml_file = os.path.join(build_and_push_test_images.OSS_FUZZ_ROOT,
                             f'cloudbuild-testing-batch-{i//BATCH_SIZE}.yaml')
    with open(yaml_file, 'w') as yaml_file_handle:
      yaml.dump(build_body, yaml_file_handle)

    # Submit the build asynchronously.
    gcloud_command = [
        'gcloud', 'builds', 'submit', '--project=oss-fuzz-base',
        f'--config={yaml_file}', '--format=json'
    ]
    process = subprocess.Popen(gcloud_command,
                               cwd=build_and_push_test_images.OSS_FUZZ_ROOT,
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()
    if process.returncode != 0:
      print(f'Error submitting build for batch {i//BATCH_SIZE}:',
            stderr.decode())
      continue

    build_info = json.loads(stdout)
    build_id = build_info['id']
    batch_build_ids.append(build_id)
    print(f'Successfully submitted build for batch {i//BATCH_SIZE} with '
          f'build ID: {build_id}')

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
            '--format=json'
        ]
        build_info_raw = subprocess.check_output(gcloud_command)
        build_info = json.loads(build_info_raw)
        if build_info['status'] in ('SUCCESS', 'FAILURE', 'TIMEOUT',
                                    'CANCELLED', 'EXPIRED'):
          finished_builds += 1
      except (subprocess.CalledProcessError, json.JSONDecodeError) as error:
        print(f'Error checking status of build {build_id}: {error}')
        # Consider a failed check as a finished build to avoid infinite loops.
        finished_builds += 1
    if finished_builds < len(build_ids):
      print(f'  {finished_builds} / {len(build_ids)} batches complete. '
            'Waiting 60 seconds...')
      time.sleep(60)

  print('\nAll batch builds finished. Analyzing results...')
  successful_projects = []
  failed_projects = {}  # project_name -> (status, log_url)

  for build_id in build_ids:
    try:
      gcloud_command = [
          'gcloud', 'builds', 'describe', build_id, '--project=oss-fuzz-base',
          '--format=json'
      ]
      build_info_raw = subprocess.check_output(gcloud_command)
      build_info = json.loads(build_info_raw)
      for step in build_info.get('steps', []):
        project_name = step['id'].replace('test-', '')
        status = step.get('status', 'UNKNOWN')
        if status == 'SUCCESS':
          successful_projects.append(project_name)
        else:
          failed_projects[project_name] = (status,
                                           build_info.get('logUrl', 'N/A'))
    except (subprocess.CalledProcessError, json.JSONDecodeError) as error:
      print(f'Error analyzing build {build_id}: {error}')

  # Final Report
  print('\n--- FINAL BUILD REPORT ---')
  total_projects = len(successful_projects) + len(failed_projects)
  print(f'Total projects tested: {total_projects}')
  print(f'  - Successful: {len(successful_projects)}')
  print(f'  - Failed: {len(failed_projects)}')

  if failed_projects:
    print('\n--- FAILED PROJECTS ---')
    for name, (status, log_url) in failed_projects.items():
      print(f'  - Project: {name}')
      print(f'    Status: {status}')
      print(f'    Logs: {log_url}')
    print('-----------------------')
    return False  # Indicate failure

  print('\nAll projects passed successfully!')
  print('------------------------')
  return True

def trial_build_main(args=None, local_base_build=True):
  """Main function for trial_build. Pushes test images and then does test
  builds."""
  args = get_args(args)

  test_image_suffix = TEST_IMAGE_SUFFIX
  if args.branch:
    test_image_suffix = f'{test_image_suffix}-{args.branch.lower().replace("/", "-")}'
  if args.version_tag:
    test_image_suffix = f'{test_image_suffix}-{args.version_tag}'

  # Phase 1: Build and push images.
  if not args.skip_build_images:
    logging.info('Starting "Build and Push Images" phase...')
    if local_base_build:
      build_and_push_test_images.build_and_push_images(test_image_suffix)
    else:
      build_and_push_test_images.gcb_build_and_push_images(
          test_image_suffix, version_tag=args.version_tag)
    logging.info('"Build and Push Images" phase completed.')
  else:
    logging.info('Skipping "Build and Push Images" phase as requested.')

  # Phase 2: Trigger the project testing build.
  logging.info('Starting "Testing Projects" phase...')
  result = _gcb_build_and_run_project_tests(args)
  logging.info('"Testing Projects" phase completed.')
  return result

def main():
  """Builds and pushes test images of the base images. Then does test coverage
  and fuzzing builds using the test images."""
  logging.basicConfig(level=logging.INFO)
  return 0 if trial_build_main() else 1


if __name__ == '__main__':
  sys.exit(main())
