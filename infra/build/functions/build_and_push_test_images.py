#! /usr/bin/env python3
# Copyright 2021 Google LLC
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
"""Script for building and pushing base-images to gcr.io/oss-fuzz-base/ with
"-test" suffix. This is useful for using the build infra to test image
changes."""
import logging
import multiprocessing
import os
import re
import subprocess
import sys
import time

import google.auth
import yaml
from googleapiclient.discovery import build as cloud_build

import base_images
import build_lib

CLOUD_PROJECT = 'oss-fuzz-base'
INFRA_DIR = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
IMAGES_DIR = os.path.join(INFRA_DIR, 'base-images')
OSS_FUZZ_ROOT = os.path.dirname(INFRA_DIR)
GCB_BUILD_TAGS = ['trial-build']

# Add the new Ubuntu versions to the list of versions to build.
BASE_IMAGE_VERSIONS = ['legacy', 'ubuntu-20-04', 'ubuntu-24-04']


def push_image(tag):
  """Pushes image with |tag| to docker registry."""
  logging.info('Pushing: %s', tag)
  command = ['docker', 'push', tag]
  subprocess.run(command, check=True)
  logging.info('Pushed: %s', tag)


def build_and_push_image(image, test_image_tag, version='legacy'):
  """Builds and pushes |image| to docker registry with "-testing" suffix."""
  main_image_name, test_image_name = get_image_tags(image, test_image_tag,
                                                    version)
  build_image(image, [main_image_name, test_image_name], main_image_name,
              version)
  push_image(test_image_name)


def build_image(image, tags, cache_from_tag, version='latest'):
  """Builds |image| and tags it with |tags|."""
  logging.info('Building: %s', image)
  command = ['docker', 'build']
  for tag in tags:
    command.extend(['--tag', tag])
  path = os.path.join(IMAGES_DIR, image)
  if version != 'legacy':
    command.extend(['-f', os.path.join(path, f'{version}.Dockerfile')])
  command.extend([
      '--build-arg', 'BUILDKIT_INLINE_CACHE=1', '--cache-from', cache_from_tag
  ])
  command.append(path)
  subprocess.run(command, check=True)
  logging.info('Built: %s', image)


def _run_cloudbuild(build_body):
  """Runs a cloud build and returns the build ID."""
  yaml_file = os.path.join(OSS_FUZZ_ROOT, 'cloudbuild.yaml')
  with open(yaml_file, 'w') as yaml_file_handle:
    yaml.dump(build_body, yaml_file_handle)

  # Use --async to not wait on the build.
  result = subprocess.run([
      'gcloud', 'builds', 'submit', '--project=oss-fuzz-base',
      f'--config={yaml_file}', '--async', '--format=value(id)'
  ],
                          cwd=OSS_FUZZ_ROOT,
                          check=True,
                          capture_output=True,
                          text=True)
  return result.stdout.strip()


def wait_for_build_and_report_summary(build_id, cloud_project='oss-fuzz-base'):
  """Waits for a GCB build to complete and reports a detailed summary."""
  logs_url = build_lib.get_logs_url(build_id)
  credentials, _ = google.auth.default()
  cloudbuild = cloud_build('cloudbuild',
                           'v1',
                           credentials=credentials,
                           cache_discovery=False,
                           client_options=build_lib.REGIONAL_CLIENT_OPTIONS)
  cloudbuild_api = cloudbuild.projects().builds()

  logging.info(
      '================================================================')
  logging.info('            PHASE 1: STARTED BASE IMAGE BUILD')
  logging.info(
      '----------------------------------------------------------------')
  for line in build_lib.get_build_info_lines(build_id, cloud_project):
    logging.info(line)
  logging.info(
      '================================================================')

  logging.info('Waiting for base image build to complete...')
  build_result = None
  while True:
    try:
      build_result = cloudbuild_api.get(projectId=cloud_project,
                                        id=build_id).execute()
      status = build_result['status']
      if status in ('SUCCESS', 'FAILURE', 'TIMEOUT', 'CANCELLED', 'EXPIRED'):
        break
    except Exception as e:
      logging.error('Error checking build status: %s', e)
    time.sleep(15)

  logging.info(
      '================================================================')
  logging.info('            PHASE 1: BASE IMAGE BUILD REPORT')
  logging.info(
      '----------------------------------------------------------------')
  for line in build_lib.get_build_info_lines(build_id, cloud_project):
    logging.info(line)
  logging.info(
      '================================================================')

  if not build_result or 'steps' not in build_result:
    logging.error('Could not retrieve build steps. See logs for details: %s',
                  logs_url)
    return False

  # Detailed step-by-step report
  succeeded_steps = 0
  failed_steps = []
  for step in build_result['steps']:
    step_id = step.get('id', step.get('name', 'Unnamed Step'))
    step_status = step.get('status', 'UNKNOWN')
    if step_status == 'SUCCESS':
      logging.info('  - %s: %s', step_id, step_status)
      succeeded_steps += 1
    else:
      logging.error('  - %s: %s', step_id, step_status)
      failed_steps.append(step_id)

  logging.info(
      '----------------------------------------------------------------')
  logging.info('Summary: %d succeeded, %d failed.', succeeded_steps,
               len(failed_steps))
  logging.info(
      '================================================================')

  if failed_steps:
    logging.error('The following images failed to build: %s',
                  ', '.join(failed_steps))
    logging.error('See full logs for details: %s', logs_url)
    return False

  logging.info('All base images built successfully.')
  return True


def get_image_tags(image: str,
                   test_image_tag: str | None = None,
                   version: str = 'legacy'):
  """Returns tags for image build."""
  if version == 'legacy':
    main_image_name = f'{base_images.IMAGE_NAME_PREFIX}{image}'
  else:
    main_image_name = f'{base_images.IMAGE_NAME_PREFIX}{image}:{version}'

  test_image_name = None
  if test_image_tag:
    test_image_name = (
        f'{base_images.IMAGE_NAME_PREFIX}{image}-{test_image_tag}')

  return main_image_name, test_image_name


def gcb_build_and_push_images(test_image_tag: str, version_tag: str = None):
  """Build and push test versions of base images using GCB."""
  # Define the dependency hierarchy for base images.
  IMAGE_DEPENDENCIES = {
      'base-clang': ['base-image'],
      'base-clang-full': ['base-clang'],
      'base-builder': ['base-clang'],
      'base-runner': [
          'base-image', 'base-clang', 'base-builder', 'base-builder-ruby'
      ],
      'base-builder-go': ['base-builder'],
      'base-builder-javascript': ['base-builder'],
      'base-builder-jvm': ['base-builder'],
      'base-builder-python': ['base-builder'],
      'base-builder-ruby': ['base-builder'],
      'base-builder-rust': ['base-builder'],
      'base-builder-swift': ['base-builder'],
      'base-runner-debug': ['base-runner'],
      'indexer': ['base-clang-full'],
  }

  steps = []
  added_step_ids = set()
  test_image_names = []
  versions = [version_tag] if version_tag else BASE_IMAGE_VERSIONS
  for version in versions:
    for base_image_def in base_images.BASE_IMAGE_DEFS:
      base_image = base_images.ImageConfig(version=version, **base_image_def)
      main_image_name, test_image_name = get_image_tags(base_image.name,
                                                        test_image_tag, version)
      test_image_names.append(test_image_name)

      if version == 'legacy':
        dockerfile = os.path.join(base_image.path, 'Dockerfile')
      else:
        dockerfile = os.path.join(base_image.path, f'{version}.Dockerfile')

      # Skip building if the Dockerfile does not exist.
      if not os.path.exists(os.path.join(OSS_FUZZ_ROOT, dockerfile)):
        logging.info('Skipping %s for version %s as it does not exist.',
                     dockerfile, version)
        continue

      intermediate_tag = base_images.IMAGE_NAME_PREFIX + base_image.name
      tags_for_build = sorted(
          list(set([main_image_name, test_image_name, intermediate_tag])))

      # Get dependency tags for caching.
      dependencies = IMAGE_DEPENDENCIES.get(base_image.name, [])
      if not isinstance(dependencies, list):
        dependencies = [dependencies]

      cache_tags = []
      for dep_name in dependencies:
        dep_main_tag, _ = get_image_tags(dep_name, None, version)
        cache_tags.append(dep_main_tag)

      step = build_lib.get_docker_build_step(
          tags_for_build,
          base_image.path,
          use_buildkit_cache=True,
          src_root='.',
          build_args=base_image.build_args,
          dockerfile_path=dockerfile,
          additional_cache_from_tags=cache_tags)

      # Add a unique ID to each step for dependency tracking.
      step_id = f'build-{base_image.name}-{version}'
      step['id'] = step_id

      # Add 'waitFor' if the image has dependencies that have been added.
      wait_for_ids = []
      for dependency in dependencies:
        dependency_id = f'build-{dependency}-{version}'
        if dependency_id in added_step_ids:
          wait_for_ids.append(dependency_id)
      if wait_for_ids:
        step['waitFor'] = wait_for_ids

      steps.append(step)
      added_step_ids.add(step_id)

  build_body = build_lib.get_build_body(steps, base_images.TIMEOUT,
                                        {'images': test_image_names},
                                        GCB_BUILD_TAGS + [test_image_tag])
  build_id = _run_cloudbuild(build_body)
  return wait_for_build_and_report_summary(build_id)


def build_and_push_images(test_image_tag, version_tag=None):
  """Builds and pushes base-images."""
  images = [
      ['base-image'],
      ['base-clang'],
      ['base-clang-full'],
      ['indexer'],
      ['base-builder'],
      [
          'base-builder-swift',
          'base-builder-ruby',
          'base-builder-rust',
          'base-builder-go',
          'base-builder-javascript',
          'base-builder-jvm',
          'base-builder-python',
      ],
      ['base-runner'],
      ['base-runner-debug'],
  ]
  os.environ['DOCKER_BUILDKIT'] = '1'
  max_parallelization = max([len(image_list) for image_list in images])
  proc_count = min(multiprocessing.cpu_count(), max_parallelization)
  logging.info('Using %d parallel processes.', proc_count)
  with multiprocessing.Pool(proc_count) as pool:
    for image_list in images:
      args_list = []
      for image in image_list:
        versions = [version_tag] if version_tag else BASE_IMAGE_VERSIONS
        for version in versions:
          # Check if the specific versioned Dockerfile exists before adding.
          if version == 'legacy':
            dockerfile_path = os.path.join(IMAGES_DIR, image, 'Dockerfile')
          else:
            dockerfile_path = os.path.join(IMAGES_DIR, image,
                                           f'{version}.Dockerfile')
          if os.path.exists(dockerfile_path):
            args_list.append((image, test_image_tag, version))

      pool.starmap(build_and_push_image, args_list)


def main():
  """Builds base-images tags them with "-testing" suffix (in addition to normal
  tag) and pushes testing suffixed images to docker registry."""
  test_image_tag = sys.argv[1]
  logging.basicConfig(level=logging.DEBUG)
  logging.info('Doing simple gcloud command to ensure 2FA passes.')
  subprocess.run(['gcloud', 'projects', 'list', '--limit=1'], check=True)
  build_and_push_images(test_image_tag)


if __name__ == '__main__':
  main()
