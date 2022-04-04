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
import subprocess
import sys

import oauth2client.client

import base_images
import build_lib
import trial_build

CLOUD_PROJECT = 'oss-fuzz-base'
TAG_PREFIX = f'gcr.io/{CLOUD_PROJECT}/'
INFRA_DIR = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
IMAGES_DIR = os.path.join(INFRA_DIR, 'base-images')


def push_image(tag):
  """Pushes image with |tag| to docker registry."""
  logging.info('Pushing: %s', tag)
  command = ['docker', 'push', tag]
  subprocess.run(command, check=True)
  logging.info('Pushed: %s', tag)


def build_and_push_image(image, test_image_suffix):
  """Builds and pushes |image| to docker registry with "-testing" suffix."""
  main_tag = TAG_PREFIX + image
  testing_tag = main_tag + '-' + test_image_suffix
  tags = [main_tag, testing_tag]
  build_image(image, tags)
  push_image(testing_tag)


def build_image(image, tags):
  """Builds |image| and tags it with |tags|."""
  logging.info('Building: %s', image)
  command = ['docker', 'build']
  for tag in tags:
    command.extend(['--tag', tag])
    path = os.path.join(IMAGES_DIR, image)
  command.append(path)
  subprocess.run(command, check=True)
  logging.info('Built: %s', image)


def gcb_build_and_push_images(test_image_suffix):
  """Build and push test versions of base images using GCB."""
  steps = [build_lib.get_git_clone_step()]
  test_images = []
  for base_image in base_images.BASE_IMAGES:
    image_name = TAG_PREFIX + base_image
    test_image_name = f'{image_name}-{test_image_suffix}'
    test_images.append(test_image_name)
    directory = os.path.join('infra', 'base-images', base_image)
    step = build_lib.get_docker_build_step([image_name, test_image_name],
                                           directory)
    steps.append(step)

  overrides = {'images': test_images}
  credentials = oauth2client.client.GoogleCredentials.get_application_default()
  build_id = build_lib.run_build(steps, credentials, base_images.BASE_PROJECT,
                                 base_images.TIMEOUT, overrides,
                                 ['trial-build'])
  return trial_build.wait_on_builds({'base-images': build_id}, credentials,
                                    CLOUD_PROJECT)


def build_and_push_images(test_image_suffix):
  """Builds and pushes base-images."""
  images = [
      ['base-image'],
      ['base-clang'],
      # base-runner is also dependent on base-clang.
      ['base-builder', 'base-runner'],
      # Exclude 'base-builder-swift' as it takes extremely long to build because
      # it clones LLVM.
      [
          'base-runner-debug',
          'base-builder-go',
          'base-builder-jvm',
          'base-builder-python',
          'base-builder-rust',
      ],
  ]
  max_parallelization = max([len(image_list) for image_list in images])
  proc_count = min(multiprocessing.cpu_count(), max_parallelization)
  logging.info('Using %d parallel processes.', proc_count)
  pool = multiprocessing.Pool(proc_count)
  for image_list in images:
    args_list = [(image, test_image_suffix) for image in image_list]
    pool.starmap(build_and_push_image, args_list)


def main():
  """"Builds base-images tags them with "-testing" suffix (in addition to normal
  tag) and pushes testing suffixed images to docker registry."""
  test_image_suffix = sys.argv[1]
  logging.basicConfig(level=logging.DEBUG)
  logging.info('Doing simple gcloud command to ensure 2FA passes.')
  subprocess.run(['gcloud', 'projects', 'list', '--limit=1'], check=True)
  build_and_push_images(test_image_suffix)


if __name__ == '__main__':
  main()
