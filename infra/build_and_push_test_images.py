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
"-test" suffix. This is useful for reusing the build infra to test image
changes."""
import logging
import multiprocessing
import os
import subprocess

TAG_PREFIX = 'gcr.io/oss-fuzz-base/'
TESTING_TAG_SUFFIX = '-testing'
INFRA_DIR = os.path.dirname(__file__)
IMAGES_DIR = os.path.join(INFRA_DIR, 'base-images')


def push_image(tag):
  """Pushes image with |tag| to docker registry."""
  logging.info('Pushing: %s', tag)
  command = ['docker', 'push', tag]
  subprocess.run(command, check=True)
  logging.info('Pushed: %s', tag)


def build_and_push_image(image):
  """Builds and pushes |image| to docker registry with "-testing" suffix."""
  main_tag = TAG_PREFIX + image
  testing_tag = main_tag + TESTING_TAG_SUFFIX
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


def build_and_push_images():
  """Builds and pushes base-images."""
  images = [
      ['base-image'],
      ['base-clang', 'base-runner'],
      ['base-builder', 'base-runner-debug', 'base-builder-new'],
      ['base-runner-debug', 'base-sanitizer-build-libs', 'base-builder-swift'],
  ]
  max_parallelization = max([len(image_list) for image_list in images])
  proc_count = min(multiprocessing.cpu_count(), max_parallelization)
  pool = multiprocessing.Pool(proc_count)
  for image_list in images:
    pool.map(build_and_push_image, image_list)


def main():
  """"Builds base-images tags them with "-testing" suffix (in addition to normal
  tag) and pushes "-testing" suffixed images to docker registry."""
  logging.basicConfig(level=logging.DEBUG)
  logging.info('Doing simple gcloud command to ensure 2FA passes.')
  subprocess.run(['gcloud', 'projects', 'list', '--limit=1'], check=True)
  build_and_push_images()


if __name__ == '__main__':
  main()
