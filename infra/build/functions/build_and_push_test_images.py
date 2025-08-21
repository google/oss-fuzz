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

import yaml

import base_images
import build_lib

CLOUD_PROJECT = 'oss-fuzz-base'
INFRA_DIR = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
IMAGES_DIR = os.path.join(INFRA_DIR, 'base-images')
OSS_FUZZ_ROOT = os.path.dirname(INFRA_DIR)
GCB_BUILD_TAGS = ['trial-build']


def push_image(tag):
  """Pushes image with |tag| to docker registry."""
  logging.info('Pushing: %s', tag)
  command = ['docker', 'push', tag]
  subprocess.run(command, check=True)
  logging.info('Pushed: %s', tag)


def build_and_push_image(image, test_image_suffix):
  """Builds and pushes |image| to docker registry with "-testing" suffix."""
  main_tag, testing_tag = get_image_tags(image, test_image_suffix)
  build_image(image, [main_tag, testing_tag], testing_tag)
  push_image(testing_tag)


def build_image(image, tags, cache_from_tag):
  """Builds |image| and tags it with |tags|."""
  logging.info('Building: %s', image)
  command = ['docker', 'build']
  for tag in tags:
    command.extend(['--tag', tag])
    path = os.path.join(IMAGES_DIR, image)
  command.extend([
      '--build-arg', 'BUILDKIT_INLINE_CACHE=1', '--cache-from', cache_from_tag
  ])
  command.append(path)
  subprocess.run(command, check=True)
  logging.info('Built: %s', image)


def _run_cloudbuild(build_body):
  yaml_file = os.path.join(OSS_FUZZ_ROOT, 'cloudbuild.yaml')
  with open(yaml_file, 'w') as yaml_file_handle:
    yaml.dump(build_body, yaml_file_handle)

  subprocess.run([
      'gcloud', 'builds', 'submit', '--project=oss-fuzz-base',
      f'--config={yaml_file}'
  ],
                 cwd=OSS_FUZZ_ROOT,
                 check=True)


def get_image_tags(image: str, test_image_suffix: str | None = None):
  """Returns tags for image build."""
  main_tag = base_images.TAG_PREFIX + image
  test_tag = None

  if test_image_suffix:
    test_tag = main_tag + '-' + test_image_suffix

  return main_tag, test_tag


def gcb_build_and_push_images(test_image_suffix: str):
  """Build and push test versions of base images using GCB."""
  steps = []
  test_tags = []
  for base_image in base_images.BASE_IMAGES:
    main_tag, test_tag = get_image_tags(base_image.name, test_image_suffix)
    test_tags.append(test_tag)
    step = build_lib.get_docker_build_step([main_tag, test_tag],
                                           base_image.path,
                                           use_buildkit_cache=True,
                                           src_root='.')
    steps.append(step)

  overrides = {'images': test_tags}
  build_body = build_lib.get_build_body(steps, base_images.TIMEOUT, overrides,
                                        GCB_BUILD_TAGS + [test_image_suffix])
  _run_cloudbuild(build_body)


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
          'base-builder-javascript',
          'base-builder-jvm',
          'base-builder-python',
          'base-builder-ruby',
          'base-builder-rust',
          'base-builder-ruby',
      ],
  ]
  os.environ['DOCKER_BUILDKIT'] = '1'
  max_parallelization = max([len(image_list) for image_list in images])
  proc_count = min(multiprocessing.cpu_count(), max_parallelization)
  logging.info('Using %d parallel processes.', proc_count)
  with multiprocessing.Pool(proc_count) as pool:
    for image_list in images:
      args_list = [(image, test_image_suffix) for image in image_list]
      pool.starmap(build_and_push_image, args_list)


def main():
  """Builds base-images tags them with "-testing" suffix (in addition to normal
  tag) and pushes testing suffixed images to docker registry."""
  test_image_suffix = sys.argv[1]
  logging.basicConfig(level=logging.DEBUG)
  logging.info('Doing simple gcloud command to ensure 2FA passes.')
  subprocess.run(['gcloud', 'projects', 'list', '--limit=1'], check=True)
  build_and_push_images(test_image_suffix)


if __name__ == '__main__':
  main()
