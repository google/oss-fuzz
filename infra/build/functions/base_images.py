# Copyright 2020 Google Inc.
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
"""Cloud function to build base images on Google Cloud Builder."""
import logging
import os

import google.auth

import build_lib

BASE_IMAGES = [
    'base-image',
    'base-clang',
    'base-builder',
    'base-builder-go',
    'base-builder-javascript',
    'base-builder-jvm',
    'base-builder-python',
    'base-builder-rust',
    'base-builder-swift',
    'base-runner',
    'base-runner-debug',
]
BASE_PROJECT = 'oss-fuzz-base'
TAG_PREFIX = f'gcr.io/{BASE_PROJECT}/'
MAJOR_TAG = 'v1'
MANIFEST_IMAGES = [
    'gcr.io/oss-fuzz-base/base-builder', 'gcr.io/oss-fuzz-base/base-runner'
]
TIMEOUT = str(6 * 60 * 60)


def get_base_image_path(image_name):
  """Returns the path to the directory containing the Dockerfile of the base
  image."""
  return os.path.join('infra', 'base-images', image_name)


def get_base_image_steps(images, tag_prefix=TAG_PREFIX):
  """Returns build steps for given images."""
  steps = [build_lib.get_git_clone_step()]

  for base_image in images:
    image = tag_prefix + base_image
    tagged_image = image + ':' + MAJOR_TAG
    image_path = get_base_image_path(base_image)
    steps.append(
        build_lib.get_docker_build_step([image, tagged_image], image_path))
  return steps


# pylint: disable=no-member
def run_build(steps, images, tags=None, build_version=MAJOR_TAG):
  """Execute the build |steps| in GCB and push |images| to the registry."""
  credentials, _ = google.auth.default()
  images = [image for image in images if image not in MANIFEST_IMAGES
           ] + ([f'{image}:{build_version}' for image in images])
  body_overrides = {
      'images': images,
      'options': {
          'machineType': 'E2_HIGHCPU_32'
      },
  }
  return build_lib.run_build(steps,
                             credentials,
                             BASE_PROJECT,
                             TIMEOUT,
                             body_overrides,
                             tags,
                             use_build_pool=False)


def get_images_architecture_manifest_steps():
  """Returns steps to create manifests for ARM and x86_64 versions of
  base-runner and base-builder."""
  images = [f'{TAG_PREFIX}base-builder', f'{TAG_PREFIX}base-runner']
  steps = []
  for image in images:
    steps.extend(get_image_push_architecture_manifest_steps(image))
  return steps


def get_image_push_architecture_manifest_steps(image):
  """Returns the steps to push a manifest pointing to ARM64 and AMD64 versions
  of |image|."""
  arm_testing_image = f'{image}-testing-arm'
  amd64_manifest_image = f'{image}:manifest-amd64'
  arm64_manifest_image = f'{image}:manifest-arm64v8'
  steps = [
      {
          'name': 'gcr.io/cloud-builders/docker',
          'args': ['tag', image, amd64_manifest_image],
      },
      {
          'name': 'gcr.io/cloud-builders/docker',
          'args': ['push', amd64_manifest_image],
      },
      {
          'name': 'gcr.io/cloud-builders/docker',
          'args': ['pull', arm_testing_image],
      },
      {
          'name': 'gcr.io/cloud-builders/docker',
          'args': ['tag', arm_testing_image, arm64_manifest_image],
      },
      {
          'name': 'gcr.io/cloud-builders/docker',
          'args': ['push', arm64_manifest_image],
      },
      {
          'name':
              'gcr.io/cloud-builders/docker',
          'args': [
              'manifest', 'create', image, '--amend', arm64_manifest_image,
              '--amend', amd64_manifest_image
          ],
      },
      {
          'name': 'gcr.io/cloud-builders/docker',
          'args': ['manifest', 'push', image]
      },
  ]
  return steps


def base_builder(event, context):
  """Cloud function to build base images."""
  del event, context
  logging.basicConfig(level=logging.INFO)

  steps = get_base_image_steps(BASE_IMAGES)
  steps.extend(get_images_architecture_manifest_steps())
  images = [TAG_PREFIX + base_image for base_image in BASE_IMAGES]
  run_build(steps, images)
