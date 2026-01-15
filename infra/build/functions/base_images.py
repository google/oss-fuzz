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
"""Cloud function to build base images on Google Cloud Builder.

This script can be run locally for testing or deployment purposes. By default,
it performs a real build. To perform a dry run, use the '--dry-run' flag. To
prevent images from being pushed to the registry, use '--no-push'.

Example:
  python3 infra/build/functions/base_images.py --dry-run
"""
from collections.abc import Sequence
import logging
import os
import sys

import google.auth

import build_lib

BASE_PROJECT = 'oss-fuzz-base'
IMAGE_NAME_PREFIX = f'gcr.io/{BASE_PROJECT}/'
MAJOR_TAG = 'v1'
TIMEOUT = '21600'  # 6 hours

# Defines the Ubuntu versions supported by the build infrastructure.
# 'legacy' refers to the unversioned, default image.
# Note: This list indicates build capability, not production readiness.
# A version is only ready for general use after being fully enabled in
# ClusterFuzz.
SUPPORTED_VERSIONS = ('legacy', 'ubuntu-20-04', 'ubuntu-24-04')

# Define which of the supported versions is considered the default.
# This version will receive the ':v1' tag.
DEFAULT_VERSION = 'legacy'

# Defines the dependency graph for base images.
IMAGE_DEPENDENCIES = {
    'base-clang': ['base-image'],
    'base-clang-full': ['base-clang'],
    'base-builder': ['base-clang'],
    'base-builder-go': ['base-builder'],
    'base-builder-javascript': ['base-builder'],
    'base-builder-jvm': ['base-builder'],
    'base-builder-python': ['base-builder'],
    'base-builder-ruby': ['base-builder'],
    'base-builder-rust': ['base-builder'],
    'base-builder-swift': ['base-builder'],
    'base-runner': ['base-image', 'base-builder', 'base-builder-ruby'],
    'base-runner-debug': ['base-runner'],
    'indexer': ['base-clang-full'],
}


class ImageConfig:
  """Configuration for a specific base image version."""
  name: str
  version: str
  path: str
  dockerfile_path: str
  build_args: Sequence[str] | None

  def __init__(self,
               name: str,
               version: str,
               path: str | None = None,
               build_args: Sequence[str] | None = None):
    self.name = name
    self.version = version
    self.path = path if path else self._get_default_path()
    self.dockerfile_path = self._resolve_dockerfile()
    self.build_args = build_args

  def _get_default_path(self) -> str:
    """Returns the default path to the image's build directory."""
    if self.name == 'indexer':
      return os.path.join('infra', 'indexer')
    return os.path.join('infra', 'base-images', self.name)

  def _resolve_dockerfile(self) -> str:
    """Resolves the path to the Dockerfile.

    Prefers a version-specific one if it exists, otherwise falling back to the
    legacy Dockerfile.
    """
    if self.version != 'legacy':
      versioned_dockerfile = os.path.join(self.path,
                                          f'{self.version}.Dockerfile')
      logging.info('Using versioned Dockerfile: %s', versioned_dockerfile)
      return versioned_dockerfile

    legacy_dockerfile = os.path.join(self.path, 'Dockerfile')
    logging.info('Using legacy Dockerfile: %s', legacy_dockerfile)
    return legacy_dockerfile

  @property
  def final_tag(self) -> str:
    """
        Returns the final tag for the image, using ':v1' for the default
        version and the version name for others.
        """
    return MAJOR_TAG if self.version == DEFAULT_VERSION else self.version

  @property
  def full_image_name_with_tag(self) -> str:
    """Returns the full GCR image name with the final tag."""
    return f'{IMAGE_NAME_PREFIX}{self.name}:{self.final_tag}'


# Definitions of the base images to be built.
BASE_IMAGE_DEFS = [
    {
        'name': 'base-image'
    },
    {
        'name': 'base-clang'
    },
    {
        'name': 'base-clang-full',
        'path': 'infra/base-images/base-clang',
        'build_args': ('FULL_LLVM_BUILD=1',)
    },
    {
        'name': 'indexer'
    },
    {
        'name': 'base-builder'
    },
    {
        'name': 'base-builder-go'
    },
    {
        'name': 'base-builder-javascript'
    },
    {
        'name': 'base-builder-jvm'
    },
    {
        'name': 'base-builder-python'
    },
    {
        'name': 'base-builder-ruby'
    },
    {
        'name': 'base-builder-rust'
    },
    {
        'name': 'base-builder-swift'
    },
    {
        'name': 'base-runner'
    },
    {
        'name': 'base-runner-debug'
    },
]


def get_base_image_steps(images: Sequence[ImageConfig]) -> list[dict]:
  """Returns build steps for a given list of image configurations."""
  steps = [build_lib.get_git_clone_step()]
  build_ids = {}

  for image_config in images:
    # The final tag is ':v1' for the default version, or the version name
    # (e.g., ':ubuntu-24-04') for others.
    tags = [image_config.full_image_name_with_tag]

    # The 'legacy' build is also tagged as 'latest' for use by subsequent
    # build steps within the same pipeline.
    if image_config.version == 'legacy':
      tags.append(f'{IMAGE_NAME_PREFIX}{image_config.name}:latest')

    dockerfile_path = os.path.join('oss-fuzz', image_config.dockerfile_path)
    step = build_lib.get_docker_build_step(tags,
                                           image_config.path,
                                           dockerfile_path=dockerfile_path,
                                           build_args=image_config.build_args)

    # Check for dependencies and add 'waitFor' if necessary.
    dependencies = IMAGE_DEPENDENCIES.get(image_config.name, [])
    wait_for = [build_ids[dep] for dep in dependencies if dep in build_ids]
    if wait_for:
      step['waitFor'] = wait_for

    build_ids[image_config.name] = step['id']
    steps.append(step)

  return steps


def run_build(steps: list[dict],
              images_to_push: list[str],
              build_version: str,
              tags: list[str] | None = None,
              dry_run: bool = False,
              no_push: bool = False):
  """Executes a build in GCB and pushes the resulting images.

  Alternatively, prints the configuration if in dry_run mode.
  """
  if dry_run:
    print(
        '--------------------------------------------------------------------')
    print(f'DRY RUN FOR VERSION: {build_version}')
    print(
        '--------------------------------------------------------------------')
    print(f'Images to push: {images_to_push}')
    print(f'Push enabled: {not no_push}')
    print('Build steps:')
    for step in steps:
      print(f"  - {step['name']}: {' '.join(step['args'])}")
    print(
        '--------------------------------------------------------------------\n'
    )
    return

  images_for_gcb = images_to_push
  if no_push:
    logging.info('"--no-push" flag detected. Skipping push to registry.')
    images_for_gcb = []

  credentials, _ = google.auth.default()
  body_overrides = {
      'images': images_for_gcb,
      'options': {
          'machineType': 'E2_HIGHCPU_32'
      },
  }
  build_tags = ['base-image-build', f'version-{build_version}']
  if tags:
    build_tags.extend(tags)

  build_info = build_lib.run_build('',
                                   steps,
                                   credentials,
                                   BASE_PROJECT,
                                   TIMEOUT,
                                   body_overrides,
                                   build_tags,
                                   use_build_pool=False)

  if build_info:
    build_id = build_info.get('id')
    log_url = build_info.get('logUrl')
    logging.info('Successfully triggered build %s for version %s.', build_id,
                 build_version)
    logging.info('Build logs are available at: %s', log_url)
  else:
    logging.error('Failed to trigger build for version %s.', build_version)


def get_images_architecture_manifest_steps(target_tag: str) -> list[dict]:
  """Returns steps for creating and pushing a multi-architecture manifest.

  The manifest is for the base-builder and base-runner images with a
  specific tag.
  """
  images = [
      f'{IMAGE_NAME_PREFIX}base-builder', f'{IMAGE_NAME_PREFIX}base-runner'
  ]
  steps = []
  for image in images:
    steps.extend(get_image_push_architecture_manifest_steps(image, target_tag))
  return steps


def get_image_push_architecture_manifest_steps(image: str,
                                               target_tag: str) -> list[dict]:
  """Returns steps for pushing a manifest pointing to ARM64/AMD64 versions."""
  # The AMD64 image is the one we just built.
  amd64_source_image = f'{image}:{target_tag}'
  # The ARM64 image is a pre-built generic testing image.
  arm64_source_image = f'{image}-testing-arm'
  # The final manifest will point to this tag.
  manifest_tag = f'{image}:{target_tag}'

  # Intermediate tags for pushing architecture-specific images.
  amd64_manifest_image = f'{image}:{target_tag}-manifest-amd64'
  arm64_manifest_image = f'{image}:{target_tag}-manifest-arm64v8'

  steps = [
      # Tag and push the AMD64 image.
      {
          'name': 'gcr.io/cloud-builders/docker',
          'args': ['tag', amd64_source_image, amd64_manifest_image],
      },
      {
          'name': 'gcr.io/cloud-builders/docker',
          'args': ['push', amd64_manifest_image],
      },
      # Pull and tag the ARM64 image.
      {
          'name': 'gcr.io/cloud-builders/docker',
          'args': ['pull', arm64_source_image],
      },
      {
          'name': 'gcr.io/cloud-builders/docker',
          'args': ['tag', arm64_source_image, arm64_manifest_image],
      },
      {
          'name': 'gcr.io/cloud-builders/docker',
          'args': ['push', arm64_manifest_image],
      },
      # Create and push the manifest.
      {
          'name':
              'gcr.io/cloud-builders/docker',
          'args': [
              'manifest', 'create', manifest_tag, '--amend',
              arm64_manifest_image, '--amend', amd64_manifest_image
          ],
      },
      {
          'name': 'gcr.io/cloud-builders/docker',
          'args': ['manifest', 'push', manifest_tag]
      }
  ]
  return steps


def base_builder(event, context, dry_run: bool = False, no_push: bool = False):
  """Cloud function entry point.

  Triggers parallel base image builds for each supported Ubuntu version.
  """
  del event, context
  logging.basicConfig(level=logging.INFO)

  for version in SUPPORTED_VERSIONS:
    logging.info('Starting build for version: %s', version)

    version_images = [
        ImageConfig(version=version, **def_args) for def_args in BASE_IMAGE_DEFS
    ]
    steps = get_base_image_steps(version_images)
    images_to_push = [img.full_image_name_with_tag for img in version_images]

    # Also push the 'latest' tag for the default build.
    if version == DEFAULT_VERSION:
      images_to_push.extend(
          [f'{IMAGE_NAME_PREFIX}{img.name}:latest' for img in version_images])

    # Determine the final tag for this build.
    target_tag = MAJOR_TAG if version == DEFAULT_VERSION else version

    # Create a multi-architecture manifest for this version's final tag.
    logging.info('Adding multi-architecture manifest steps for tag: %s',
                 target_tag)
    steps.extend(get_images_architecture_manifest_steps(target_tag))
    images_to_push.extend([
        f'{IMAGE_NAME_PREFIX}base-builder:{target_tag}',
        f'{IMAGE_NAME_PREFIX}base-runner:{target_tag}'
    ])

    logging.info('Triggering GCB build for version: %s', version)
    run_build(steps,
              images_to_push,
              build_version=version,
              dry_run=dry_run,
              no_push=no_push)


if __name__ == '__main__':
  is_dry_run = '--dry-run' in sys.argv
  no_push = '--no-push' in sys.argv
  base_builder(None, None, dry_run=is_dry_run, no_push=no_push)
