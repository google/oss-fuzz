#! /usr/bin/env python3
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
"""Script for pushing manifest files to docker that point to AMD64 and ARM
images."""
import logging
import subprocess
import sys


def push_manifest(image):
  """Pushes a manifest file in place of |image| for ARM and AMD64 versions of
  that image."""
  subprocess.run(['docker', 'pull', image], check=True)
  amd64_image = f'{image}:manifest-amd64'
  subprocess.run(['docker', 'tag', image, amd64_image], check=True)
  subprocess.run(['docker', 'push', amd64_image], check=True)

  arm_version = f'{image}-testing-arm'
  subprocess.run(['docker', 'pull', arm_version], check=True)
  arm64_image = f'{image}:manifest-arm64v8'
  subprocess.run(['docker', 'tag', arm_version, arm64_image], check=True)

  subprocess.run([
      'docker', 'manifest', 'create', image, '--amend', arm64_image, '--amend',
      amd64_image
  ],
                 check=True)
  subprocess.run(['docker', 'manifest', 'push', image], check=True)
  return True


def main():
  """Sets up manifests for base-builder and base-runner so they can be used for
  ARM builds."""
  logging.info('Doing simple gcloud command to ensure 2FA passes. '
               'Otherwise docker push fails.')
  subprocess.run(['gcloud', 'projects', 'list', '--limit=1'], check=True)

  images = [
      'gcr.io/oss-fuzz-base/base-builder', 'gcr.io/oss-fuzz-base/base-runner'
  ]
  results = [push_manifest(image) for image in images]
  return 0 if all(results) else 1


if __name__ == '__main__':
  sys.exit(main())
