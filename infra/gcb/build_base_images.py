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
#!/usr/bin/python2
"""Build base images on Google Cloud Builder.

Usage: build_base_images.py
"""
from __future__ import print_function

import os
import sys
import yaml

from googleapiclient.discovery import build
from oauth2client.client import GoogleCredentials

BASE_IMAGES = [
    'base-image',
    'base-clang',
    'base-builder',
    'base-runner',
    'base-runner-debug',
    'base-sanitizer-libs-builder',
]

TAG_PREFIX = 'gcr.io/oss-fuzz-base/'


def get_steps(images, tag_prefix=TAG_PREFIX):
  """Returns build steps for given images."""
  steps = [{
      'args': [
          'clone',
          'https://github.com/google/oss-fuzz.git',
      ],
      'name': 'gcr.io/cloud-builders/git',
  }]

  for base_image in images:
    steps.append({
        'args': [
            'build',
            '-t',
            tag_prefix + base_image,
            '.',
        ],
        'dir': 'oss-fuzz/infra/base-images/' + base_image,
        'name': 'gcr.io/cloud-builders/docker',
    })

  return steps


def get_logs_url(build_id, project_id='oss-fuzz-base'):
  """Returns url that displays the build logs."""
  url_format = ('https://console.developers.google.com/logs/viewer?'
                'resource=build%2Fbuild_id%2F{0}&project={1}')
  return url_format.format(build_id, project_id)


# pylint: disable=no-member, missing-function-docstring
def main():
  options = {}
  if 'GCB_OPTIONS' in os.environ:
    options = yaml.safe_load(os.environ['GCB_OPTIONS'])

  build_body = {
      'steps': get_steps(BASE_IMAGES),
      'timeout': str(4 * 3600) + 's',
      'options': options,
      'images': [TAG_PREFIX + base_image for base_image in BASE_IMAGES],
  }

  credentials = GoogleCredentials.get_application_default()
  cloudbuild = build('cloudbuild', 'v1', credentials=credentials)
  build_info = cloudbuild.projects().builds().create(projectId='oss-fuzz-base',
                                                     body=build_body).execute()
  build_id = build_info['metadata']['build']['id']

  print('Logs:', get_logs_url(build_id), file=sys.stderr)
  print(build_id)


if __name__ == '__main__':
  main()
