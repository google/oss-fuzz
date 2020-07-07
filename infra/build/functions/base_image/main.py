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

import os
import sys
import yaml

import google.auth
from googleapiclient.discovery import build

BASE_IMAGES = [
    'base-image',
    'base-clang',
    'base-builder',
    'base-runner',
    'base-runner-debug',
    'base-msan-builder',
]


def get_steps(images, tag_prefix):
  """Genereates steps for building base images."""
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


def get_logs_url(build_id, project_id):
  """Returns url for build logs."""
  URL_FORMAT = ('https://console.developers.google.com/logs/viewer?'
                'resource=build%2Fbuild_id%2F{0}&project={1}')
  return URL_FORMAT.format(build_id, project_id)


def build_base_images(event, context):
  credentials, project_id = google.auth.default()
  tag_prefix = 'gcr.io/' + project_id + '/'
  build_body = {
      'steps': get_steps(BASE_IMAGES, tag_prefix),
      'timeout': str(4 * 3600) + 's',
      'options': {
          'machineType': 'N1_HIGHCPU_32'
      },
      'images': [tag_prefix + base_image for base_image in BASE_IMAGES],
  }
  cloudbuild = build('cloudbuild',
                     'v1',
                     credentials=credentials,
                     cache_discovery=False)
  build_info = cloudbuild.projects().builds().create(projectId=project_id,
                                                     body=build_body).execute()
  build_id = build_info['metadata']['build']['id']
  print('Logs:', get_logs_url(build_id, project_id), file=sys.stderr)
  print(build_id)
