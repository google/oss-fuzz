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

import google.auth
from googleapiclient.discovery import build

BASE_IMAGES = [
    'base-image',
    'base-clang',
    'base-builder',
    'base-builder-go',
    'base-builder-go-codeintelligencetesting',
    'base-builder-jvm',
    'base-builder-python',
    'base-builder-rust',
    'base-builder-swift',
    'base-runner',
    'base-runner-debug',
]
INTROSPECTOR_BASE_IMAGES = ['base-clang', 'base-builder']
BASE_PROJECT = 'oss-fuzz-base'
TAG_PREFIX = f'gcr.io/{BASE_PROJECT}/'
MAJOR_TAG = 'v1'
INTROSPECTOR_TAG = 'introspector'


def _get_base_image_steps(images, tag_prefix=TAG_PREFIX):
  """Returns build steps for given images."""
  steps = [{
      'args': [
          'clone',
          'https://github.com/google/oss-fuzz.git',
      ],
      'name': 'gcr.io/cloud-builders/git',
  }]

  for base_image in images:
    image = tag_prefix + base_image
    steps.append({
        'args': [
            'build',
            '-t',
            image,
            '-t',
            f'{image}:{MAJOR_TAG}',
            '.',
        ],
        'dir': 'oss-fuzz/infra/base-images/' + base_image,
        'name': 'gcr.io/cloud-builders/docker',
    })

  return steps


def _get_introspector_base_images_steps(images, tag_prefix=TAG_PREFIX):
  """Returns build steps for given images version of introspector"""
  steps = [{
      'args': [
          'clone',
          'https://github.com/google/oss-fuzz.git',
      ],
      'name': 'gcr.io/cloud-builders/git',
  }]

  steps.extend([{
      'name':
          'gcr.io/oss-fuzz-base/base-runner',
      'args': [
          'bash', '-c',
          (f'sed -i s/base-clang.*/base-clang:{INTROSPECTOR_TAG}/g'
           ' oss-fuzz/infra/base-images/base-builder/Dockerfile')
      ]
  }])

  for base_image in images:
    image = tag_prefix + base_image
    args_list = ['build']

    if base_image == 'base-clang':
      args_list.extend(['--build-arg', 'introspector=1'])

    args_list.extend([
        '-t',
        f'{image}:{INTROSPECTOR_TAG}',
        '.',
    ])
    steps.append({
        'args': args_list,
        'dir': 'oss-fuzz/infra/base-images/' + base_image,
        'name': 'gcr.io/cloud-builders/docker',
    })

  return steps


def get_logs_url(build_id, project_id='oss-fuzz-base'):
  """Returns url that displays the build logs."""
  return ('https://console.developers.google.com/logs/viewer?'
          f'resource=build%2Fbuild_id%2F{build_id}&project={project_id}')


# pylint: disable=no-member
def run_build(steps, images, build_version=MAJOR_TAG):
  """Execute the retrieved build steps in gcp."""
  credentials, _ = google.auth.default()
  build_body = {
      'steps': steps,
      'timeout': str(6 * 3600) + 's',
      'options': {
          'machineType': 'N1_HIGHCPU_32'
      },
      'images': images + [f'{image}:{build_version}' for image in images]
  }
  cloudbuild = build('cloudbuild',
                     'v1',
                     credentials=credentials,
                     cache_discovery=False)
  build_info = cloudbuild.projects().builds().create(projectId=BASE_PROJECT,
                                                     body=build_body).execute()
  build_id = build_info['metadata']['build']['id']
  logging.info('Build ID: %s', build_id)
  logging.info('Logs: %s', get_logs_url(build_id, BASE_PROJECT))


def base_builder(event, context):
  """Cloud function to build base images."""
  del event, context

  tag_prefix = f'gcr.io/{BASE_PROJECT}/'
  steps = _get_base_image_steps(BASE_IMAGES, tag_prefix)
  images = [tag_prefix + base_image for base_image in BASE_IMAGES]

  run_build(steps, images)

  introspector_steps = _get_introspector_base_images_steps(
      INTROSPECTOR_BASE_IMAGES, tag_prefix)
  introspector_images = [
      tag_prefix + base_image for base_image in INTROSPECTOR_BASE_IMAGES
  ]

  run_build(introspector_steps, introspector_images, INTROSPECTOR_TAG)
