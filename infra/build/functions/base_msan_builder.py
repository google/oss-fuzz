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

import build_base_images
import build_msan_libs

BASE_PROJECT = 'oss-fuzz-base'


# pylint: disable=no-member
def base_msan_builder(event, context):
  """Cloud function to build base images."""
  del event, context
  credentials, _ = google.auth.default()
  image = f'gcr.io/{BASE_PROJECT}/msan-libs-builder'
  build_body = {
      'steps': build_msan_libs.get_steps(image),
      'timeout': str(6 * 3600) + 's',
      'options': {
          'machineType': 'N1_HIGHCPU_32'
      },
      'images': [
          f'gcr.io/{BASE_PROJECT}/base-sanitizer-libs-builder',
          image,
      ],
  }
  cloudbuild = build('cloudbuild',
                     'v1',
                     credentials=credentials,
                     cache_discovery=False)
  build_info = cloudbuild.projects().builds().create(projectId=BASE_PROJECT,
                                                     body=build_body).execute()
  build_id = build_info['metadata']['build']['id']
  logging.info('Build ID: %s', build_id)
  logging.info('Logs: %s',
               build_base_images.get_logs_url(build_id, BASE_PROJECT))
