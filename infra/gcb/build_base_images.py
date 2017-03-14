#!/usr/bin/python2

"""Build base images on Google Cloud Builder.

Usage: build_base_images.py
"""

import os
import yaml

from oauth2client.client import GoogleCredentials
from googleapiclient.discovery import build

import build as gcb_build

BASE_IMAGES = [
    'base-image',
    'base-clang',
    'base-builder',
    'base-runner',
    'base-runner-debug',
]

TAG_PREFIX = 'gcr.io/clusterfuzz-external/oss-fuzz/infra/'


def get_steps():
  steps = []

  for base_image in BASE_IMAGES:
    steps.append({
        'args': [
            'build',
            '-t',
            TAG_PREFIX + base_image,
            '.',
        ],
        'dir': 'infra/base-images/' + base_image,
        'name': 'gcr.io/cloud-builders/docker',
    })

  return steps


def main():
  options = {}
  if "GCB_OPTIONS" in os.environ:
    options = yaml.safe_load(os.environ["GCB_OPTIONS"])

  build_body = {
      'source': {
          'repoSource': {
              'branchName': 'master',
              'projectId': 'clusterfuzz-external',
              'repoName': 'oss-fuzz',
          },
      },
      'steps': get_steps(),
      'timeout': str(4 * 3600) + 's',
      'options': options,
      'images': [
           TAG_PREFIX + base_image for base_image in BASE_IMAGES
       ],
  }

  credentials = GoogleCredentials.get_application_default()
  cloudbuild = build('cloudbuild', 'v1', credentials=credentials)
  build_info = cloudbuild.projects().builds().create(projectId='clusterfuzz-external', body=build_body).execute()
  build_id =  build_info['metadata']['build']['id']

  print build_id


if __name__ == "__main__":
  main()
