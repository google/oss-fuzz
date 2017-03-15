#!/usr/bin/python2

"""Starts project build on Google Cloud Builder.

Usage: build.py <project_dir>
"""

import base64
import collections
import datetime
import os
import subprocess
import sys
import time
import urllib
import yaml

from oauth2client.client import GoogleCredentials
from oauth2client.service_account import ServiceAccountCredentials
from googleapiclient.discovery import build

CONFIGURATIONS = {
  'sanitizer-address' : [ 'SANITIZER=address' ],
  'sanitizer-memory' : [ 'SANITIZER=memory' ],
  'sanitizer-undefined' : [ 'SANITIZER=undefined' ],
  'engine-libfuzzer' : [ 'FUZZING_ENGINE=libfuzzer' ],
  'engine-afl' : [ 'FUZZING_ENGINE=afl' ],
}

EngineInfo = collections.namedtuple(
    'EngineInfo', ['upload_bucket', 'supported_sanitizers'])

ENGINE_INFO = {
    'libfuzzer': EngineInfo(
        upload_bucket='clusterfuzz-builds-test',
        supported_sanitizers=['address', 'memory', 'undefined']),
    'afl': EngineInfo(
        upload_bucket='clusterfuzz-builds-afl-test',
        supported_sanitizers=['address']),
}

DEFAULT_ENGINES = ['libfuzzer', 'afl']
DEFAULT_SANITIZERS = ['address', 'undefined']


def usage():
  sys.stderr.write(
    "Usage: " + sys.argv[0] + " <project_dir>\n")
  exit(1)


def load_project_yaml(project_dir):
  project_name = os.path.basename(project_dir)
  project_yaml_path = os.path.join(project_dir, 'project.yaml')
  with open(project_yaml_path) as f:
    project_yaml = yaml.safe_load(f)
    project_yaml.setdefault('name', project_name)
    project_yaml.setdefault('image',
        'gcr.io/clusterfuzz-external/oss-fuzz/' + project_name)
    project_yaml.setdefault('sanitizers', DEFAULT_SANITIZERS)
    project_yaml.setdefault('fuzzing_engines', DEFAULT_ENGINES)
    return project_yaml


def get_signed_url(path):
  timestamp = int(time.time() + 60 * 60 * 5)
  blob = 'PUT\n\n\n{0}\n{1}'.format(
      timestamp, path)

  creds = ServiceAccountCredentials.from_json_keyfile_name(
      os.environ['GOOGLE_APPLICATION_CREDENTIALS'])
  client_id = creds.service_account_email
  signature = base64.b64encode(creds.sign_blob(blob)[1])
  values = {
      'GoogleAccessId': client_id,
      'Expires': timestamp,
      'Signature': signature,
  }

  return ('https://storage.googleapis.com{0}?'.format(path) +
          urllib.urlencode(values))


def is_supported_configuration(fuzzing_engine, sanitizer):
  return sanitizer in ENGINE_INFO[fuzzing_engine].supported_sanitizers


def get_build_steps(project_yaml):
  name = project_yaml['name']
  image = project_yaml['image']

  ts = datetime.datetime.now().strftime('%Y%m%d%H%M')

  build_steps = [
          {
              'name': 'gcr.io/cloud-builders/docker',
              'args': [
                  'build',
                  '-t',
                  image,
                  '.',
                  ],
              'dir': 'projects/' + name,
          },
          {
              'name': image,
              'args': [
                'bash',
                '-c',
                'srcmap > /workspace/srcmap.json && cat /workspace/srcmap.json'
              ],
              'env': [ 'OSSFUZZ_REVISION=$REVISION_ID' ],
          },
    ]

  for fuzzing_engine in project_yaml['fuzzing_engines']:
    for sanitizer in project_yaml['sanitizers']:
      if not is_supported_configuration(fuzzing_engine, sanitizer):
        continue

      env = CONFIGURATIONS['engine-' + fuzzing_engine][:]
      env.extend(CONFIGURATIONS['sanitizer-' + sanitizer])
      out = '/workspace/out/' + sanitizer
      stamped_name = name + '-' + sanitizer + '-' + ts
      zip_file = stamped_name + '.zip'
      stamped_srcmap_file = stamped_name + '.srcmap.json'
      bucket = ENGINE_INFO[fuzzing_engine].upload_bucket
      upload_url = get_signed_url('/{0}/{1}/{2}'.format(
          bucket, name, zip_file))
      srcmap_url = get_signed_url('/{0}/{1}/{2}'.format(
          bucket, name, stamped_srcmap_file))

      env.append('OUT=' + out)

      build_steps.extend([
          # compile
          {'name': image,
            'env' : env,
            'args': [
              'bash',
              '-c',
              'cd /src/{1} && mkdir -p {0} && compile'.format(out, name),
              ],
            },
          # zip binaries
          {'name': image,
            'args': [
              'bash',
              '-c',
              'cd {0} && zip -r {1} *'.format(out, zip_file)
            ],
          },
          # upload binaries
          {'name': 'gcr.io/clusterfuzz-external/uploader',
           'args': [
               os.path.join(out, zip_file),
               upload_url,
           ],
          },
          # upload srcmap
          {'name': 'gcr.io/clusterfuzz-external/uploader',
           'args': [
               '/workspace/srcmap.json',
               srcmap_url,
           ],
          },
          # cleanup
          {'name': image,
            'args': [
              'bash',
              '-c',
              'rm -r ' + out,
            ],
          },
      ])

  return build_steps


def get_logs_url(build_id):
  URL_FORMAT = ('https://console.developers.google.com/logs/viewer?'
                'resource=build%2Fbuild_id%2F{0}&project=clusterfuzz-external')
  return URL_FORMAT.format(build_id)


def main():
  if len(sys.argv) != 2:
    usage()

  project_dir = sys.argv[1]
  project_yaml = load_project_yaml(project_dir)

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
      'steps': get_build_steps(project_yaml),
      'timeout': str(4 * 3600) + 's',
      'options': options,
      'logsBucket': 'oss-fuzz-gcb-logs',
      'images': [ project_yaml['image'] ],
  }

  credentials = GoogleCredentials.get_application_default()
  cloudbuild = build('cloudbuild', 'v1', credentials=credentials)
  build_info = cloudbuild.projects().builds().create(
      projectId='clusterfuzz-external', body=build_body).execute()
  build_id =  build_info['metadata']['build']['id']

  print >>sys.stderr, 'Logs:', get_logs_url(build_id)
  print build_id


if __name__ == "__main__":
  main()
