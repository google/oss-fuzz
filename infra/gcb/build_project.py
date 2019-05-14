#!/usr/bin/python2
"""Starts project build on Google Cloud Builder.

Usage: build_project.py <project_dir>
"""

import base64
import collections
import datetime
import json
import os
import re
import sys
import time
import urllib
import yaml

from oauth2client.client import GoogleCredentials
from oauth2client.service_account import ServiceAccountCredentials
from googleapiclient.discovery import build

BUILD_TIMEOUT = 12 * 60 * 60

FUZZING_BUILD_TAG = 'fuzzing'

GCB_LOGS_BUCKET = 'oss-fuzz-gcb-logs'

CONFIGURATIONS = {
    'sanitizer-address': ['SANITIZER=address'],
    'sanitizer-dataflow': ['SANITIZER=dataflow'],
    'sanitizer-memory': ['SANITIZER=memory'],
    'sanitizer-undefined': ['SANITIZER=undefined'],
    'engine-libfuzzer': ['FUZZING_ENGINE=libfuzzer'],
    'engine-afl': ['FUZZING_ENGINE=afl'],
    'engine-honggfuzz': ['FUZZING_ENGINE=honggfuzz'],
    'engine-dataflow': ['FUZZING_ENGINE=dataflow'],
    'engine-none': ['FUZZING_ENGINE=none'],
}

EngineInfo = collections.namedtuple('EngineInfo',
                                    ['upload_bucket', 'supported_sanitizers'])

ENGINE_INFO = {
    'libfuzzer':
        EngineInfo(
            upload_bucket='clusterfuzz-builds',
            supported_sanitizers=['address', 'memory', 'undefined'],
            supported_architectures=['x86_64', 'i386']),
    'afl':
        EngineInfo(
            upload_bucket='clusterfuzz-builds-afl',
            supported_sanitizers=['address'],
            supported_architectures=['x86_64']),
    'honggfuzz':
        EngineInfo(
            upload_bucket='clusterfuzz-builds-honggfuzz',
            supported_sanitizers=['address', 'memory', 'undefined'],
            supported_architectures=['x86_64']),
    'dataflow':
        EngineInfo(
            upload_bucket='clusterfuzz-builds-dataflow',
            supported_sanitizers=['dataflow'],
            supported_architectures=['x86_64']),
    'none':
        EngineInfo(
            upload_bucket='clusterfuzz-builds-no-engine',
            supported_sanitizers=['address'],
            supported_architectures=['x86_64']),
}

DEFAULT_ARCHITECTURES = ['x86_64']
DEFAULT_ENGINES = ['libfuzzer', 'afl']
DEFAULT_SANITIZERS = ['address', 'undefined']

TARGETS_LIST_BASENAME = 'targets.list'

UPLOAD_URL_FORMAT = '/{0}/{1}/{2}'


def usage():
  sys.stderr.write('Usage: ' + sys.argv[0] + ' <project_dir>\n')
  exit(1)


def load_project_yaml(project_dir):
  project_name = os.path.basename(project_dir)
  project_yaml_path = os.path.join(project_dir, 'project.yaml')
  with open(project_yaml_path) as f:
    project_yaml = yaml.safe_load(f)
    project_yaml.setdefault('disabled', False)
    project_yaml.setdefault('name', project_name)
    project_yaml.setdefault('image', 'gcr.io/oss-fuzz/' + project_name)
    project_yaml.setdefault('sanitizers', DEFAULT_SANITIZERS)
    project_yaml.setdefault('fuzzing_engines', DEFAULT_ENGINES)
    project_yaml.setdefault('architectures', DEFAULT_ARCHITECTURES)
    project_yaml.setdefault('run_tests', True)
    project_yaml.setdefault('coverage_extra_args', '')
    project_yaml.setdefault('labels', {})
    return project_yaml


def get_signed_url(path, method='PUT', content_type=''):
  timestamp = int(time.time() + BUILD_TIMEOUT)
  blob = '{0}\n\n{1}\n{2}\n{3}'.format(method, content_type, timestamp, path)

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


def is_supported_configuration(fuzzing_engine, sanitizer, architecture):
  fuzzing_engine_info = ENGINE_INFO[fuzzing_engine]
  return (sanitizer in fuzzing_engine_info.supported_sanitizers and
          architecture in fuzzing_engine_info.supported_architectures)


def get_sanitizers(project_yaml):
  sanitizers = project_yaml['sanitizers']
  assert isinstance(sanitizers, list)

  processed_sanitizers = []
  for sanitizer in sanitizers:
    if isinstance(sanitizer, basestring):
      processed_sanitizers.append(sanitizer)
    elif isinstance(sanitizer, dict):
      for key in sanitizer.iterkeys():
        processed_sanitizers.append(key)

  return processed_sanitizers


def workdir_from_dockerfile(dockerfile):
  """Parse WORKDIR from the Dockerfile."""
  WORKDIR_REGEX = re.compile(r'\s*WORKDIR\s*([^\s]+)')

  with open(dockerfile) as f:
    lines = f.readlines()

  for line in lines:
    match = re.match(WORKDIR_REGEX, line)
    if match:
      # We need to escape '$' since they're used for subsitutions in Container
      # Builer builds.
      return match.group(1).replace('$', '$$')

  return None


def get_build_steps(project_dir):
  project_yaml = load_project_yaml(project_dir)
  dockerfile_path = os.path.join(project_dir, 'Dockerfile')
  name = project_yaml['name']
  image = project_yaml['image']
  run_tests = project_yaml['run_tests']

  ts = datetime.datetime.now().strftime('%Y%m%d%H%M')

  build_steps = [
      {
          'args': [
              'clone',
              'https://github.com/google/oss-fuzz.git',
          ],
          'name': 'gcr.io/cloud-builders/git',
      },
      {
          'name': 'gcr.io/cloud-builders/docker',
          'args': [
              'build',
              '-t',
              image,
              '.',
          ],
          'dir': 'oss-fuzz/projects/' + name,
      },
      {
          'name':
              image,
          'args': [
              'bash', '-c',
              'srcmap > /workspace/srcmap.json && cat /workspace/srcmap.json'
          ],
          'env': ['OSSFUZZ_REVISION=$REVISION_ID'],
      },
      {
          'name': 'gcr.io/oss-fuzz-base/msan-builder',
          'args': [
              'bash',
              '-c',
              'cp -r /msan /workspace',
          ],
      },
  ]

  for fuzzing_engine in project_yaml['fuzzing_engines']:
    for sanitizer in get_sanitizers(project_yaml):
      for architecture in project_yaml['architectures']:
        if not is_supported_configuration(fuzzing_engine, sanitizer,
                                          architecture):
          continue

        env = CONFIGURATIONS['engine-' + fuzzing_engine][:]
        env.extend(CONFIGURATIONS['sanitizer-' + sanitizer])
        out = '/workspace/out/' + sanitizer
        if architecture == 'x86_64':
          stamped_name = '-'.join([name, sanitizer, ts])
        else:
          stamped_name = '-'.join([name, sanitizer, architecture, ts])
        zip_file = stamped_name + '.zip'
        stamped_srcmap_file = stamped_name + '.srcmap.json'
        bucket = ENGINE_INFO[fuzzing_engine].upload_bucket
        upload_url = get_signed_url(
            UPLOAD_URL_FORMAT.format(bucket, name, zip_file))
        srcmap_url = get_signed_url(
            UPLOAD_URL_FORMAT.format(bucket, name, stamped_srcmap_file))
        targets_list_filename = get_targets_list_filename(sanitizer)
        targets_list_url = get_signed_url(
            get_targets_list_url(bucket, name, sanitizer))

        env.append('OUT=' + out)
        env.append('MSAN_LIBS_PATH=/workspace/msan')

        workdir = workdir_from_dockerfile(dockerfile_path)
        if not workdir:
          workdir = '/src'

        build_steps.append(
            # compile
            {
                'name':
                    image,
                'env':
                    env,
                'args': [
                    'bash',
                    '-c',
                    # Remove /out to break loudly when a build script
                    # incorrectly uses /out instead of $OUT.
                    # `cd /src && cd {workdir}` (where {workdir} is parsed from
                    # the Dockerfile). Container Builder overrides our workdir
                    # so we need to add this step to set it back.
                    'rm -r /out && cd /src && cd {1} && mkdir -p {0} && compile'
                    .format(out, workdir),
                ],
            })

        if run_tests:
          build_steps.append(
              # test binaries
              {
                  'name': 'gcr.io/oss-fuzz-base/base-runner',
                  'env': env,
                  'args': ['bash', '-c', 'test_all'],
              })

        if sanitizer == 'memory':
          # Patch dynamic libraries to use instrumented ones.
          build_steps.append({
              'name':
                  'gcr.io/oss-fuzz-base/msan-builder',
              'args': [
                  'bash',
                  '-c',
                  # TODO(ochang): Replace with just patch_build.py once
                  # permission in image is fixed.
                  'python /usr/local/bin/patch_build.py {0}'.format(out),
              ],
          })

        if project_yaml['labels']:
          # write target labels
          build_steps.append({
              'name':
                  image,
              'env':
                  env,
              'args': [
                  '/usr/local/bin/write_labels.py',
                  json.dumps(project_yaml['labels']),
                  out,
              ],
          })

        build_steps.extend([
            # generate targets list
            {
                'name':
                    'gcr.io/oss-fuzz-base/base-runner',
                'env':
                    env,
                'args': [
                    'bash',
                    '-c',
                    'targets_list > /workspace/{0}'.format(
                        targets_list_filename),
                ],
            },
            # zip binaries
            {
                'name':
                    image,
                'args': [
                    'bash', '-c', 'cd {0} && zip -r {1} *'.format(
                        out, zip_file)
                ],
            },
            # upload srcmap
            {
                'name': 'gcr.io/oss-fuzz-base/uploader',
                'args': [
                    '/workspace/srcmap.json',
                    srcmap_url,
                ],
            },
            # upload binaries
            {
                'name': 'gcr.io/oss-fuzz-base/uploader',
                'args': [
                    os.path.join(out, zip_file),
                    upload_url,
                ],
            },
            # upload targets list
            {
                'name':
                    'gcr.io/oss-fuzz-base/uploader',
                'args': [
                    '/workspace/{0}'.format(targets_list_filename),
                    targets_list_url,
                ],
            },
            # cleanup
            {
                'name': image,
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
                'resource=build%2Fbuild_id%2F{0}&project=oss-fuzz')
  return URL_FORMAT.format(build_id)


def get_targets_list_filename(sanitizer):
  return TARGETS_LIST_BASENAME + '.' + sanitizer


def get_targets_list_url(bucket, project, sanitizer):
  filename = get_targets_list_filename(sanitizer)
  url = UPLOAD_URL_FORMAT.format(bucket, project, filename)
  return url


def run_build(build_steps, project_name, tag):
  options = {}
  if 'GCB_OPTIONS' in os.environ:
    options = yaml.safe_load(os.environ['GCB_OPTIONS'])

  build_body = {
      'steps': build_steps,
      'timeout': str(BUILD_TIMEOUT) + 's',
      'options': options,
      'logsBucket': GCB_LOGS_BUCKET,
      'tags': [project_name + '-' + tag,],
  }

  credentials = GoogleCredentials.get_application_default()
  cloudbuild = build('cloudbuild', 'v1', credentials=credentials)
  build_info = cloudbuild.projects().builds().create(
      projectId='oss-fuzz', body=build_body).execute()
  build_id = build_info['metadata']['build']['id']

  print >> sys.stderr, 'Logs:', get_logs_url(build_id)
  print build_id


def main():
  if len(sys.argv) != 2:
    usage()

  project_dir = sys.argv[1].rstrip(os.path.sep)
  steps = get_build_steps(project_dir)

  project_name = os.path.basename(project_dir)
  run_build(steps, project_name, FUZZING_BUILD_TAG)


if __name__ == '__main__':
  main()
