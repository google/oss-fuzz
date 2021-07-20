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
"""Starts project build on Google Cloud Builder.

Usage: build_project.py <project_dir>
"""

from __future__ import print_function

import datetime
import json
import logging
import os
import re
import sys

import six
import yaml

from oauth2client.client import GoogleCredentials
from googleapiclient.discovery import build

import build_lib

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

DEFAULT_ARCHITECTURES = ['x86_64']
DEFAULT_ENGINES = ['libfuzzer', 'afl', 'honggfuzz']
DEFAULT_SANITIZERS = ['address', 'undefined']

LATEST_VERSION_FILENAME = 'latest.version'
LATEST_VERSION_CONTENT_TYPE = 'text/plain'

QUEUE_TTL_SECONDS = 60 * 60 * 24  # 24 hours.


def usage():
  """Exit with code 1 and display syntax to use this file."""
  sys.stderr.write('Usage: ' + sys.argv[0] + ' <project_dir>\n')
  sys.exit(1)


def set_yaml_defaults(project_name, project_yaml, image_project):
  """Set project.yaml's default parameters."""
  project_yaml.setdefault('disabled', False)
  project_yaml.setdefault('name', project_name)
  project_yaml.setdefault('image',
                          'gcr.io/{0}/{1}'.format(image_project, project_name))
  project_yaml.setdefault('architectures', DEFAULT_ARCHITECTURES)
  project_yaml.setdefault('sanitizers', DEFAULT_SANITIZERS)
  project_yaml.setdefault('fuzzing_engines', DEFAULT_ENGINES)
  project_yaml.setdefault('run_tests', True)
  project_yaml.setdefault('coverage_extra_args', '')
  project_yaml.setdefault('labels', {})


def is_supported_configuration(fuzzing_engine, sanitizer, architecture):
  """Check if the given configuration is supported."""
  fuzzing_engine_info = build_lib.ENGINE_INFO[fuzzing_engine]
  if architecture == 'i386' and sanitizer != 'address':
    return False
  return (sanitizer in fuzzing_engine_info.supported_sanitizers and
          architecture in fuzzing_engine_info.supported_architectures)


def get_sanitizers(project_yaml):
  """Retrieve sanitizers from project.yaml."""
  sanitizers = project_yaml['sanitizers']
  assert isinstance(sanitizers, list)

  processed_sanitizers = []
  for sanitizer in sanitizers:
    if isinstance(sanitizer, six.string_types):
      processed_sanitizers.append(sanitizer)
    elif isinstance(sanitizer, dict):
      for key in sanitizer.keys():
        processed_sanitizers.append(key)

  return processed_sanitizers


def workdir_from_dockerfile(dockerfile_lines):
  """Parse WORKDIR from the Dockerfile."""
  workdir_regex = re.compile(r'\s*WORKDIR\s*([^\s]+)')
  for line in dockerfile_lines:
    match = re.match(workdir_regex, line)
    if match:
      # We need to escape '$' since they're used for subsitutions in Container
      # Builer builds.
      return match.group(1).replace('$', '$$')

  return None


def load_project_yaml(project_name, project_yaml_file, image_project):
  """Loads project yaml and sets default values."""
  project_yaml = yaml.safe_load(project_yaml_file)
  set_yaml_defaults(project_name, project_yaml, image_project)
  return project_yaml


# pylint: disable=too-many-locals, too-many-statements, too-many-branches
def get_build_steps(project_name, project_yaml_file, dockerfile_lines,
                    image_project, base_images_project):
  """Returns build steps for project."""
  project_yaml = load_project_yaml(project_name, project_yaml_file,
                                   image_project)

  if project_yaml['disabled']:
    logging.info('Project "%s" is disabled.', project_name)
    return []

  name = project_yaml['name']
  image = project_yaml['image']
  language = project_yaml['language']
  run_tests = project_yaml['run_tests']
  time_stamp = datetime.datetime.now().strftime('%Y%m%d%H%M')

  build_steps = build_lib.project_image_steps(name, image, language)
  # Copy over MSan instrumented libraries.
  build_steps.append({
      'name': 'gcr.io/{0}/msan-libs-builder'.format(base_images_project),
      'args': [
          'bash',
          '-c',
          'cp -r /msan /workspace',
      ],
  })

  # Sort engines to make AFL first to test if libFuzzer has an advantage in
  # finding bugs first since it is generally built first.
  for fuzzing_engine in sorted(project_yaml['fuzzing_engines']):
    for sanitizer in get_sanitizers(project_yaml):
      for architecture in project_yaml['architectures']:
        if not is_supported_configuration(fuzzing_engine, sanitizer,
                                          architecture):
          continue

        env = CONFIGURATIONS['engine-' + fuzzing_engine][:]
        env.extend(CONFIGURATIONS['sanitizer-' + sanitizer])
        out = '/workspace/out/' + sanitizer
        stamped_name = '-'.join([name, sanitizer, time_stamp])
        latest_version_file = '-'.join(
            [name, sanitizer, LATEST_VERSION_FILENAME])
        zip_file = stamped_name + '.zip'
        stamped_srcmap_file = stamped_name + '.srcmap.json'
        bucket = build_lib.ENGINE_INFO[fuzzing_engine].upload_bucket
        if architecture != 'x86_64':
          bucket += '-' + architecture

        upload_url = build_lib.get_signed_url(
            build_lib.GCS_UPLOAD_URL_FORMAT.format(bucket, name, zip_file))
        srcmap_url = build_lib.get_signed_url(
            build_lib.GCS_UPLOAD_URL_FORMAT.format(bucket, name,
                                                   stamped_srcmap_file))
        latest_version_url = build_lib.GCS_UPLOAD_URL_FORMAT.format(
            bucket, name, latest_version_file)
        latest_version_url = build_lib.get_signed_url(
            latest_version_url, content_type=LATEST_VERSION_CONTENT_TYPE)

        targets_list_filename = build_lib.get_targets_list_filename(sanitizer)
        targets_list_url = build_lib.get_signed_url(
            build_lib.get_targets_list_url(bucket, name, sanitizer))

        env.append('OUT=' + out)
        env.append('MSAN_LIBS_PATH=/workspace/msan')
        env.append('ARCHITECTURE=' + architecture)
        env.append('FUZZING_LANGUAGE=' + language)

        workdir = workdir_from_dockerfile(dockerfile_lines)
        if not workdir:
          workdir = '/src'

        failure_msg = ('*' * 80 + '\nFailed to build.\nTo reproduce, run:\n'
                       'python infra/helper.py build_image {name}\n'
                       'python infra/helper.py build_fuzzers --sanitizer '
                       '{sanitizer} --engine {engine} --architecture '
                       '{architecture} {name}\n' + '*' * 80).format(
                           name=name,
                           sanitizer=sanitizer,
                           engine=fuzzing_engine,
                           architecture=architecture)

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
                    # Reset HOME so that it doesn't point to a persisted volume
                    # (see https://github.com/google/oss-fuzz/issues/6035).
                    ('export HOME=/root; rm -r /out && cd /src && cd {workdir} '
                     '&& mkdir -p {out} && compile || (echo "{failure_msg}" '
                     '&& false)').format(workdir=workdir,
                                         out=out,
                                         failure_msg=failure_msg),
                ],
            })

        if sanitizer == 'memory':
          # Patch dynamic libraries to use instrumented ones.
          build_steps.append({
              'name':
                  'gcr.io/{0}/msan-libs-builder'.format(base_images_project),
              'args': [
                  'bash',
                  '-c',
                  # TODO(ochang): Replace with just patch_build.py once
                  # permission in image is fixed.
                  'python /usr/local/bin/patch_build.py {0}'.format(out),
              ],
          })

        if run_tests:
          failure_msg = ('*' * 80 + '\nBuild checks failed.\n'
                         'To reproduce, run:\n'
                         'python infra/helper.py build_image {name}\n'
                         'python infra/helper.py build_fuzzers --sanitizer '
                         '{sanitizer} --engine {engine} --architecture '
                         '{architecture} {name}\n'
                         'python infra/helper.py check_build --sanitizer '
                         '{sanitizer} --engine {engine} --architecture '
                         '{architecture} {name}\n' + '*' * 80).format(
                             name=name,
                             sanitizer=sanitizer,
                             engine=fuzzing_engine,
                             architecture=architecture)

          build_steps.append(
              # test binaries
              {
                  'name':
                      'gcr.io/{0}/base-runner'.format(base_images_project),
                  'env':
                      env,
                  'args': [
                      'bash', '-c',
                      'test_all.py || (echo "{0}" && false)'.format(failure_msg)
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

        if sanitizer == 'dataflow' and fuzzing_engine == 'dataflow':
          dataflow_steps = dataflow_post_build_steps(name, env,
                                                     base_images_project)
          if dataflow_steps:
            build_steps.extend(dataflow_steps)
          else:
            sys.stderr.write('Skipping dataflow post build steps.\n')

        build_steps.extend([
            # generate targets list
            {
                'name':
                    'gcr.io/{0}/base-runner'.format(base_images_project),
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
                    'bash', '-c',
                    'cd {out} && zip -r {zip_file} *'.format(out=out,
                                                             zip_file=zip_file)
                ],
            },
            # upload srcmap
            {
                'name': 'gcr.io/{0}/uploader'.format(base_images_project),
                'args': [
                    '/workspace/srcmap.json',
                    srcmap_url,
                ],
            },
            # upload binaries
            {
                'name': 'gcr.io/{0}/uploader'.format(base_images_project),
                'args': [
                    os.path.join(out, zip_file),
                    upload_url,
                ],
            },
            # upload targets list
            {
                'name':
                    'gcr.io/{0}/uploader'.format(base_images_project),
                'args': [
                    '/workspace/{0}'.format(targets_list_filename),
                    targets_list_url,
                ],
            },
            # upload the latest.version file
            build_lib.http_upload_step(zip_file, latest_version_url,
                                       LATEST_VERSION_CONTENT_TYPE),
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


def dataflow_post_build_steps(project_name, env, base_images_project):
  """Appends dataflow post build steps."""
  steps = build_lib.download_corpora_steps(project_name)
  if not steps:
    return None

  steps.append({
      'name':
          'gcr.io/{0}/base-runner'.format(base_images_project),
      'env':
          env + [
              'COLLECT_DFT_TIMEOUT=2h',
              'DFT_FILE_SIZE_LIMIT=65535',
              'DFT_MIN_TIMEOUT=2.0',
              'DFT_TIMEOUT_RANGE=6.0',
          ],
      'args': [
          'bash', '-c',
          ('for f in /corpus/*.zip; do unzip -q $f -d ${f%%.*}; done && '
           'collect_dft || (echo "DFT collection failed." && false)')
      ],
      'volumes': [{
          'name': 'corpus',
          'path': '/corpus'
      }],
  })
  return steps


def get_logs_url(build_id, image_project='oss-fuzz'):
  """Returns url where logs are displayed for the build."""
  url_format = ('https://console.developers.google.com/logs/viewer?'
                'resource=build%2Fbuild_id%2F{0}&project={1}')
  return url_format.format(build_id, image_project)


# pylint: disable=no-member
def run_build(build_steps, project_name, tag):
  """Run the build for given steps on cloud build."""
  options = {}
  if 'GCB_OPTIONS' in os.environ:
    options = yaml.safe_load(os.environ['GCB_OPTIONS'])

  build_body = {
      'steps': build_steps,
      'timeout': str(build_lib.BUILD_TIMEOUT) + 's',
      'options': options,
      'logsBucket': GCB_LOGS_BUCKET,
      'tags': [project_name + '-' + tag,],
      'queueTtl': str(QUEUE_TTL_SECONDS) + 's',
  }

  credentials = GoogleCredentials.get_application_default()
  cloudbuild = build('cloudbuild',
                     'v1',
                     credentials=credentials,
                     cache_discovery=False)
  build_info = cloudbuild.projects().builds().create(projectId='oss-fuzz',
                                                     body=build_body).execute()
  build_id = build_info['metadata']['build']['id']

  print('Logs:', get_logs_url(build_id), file=sys.stderr)
  print(build_id)


def main():
  """Build and run projects."""
  if len(sys.argv) != 2:
    usage()

  image_project = 'oss-fuzz'
  base_images_project = 'oss-fuzz-base'
  project_dir = sys.argv[1].rstrip(os.path.sep)
  dockerfile_path = os.path.join(project_dir, 'Dockerfile')
  project_yaml_path = os.path.join(project_dir, 'project.yaml')
  project_name = os.path.basename(project_dir)

  with open(dockerfile_path) as dockerfile:
    dockerfile_lines = dockerfile.readlines()

  with open(project_yaml_path) as project_yaml_file:
    steps = get_build_steps(project_name, project_yaml_file, dockerfile_lines,
                            image_project, base_images_project)

  run_build(steps, project_name, FUZZING_BUILD_TAG)


if __name__ == '__main__':
  main()
