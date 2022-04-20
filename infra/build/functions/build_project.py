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
#!/usr/bin/env python3
"""Starts project build on Google Cloud Builder.

Usage: build_project.py <project_dir>
"""

from __future__ import print_function

import argparse
import collections
import datetime
import json
import logging
import os
import posixpath
import re
import sys

import oauth2client.client
import six
import yaml

import build_lib

FUZZING_BUILD_TYPE = 'fuzzing'

GCB_LOGS_BUCKET = 'oss-fuzz-gcb-logs'

DEFAULT_ARCHITECTURES = ['x86_64']
DEFAULT_ENGINES = ['libfuzzer', 'afl', 'honggfuzz']
DEFAULT_SANITIZERS = ['address', 'undefined']

LATEST_VERSION_FILENAME = 'latest.version'
LATEST_VERSION_CONTENT_TYPE = 'text/plain'

QUEUE_TTL_SECONDS = 60 * 60 * 24  # 24 hours.

PROJECTS_DIR = os.path.abspath(
    os.path.join(__file__, os.path.pardir, os.path.pardir, os.path.pardir,
                 os.path.pardir, 'projects'))

Config = collections.namedtuple(
    'Config', ['testing', 'test_image_suffix', 'branch', 'parallel', 'upload'])

WORKDIR_REGEX = re.compile(r'\s*WORKDIR\s*([^\s]+)')


class Build:  # pylint: disable=too-few-public-methods
  """Class representing the configuration for a build."""

  def __init__(self, fuzzing_engine, sanitizer, architecture):
    self.fuzzing_engine = fuzzing_engine
    self.sanitizer = sanitizer
    self.architecture = architecture
    self.targets_list_filename = build_lib.get_targets_list_filename(
        self.sanitizer)

  @property
  def out(self):
    """Returns the out directory for the build."""
    return posixpath.join(
        '/workspace/out/',
        f'{self.fuzzing_engine}-{self.sanitizer}-{self.architecture}')


def get_project_data(project_name):
  """(Local only) Returns a tuple containing the contents of the project.yaml
  and Dockerfile of |project_name|. Raises a FileNotFoundError if there is no
  Dockerfile for |project_name|."""
  project_dir = os.path.join(PROJECTS_DIR, project_name)
  dockerfile_path = os.path.join(project_dir, 'Dockerfile')
  try:
    with open(dockerfile_path) as dockerfile:
      dockerfile = dockerfile.read()
  except FileNotFoundError:
    logging.error('Project "%s" does not have a dockerfile.', project_name)
    raise
  project_yaml_path = os.path.join(project_dir, 'project.yaml')
  with open(project_yaml_path, 'r') as project_yaml_file_handle:
    project_yaml_contents = project_yaml_file_handle.read()
  project_yaml = yaml.safe_load(project_yaml_contents)
  return project_yaml, dockerfile


class Project:  # pylint: disable=too-many-instance-attributes
  """Class representing an OSS-Fuzz project."""

  def __init__(self, name, project_yaml, dockerfile, image_project):
    project_yaml = project_yaml.copy()
    set_yaml_defaults(project_yaml)

    self.name = name
    self.image_project = image_project
    self.workdir = workdir_from_dockerfile(dockerfile)
    self._sanitizers = project_yaml['sanitizers']
    self.disabled = project_yaml['disabled']
    self.architectures = project_yaml['architectures']
    self.fuzzing_engines = project_yaml['fuzzing_engines']
    self.coverage_extra_args = project_yaml['coverage_extra_args']
    self.labels = project_yaml['labels']
    self.fuzzing_language = project_yaml['language']
    self.run_tests = project_yaml['run_tests']
    if 'main_repo' in project_yaml:
      self.main_repo = project_yaml['main_repo']
    else:
      self.main_repo = ''

  @property
  def sanitizers(self):
    """Returns processed sanitizers."""
    assert isinstance(self._sanitizers, list)
    processed_sanitizers = []
    for sanitizer in self._sanitizers:
      if isinstance(sanitizer, six.string_types):
        processed_sanitizers.append(sanitizer)
      elif isinstance(sanitizer, dict):
        for key in sanitizer.keys():
          processed_sanitizers.append(key)

    return processed_sanitizers

  @property
  def image(self):
    """Returns the docker image for the project."""
    return f'gcr.io/{self.image_project}/{self.name}'


def get_last_step_id(steps):
  """Returns the id of the last step in |steps|."""
  return steps[-1]['id']


def set_yaml_defaults(project_yaml):
  """Sets project.yaml's default parameters."""
  project_yaml.setdefault('disabled', False)
  project_yaml.setdefault('architectures', DEFAULT_ARCHITECTURES)
  project_yaml.setdefault('sanitizers', DEFAULT_SANITIZERS)
  project_yaml.setdefault('fuzzing_engines', DEFAULT_ENGINES)
  project_yaml.setdefault('run_tests', True)
  project_yaml.setdefault('coverage_extra_args', '')
  project_yaml.setdefault('labels', {})


def is_supported_configuration(build):
  """Check if the given configuration is supported."""
  fuzzing_engine_info = build_lib.ENGINE_INFO[build.fuzzing_engine]
  if build.architecture == 'i386' and build.sanitizer != 'address':
    return False
  return (build.sanitizer in fuzzing_engine_info.supported_sanitizers and
          build.architecture in fuzzing_engine_info.supported_architectures)


def workdir_from_dockerfile(dockerfile):
  """Parses WORKDIR from the Dockerfile."""
  dockerfile_lines = dockerfile.split('\n')
  for line in dockerfile_lines:
    match = re.match(WORKDIR_REGEX, line)
    if match:
      # We need to escape '$' since they're used for subsitutions in Container
      # Builer builds.
      return match.group(1).replace('$', '$$')

  return '/src'


def get_datetime_now():
  """Returns datetime.datetime.now(). Used for mocking."""
  return datetime.datetime.now()


def get_env(fuzzing_language, build):
  """Returns an environment for building. The environment is returned as a list
  and is suitable for use as the "env" parameter in a GCB build step. The
  environment variables are based on the values of |fuzzing_language| and
  |build."""
  env_dict = {
      'FUZZING_LANGUAGE': fuzzing_language,
      'FUZZING_ENGINE': build.fuzzing_engine,
      'SANITIZER': build.sanitizer,
      'ARCHITECTURE': build.architecture,
      # Set HOME so that it doesn't point to a persisted volume (see
      # https://github.com/google/oss-fuzz/issues/6035).
      'HOME': '/root',
      'OUT': build.out,
  }
  return list(sorted([f'{key}={value}' for key, value in env_dict.items()]))


def get_compile_step(project, build, env, parallel):
  """Returns the GCB step for compiling |projects| fuzzers using |env|. The type
  of build is specified by |build|."""
  failure_msg = (
      '*' * 80 + '\nFailed to build.\nTo reproduce, run:\n'
      f'python infra/helper.py build_image {project.name}\n'
      'python infra/helper.py build_fuzzers --sanitizer '
      f'{build.sanitizer} --engine {build.fuzzing_engine} --architecture '
      f'{build.architecture} {project.name}\n' + '*' * 80)
  compile_step = {
      'name': project.image,
      'env': env,
      'args': [
          'bash',
          '-c',
          # Remove /out to make sure there are non instrumented binaries.
          # `cd /src && cd {workdir}` (where {workdir} is parsed from the
          # Dockerfile). Container Builder overrides our workdir so we need
          # to add this step to set it back.
          (f'rm -r /out && cd /src && cd {project.workdir} && '
           f'mkdir -p {build.out} && compile || '
           f'(echo "{failure_msg}" && false)'),
      ],
      'id': get_id('compile', build),
  }
  if parallel:
    maybe_add_parallel(compile_step, build_lib.get_srcmap_step_id(), parallel)
  return compile_step


def maybe_add_parallel(step, wait_for_id, parallel):
  """Makes |step| run immediately after |wait_for_id| if |parallel|. Mutates
  |step|."""
  if not parallel:
    return
  step['waitFor'] = wait_for_id


def get_id(step_type, build):
  """Returns a unique step id based on |step_type| and |build|. Useful for
  parallelizing builds."""
  return (f'{step_type}-{build.fuzzing_engine}-{build.sanitizer}'
          f'-{build.architecture}')


def get_build_steps(  # pylint: disable=too-many-locals, too-many-statements, too-many-branches, too-many-arguments
    project_name, project_yaml, dockerfile, image_project, base_images_project,
    config):
  """Returns build steps for project."""

  project = Project(project_name, project_yaml, dockerfile, image_project)

  if project.disabled:
    logging.info('Project "%s" is disabled.', project.name)
    return []

  timestamp = get_datetime_now().strftime('%Y%m%d%H%M')

  build_steps = build_lib.project_image_steps(
      project.name,
      project.image,
      project.fuzzing_language,
      branch=config.branch,
      test_image_suffix=config.test_image_suffix)

  # Sort engines to make AFL first to test if libFuzzer has an advantage in
  # finding bugs first since it is generally built first.
  for fuzzing_engine in sorted(project.fuzzing_engines):
    for sanitizer in project.sanitizers:
      for architecture in project.architectures:
        build = Build(fuzzing_engine, sanitizer, architecture)
        if not is_supported_configuration(build):
          continue

        env = get_env(project.fuzzing_language, build)
        compile_step = get_compile_step(project, build, env, config.parallel)
        build_steps.append(compile_step)

        if project.run_tests:
          failure_msg = (
              '*' * 80 + '\nBuild checks failed.\n'
              'To reproduce, run:\n'
              f'python infra/helper.py build_image {project.name}\n'
              'python infra/helper.py build_fuzzers --sanitizer '
              f'{build.sanitizer} --engine {build.fuzzing_engine} '
              f'--architecture {build.architecture} {project.name}\n'
              'python infra/helper.py check_build --sanitizer '
              f'{build.sanitizer} --engine {build.fuzzing_engine} '
              f'--architecture {build.architecture} {project.name}\n' +
              '*' * 80)
          # Test fuzz targets.
          test_step = {
              'name':
                  get_runner_image_name(base_images_project,
                                        config.test_image_suffix),
              'env':
                  env,
              'args': [
                  'bash', '-c',
                  f'test_all.py || (echo "{failure_msg}" && false)'
              ],
              'id':
                  get_id('build-check', build)
          }
          maybe_add_parallel(test_step, get_last_step_id(build_steps),
                             config.parallel)
          build_steps.append(test_step)

        if project.labels:
          # Write target labels.
          build_steps.append({
              'name':
                  project.image,
              'env':
                  env,
              'args': [
                  '/usr/local/bin/write_labels.py',
                  json.dumps(project.labels),
                  build.out,
              ],
          })

        if build.sanitizer == 'dataflow' and build.fuzzing_engine == 'dataflow':
          dataflow_steps = dataflow_post_build_steps(project.name, env,
                                                     base_images_project,
                                                     config.testing,
                                                     config.test_image_suffix)
          if dataflow_steps:
            build_steps.extend(dataflow_steps)
          else:
            sys.stderr.write('Skipping dataflow post build steps.\n')

        build_steps.extend([
            # Generate targets list.
            {
                'name':
                    get_runner_image_name(base_images_project,
                                          config.test_image_suffix),
                'env':
                    env,
                'args': [
                    'bash', '-c',
                    f'targets_list > /workspace/{build.targets_list_filename}'
                ],
            }
        ])
        if config.upload:
          upload_steps = get_upload_steps(project, build, timestamp,
                                          base_images_project, config.testing)
          build_steps.extend(upload_steps)

  return build_steps


def get_targets_list_upload_step(bucket, project, build, uploader_image):
  """Returns the step to upload targets_list for |build| of |project| to
  |bucket|."""
  targets_list_url = build_lib.get_signed_url(
      build_lib.get_targets_list_url(bucket, project.name, build.sanitizer))
  return {
      'name': uploader_image,
      'args': [
          f'/workspace/{build.targets_list_filename}',
          targets_list_url,
      ],
  }


def get_uploader_image(base_images_project):
  """Returns the uploader base image in |base_images_project|."""
  return f'gcr.io/{base_images_project}/uploader'


def get_upload_steps(project, build, timestamp, base_images_project, testing):
  """Returns the steps for uploading the fuzzer build specified by |project| and
  |build|. Uses |timestamp| for naming the uploads. Uses |base_images_project|
  and |testing| for determining which image to use for the upload."""
  bucket = build_lib.get_upload_bucket(build.fuzzing_engine, build.architecture,
                                       testing)
  stamped_name = '-'.join([project.name, build.sanitizer, timestamp])
  zip_file = stamped_name + '.zip'
  upload_url = build_lib.get_signed_url(
      build_lib.GCS_UPLOAD_URL_FORMAT.format(bucket, project.name, zip_file))
  stamped_srcmap_file = stamped_name + '.srcmap.json'
  srcmap_url = build_lib.get_signed_url(
      build_lib.GCS_UPLOAD_URL_FORMAT.format(bucket, project.name,
                                             stamped_srcmap_file))
  latest_version_file = '-'.join(
      [project.name, build.sanitizer, LATEST_VERSION_FILENAME])
  latest_version_url = build_lib.GCS_UPLOAD_URL_FORMAT.format(
      bucket, project.name, latest_version_file)
  latest_version_url = build_lib.get_signed_url(
      latest_version_url, content_type=LATEST_VERSION_CONTENT_TYPE)
  uploader_image = get_uploader_image(base_images_project)

  upload_steps = [
      # Zip binaries.
      {
          'name': project.image,
          'args': ['bash', '-c', f'cd {build.out} && zip -r {zip_file} *'],
      },
      # Upload srcmap.
      {
          'name': uploader_image,
          'args': [
              '/workspace/srcmap.json',
              srcmap_url,
          ],
      },
      # Upload binaries.
      {
          'name': uploader_image,
          'args': [
              os.path.join(build.out, zip_file),
              upload_url,
          ],
      },
      # Upload targets list.
      get_targets_list_upload_step(bucket, project, build, uploader_image),
      # Upload the latest.version file.
      build_lib.http_upload_step(zip_file, latest_version_url,
                                 LATEST_VERSION_CONTENT_TYPE),
      # Cleanup.
      get_cleanup_step(project, build),
  ]
  return upload_steps


def get_cleanup_step(project, build):
  """Returns the step for cleaning up after doing |build| of |project|."""
  return {
      'name': project.image,
      'args': [
          'bash',
          '-c',
          'rm -r ' + build.out,
      ],
  }


def get_runner_image_name(base_images_project, test_image_suffix):
  """Returns the runner image that should be used, based on
  |base_images_project|. Returns the testing image if |test_image_suffix|."""
  image = f'gcr.io/{base_images_project}/base-runner'
  if test_image_suffix:
    image += '-' + test_image_suffix
  return image


def dataflow_post_build_steps(project_name, env, base_images_project, testing,
                              test_image_suffix):
  """Appends dataflow post build steps."""
  steps = build_lib.download_corpora_steps(project_name, testing)
  if not steps:
    return None

  steps.append({
      'name':
          get_runner_image_name(base_images_project, test_image_suffix),
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


# pylint: disable=no-member,too-many-arguments
def run_build(oss_fuzz_project,
              build_steps,
              credentials,
              build_type,
              cloud_project='oss-fuzz',
              extra_tags=None):
  """Run the build for given steps on cloud build. |build_steps| are the steps
  to run. |credentials| are are used to authenticate to GCB and build in
  |cloud_project|. |oss_fuzz_project| and |build_type| are used to tag the build
  in GCB so the build can be queried for debugging purposes."""
  if extra_tags is None:
    extra_tags = []
  tags = [oss_fuzz_project + '-' + build_type, build_type, oss_fuzz_project]
  tags.extend(extra_tags)
  timeout = build_lib.BUILD_TIMEOUT
  # TODO(navidem): This is temporary until I fix shorter failing projects.
  if build_type == 'introspector':
    timeout /= 4
  body_overrides = {
      'logsBucket': GCB_LOGS_BUCKET,
      'queueTtl': str(QUEUE_TTL_SECONDS) + 's',
  }
  return build_lib.run_build(build_steps,
                             credentials,
                             cloud_project,
                             timeout,
                             body_overrides=body_overrides,
                             tags=tags)


def get_args(description):
  """Parses command line arguments and returns them. Suitable for a build
  script."""
  parser = argparse.ArgumentParser(sys.argv[0], description=description)
  parser.add_argument('projects', help='Projects.', nargs='+')
  parser.add_argument('--testing',
                      action='store_true',
                      required=False,
                      default=False,
                      help='Upload to testing buckets.')
  parser.add_argument('--test-image-suffix',
                      required=False,
                      default=None,
                      help='Use testing base-images.')
  parser.add_argument('--branch',
                      required=False,
                      default=None,
                      help='Use specified OSS-Fuzz branch.')
  parser.add_argument('--parallel',
                      action='store_true',
                      required=False,
                      default=False,
                      help='Do builds in parallel.')
  return parser.parse_args()


def build_script_main(script_description, get_build_steps_func, build_type):
  """Gets arguments from command line using |script_description| as helpstring
  description. Gets build_steps using |get_build_steps_func| and then runs those
  steps on GCB, tagging the builds with |build_type|. Returns 0 on success, 1 on
  failure."""
  args = get_args(script_description)
  logging.basicConfig(level=logging.INFO)

  image_project = 'oss-fuzz'
  base_images_project = 'oss-fuzz-base'

  credentials = oauth2client.client.GoogleCredentials.get_application_default()
  error = False
  config = Config(args.testing,
                  args.test_image_suffix,
                  args.branch,
                  args.parallel,
                  upload=True)
  for project_name in args.projects:
    logging.info('Getting steps for: "%s".', project_name)
    try:
      project_yaml, dockerfile_contents = get_project_data(project_name)
    except FileNotFoundError:
      logging.error('Couldn\'t get project data. Skipping %s.', project_name)
      error = True
      continue

    steps = get_build_steps_func(project_name, project_yaml,
                                 dockerfile_contents, image_project,
                                 base_images_project, config)
    if not steps:
      logging.error('No steps. Skipping %s.', project_name)
      error = True
      continue

    run_build(project_name, steps, credentials, build_type)
  return 0 if not error else 1


def main():
  """Build and run projects."""
  return build_script_main('Builds a project on GCB.', get_build_steps,
                           FUZZING_BUILD_TYPE)


if __name__ == '__main__':
  sys.exit(main())
