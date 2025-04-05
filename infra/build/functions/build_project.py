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

import argparse
from dataclasses import dataclass
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
GCB_EXPERIMENT_LOGS_BUCKET = 'oss-fuzz-gcb-experiment-logs'

DEFAULT_ARCHITECTURES = ['x86_64']
DEFAULT_ENGINES = ['libfuzzer', 'afl', 'honggfuzz', 'centipede']
DEFAULT_SANITIZERS = ['address', 'undefined']

LATEST_VERSION_FILENAME = 'latest.version'
LATEST_VERSION_CONTENT_TYPE = 'text/plain'

QUEUE_TTL_SECONDS = 60 * 60 * 24  # 24 hours.

PROJECTS_DIR = os.path.abspath(
    os.path.join(__file__, os.path.pardir, os.path.pardir, os.path.pardir,
                 os.path.pardir, 'projects'))

DEFAULT_OSS_FUZZ_REPO = 'https://github.com/google/oss-fuzz.git'

# Used if build logs are uploaded to a separate place.
LOCAL_BUILD_LOG_PATH = '/workspace/build.log'
BUILD_SUCCESS_MARKER = '/workspace/build.succeeded'

_CACHED_IMAGE = ('us-central1-docker.pkg.dev/oss-fuzz/oss-fuzz-gen/'
                 '{name}-ofg-cached-{sanitizer}')
_CACHED_SANITIZERS = ('address', 'coverage')


@dataclass
class Config:
  testing: bool = False
  test_image_suffix: str = None
  repo: str = DEFAULT_OSS_FUZZ_REPO
  branch: str = None
  parallel: bool = False
  upload: bool = True
  experiment: bool = False
  # TODO(ochang): This should be different per engine+sanitizer combination.
  upload_build_logs: str = None
  build_type: str = None


# Allow the WORKDIR to be commented out for OSS-Fuzz-Gen, which creates new
# Dockerfiles that inherit from cached verisons of the project images.
# e.g.
#   FROM us-central1-docker.pkg.dev/oss-fuzz/oss-fuzz-gen/proj-ofg-cached-address
#   # WORKDIR foo
#   COPY new_target.c /src/proj/
#
# Because the WORKDIR is already set in the parent image and can be a relative
# path, we can't set it again in the new Dockerfile.
# However, we still need to know what the value is (for GCB), so we leave it
# commented.
WORKDIR_REGEX = re.compile(r'\s*#?\s*WORKDIR\s*([^\s]+)')


class Build:  # pylint: disable=too-few-public-methods
  """Class representing the configuration for a build."""

  def __init__(self, fuzzing_engine, sanitizer, architecture):
    self.fuzzing_engine = fuzzing_engine
    self.sanitizer = sanitizer
    self.architecture = architecture
    self.targets_list_filename = build_lib.get_targets_list_filename(
        self.sanitizer)

  @property
  def is_arm(self):
    """Returns True if CPU architecture is ARM-based."""
    return self.architecture == 'aarch64'

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


def get_sanitizer_strings(sanitizers):
  """Accepts the sanitizers field from project.yaml where some sanitizers can be
  defined as experimental. Returns a list of sanitizers."""
  processed_sanitizers = []
  for sanitizer in sanitizers:
    if isinstance(sanitizer, six.string_types):
      processed_sanitizers.append(sanitizer)
    elif isinstance(sanitizer, dict):
      processed_sanitizers.extend(sanitizer.keys())

  return processed_sanitizers


def set_default_sanitizer_for_centipede(project_yaml):
  """Adds none as a sanitizer for centipede in yaml if it does not exist yet."""
  # Centipede requires a separate unsanitized binary to use sanitized ones.
  if ('centipede' in project_yaml['fuzzing_engines'] and
      project_yaml['sanitizers'] and 'none' not in project_yaml['sanitizers']):
    project_yaml['sanitizers'].append('none')


class Project:  # pylint: disable=too-many-instance-attributes
  """Class representing an OSS-Fuzz project."""

  def __init__(self, name, project_yaml, dockerfile):
    project_yaml = project_yaml.copy()
    set_yaml_defaults(project_yaml)

    self.name = name
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

    # This is set to enable build infra to use cached images (which are
    # specific to a sanitizer).
    # TODO: find a better way to handle this.
    self.cached_sanitizer = None

    # This is used by OSS-Fuzz-Gen, which generates fake project names for each
    # benchmark. We still need access to the real project name in some cases.
    self.real_name = self.name

  @property
  def sanitizers(self):
    """Returns processed sanitizers."""
    assert isinstance(self._sanitizers, list)
    return get_sanitizer_strings(self._sanitizers)

  @property
  def image(self):
    """Returns the docker image for the project."""
    return f'gcr.io/{build_lib.IMAGE_PROJECT}/{self.name}'

  @property
  def cached_image(self):
    return _CACHED_IMAGE.format(name=self.real_name,
                                sanitizer=self.cached_sanitizer)


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
  # Adds 'none' as a sanitizer for centipede to the project yaml by default,
  # because Centipede always requires a separate build of unsanitized binary.
  set_default_sanitizer_for_centipede(project_yaml)


def is_supported_configuration(build):
  """Check if the given configuration is supported."""
  fuzzing_engine_info = build_lib.ENGINE_INFO[build.fuzzing_engine]
  if build.architecture == 'i386' and build.sanitizer != 'address':
    return False
  # TODO(jonathanmetzman): UBSan should be easy to support.
  if build.architecture == 'aarch64' and (build.sanitizer
                                          not in {'address', 'hwaddress'}):
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


def get_compile_step(project,
                     build,
                     env,
                     parallel,
                     upload_build_logs=None,
                     allow_failure=False):
  """Returns the GCB step for compiling |projects| fuzzers using |env|. The type
  of build is specified by |build|."""
  failure_msg = (
      '*' * 80 + '\nFailed to build.\nTo reproduce, run:\n'
      f'python infra/helper.py build_image {project.name}\n'
      'python infra/helper.py build_fuzzers --sanitizer '
      f'{build.sanitizer} --engine {build.fuzzing_engine} --architecture '
      f'{build.architecture} {project.name}\n' + '*' * 80)
  compile_output_redirect = ''

  if upload_build_logs:
    # Also write a build success marker because this step needs to succeed first
    # for a subsequent step to upload the log.
    compile_output_redirect = (
        f'&> {LOCAL_BUILD_LOG_PATH} && touch {BUILD_SUCCESS_MARKER}')

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
           f'mkdir -p {build.out} && compile {compile_output_redirect}|| '
           f'(echo "{failure_msg}" && false)'),
      ],
      'id': get_id('compile', build),
  }

  if upload_build_logs or allow_failure:
    # The failure will be reported in a subsequent step.
    compile_step['allowFailure'] = True

  build_lib.dockerify_run_step(compile_step,
                               build,
                               use_architecture_image_name=build.is_arm)
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
    project_name,
    project_yaml,
    dockerfile,
    config,
    additional_env=None,
    use_caching=False):
  """Returns build steps for project."""

  project = Project(project_name, project_yaml, dockerfile)
  return get_build_steps_for_project(project,
                                     config,
                                     additional_env=additional_env,
                                     use_caching=use_caching)


def get_build_steps_for_project(project,
                                config,
                                additional_env=None,
                                use_caching=False):
  """Returns build steps for project."""

  if project.disabled:
    logging.info('Project "%s" is disabled.', project.name)
    return []

  timestamp = get_datetime_now().strftime('%Y%m%d%H%M')

  if use_caching:
    # For cached builds: the cache images are sanitizer-specific, so we need to
    # do a rebuild prior to each compile.
    build_steps = []
  else:
    # Non-cached builds just use a single builder image to build all sanitizers.
    build_steps = build_lib.get_project_image_steps(
        project.name,
        project.image,
        project.fuzzing_language,
        config=config,
        architectures=project.architectures,
        experiment=config.experiment)

  # Sort engines to make AFL first to test if libFuzzer has an advantage in
  # finding bugs first since it is generally built first.
  for fuzzing_engine in sorted(project.fuzzing_engines):
    # Sort sanitizers and architectures so order is determinisitic (good for
    # tests).
    for sanitizer in sorted(project.sanitizers):
      if use_caching and sanitizer in _CACHED_SANITIZERS:
        project.cached_sanitizer = sanitizer
        build_steps.extend(
            build_lib.get_project_image_steps(
                project.name,
                project.image,
                project.fuzzing_language,
                config=config,
                architectures=project.architectures,
                experiment=config.experiment,
                cache_image=project.cached_image))

      # Build x86_64 before i386.
      for architecture in reversed(sorted(project.architectures)):
        build = Build(fuzzing_engine, sanitizer, architecture)
        if not is_supported_configuration(build):
          continue

        env = get_env(project.fuzzing_language, build)
        if additional_env:
          env.extend(additional_env)

        compile_step = get_compile_step(project, build, env, config.parallel,
                                        config.upload_build_logs)
        build_steps.append(compile_step)
        if config.upload_build_logs:
          build_steps.append({
              'name':
                  'gcr.io/cloud-builders/gsutil',
              'args': [
                  '-m', 'cp', LOCAL_BUILD_LOG_PATH, config.upload_build_logs
              ],
          })

          # Report the build failure if it happened.
          build_steps.append({
              'name':
                  project.image,
              'args': [
                  'bash', '-c',
                  f'cat {LOCAL_BUILD_LOG_PATH} && test -f {BUILD_SUCCESS_MARKER}'
              ],
          })

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
              'name': build_lib.get_runner_image_name(config.test_image_suffix),
              'env': env,
              'args': [
                  'bash', '-c',
                  f'test_all.py || (echo "{failure_msg}" && false)'
              ],
              'id': get_id('build-check', build)
          }
          build_lib.dockerify_run_step(test_step, build)
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

        build_steps.extend([
            # Generate targets list.
            {
                'name':
                    build_lib.get_runner_image_name(config.test_image_suffix),
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
                                          config.testing)
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


def get_uploader_image():
  """Returns the uploader base image in |base_images_project|."""
  return f'gcr.io/{build_lib.BASE_IMAGES_PROJECT}/uploader'


def get_upload_steps(project, build, timestamp, testing):
  """Returns the steps for uploading the fuzzer build specified by |project| and
  |build|. Uses |timestamp| for naming the uploads. Uses |testing| for
  determining which image to use for the upload."""
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
  uploader_image = get_uploader_image()

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


# pylint: disable=no-member,too-many-arguments
def run_build(oss_fuzz_project,
              build_steps,
              credentials,
              build_type,
              cloud_project='oss-fuzz',
              extra_tags=None,
              experiment=False):
  """Run the build for given steps on cloud build. |build_steps| are the steps
  to run. |credentials| are are used to authenticate to GCB and build in
  |cloud_project|. |oss_fuzz_project| and |build_type| are used to tag the build
  in GCB so the build can be queried for debugging purposes."""
  if extra_tags is None:
    extra_tags = []
  tags = [oss_fuzz_project + '-' + build_type, build_type, oss_fuzz_project]
  tags.extend(extra_tags)
  timeout = build_lib.BUILD_TIMEOUT
  bucket = GCB_LOGS_BUCKET if not experiment else GCB_EXPERIMENT_LOGS_BUCKET
  body_overrides = {
      'logsBucket': bucket,
      'queueTtl': str(QUEUE_TTL_SECONDS) + 's',
  }
  return build_lib.run_build(oss_fuzz_project,
                             build_steps,
                             credentials,
                             cloud_project,
                             timeout,
                             body_overrides=body_overrides,
                             tags=tags,
                             experiment=experiment)


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
  parser.add_argument('--experiment',
                      action='store_true',
                      required=False,
                      default=False,
                      help='Configuration for experiments.')
  return parser.parse_args()


def create_config(args, build_type):
  """Create a Config object from parsed command line |args|."""
  upload = not args.experiment
  return Config(testing=args.testing,
                test_image_suffix=args.test_image_suffix,
                branch=args.branch,
                parallel=args.parallel,
                upload=upload,
                experiment=args.experiment,
                build_type=build_type)


def build_script_main(script_description, get_build_steps_func, build_type):
  """Gets arguments from command line using |script_description| as helpstring
  description. Gets build_steps using |get_build_steps_func| and then runs those
  steps on GCB, tagging the builds with |build_type|. Returns 0 on success, 1 on
  failure."""
  args = get_args(script_description)
  logging.basicConfig(level=logging.INFO)

  credentials = oauth2client.client.GoogleCredentials.get_application_default()
  error = False
  config = create_config(args, build_type)
  for project_name in args.projects:
    logging.info('Getting steps for: "%s".', project_name)
    try:
      project_yaml, dockerfile_contents = get_project_data(project_name)
    except FileNotFoundError:
      logging.error('Couldn\'t get project data. Skipping %s.', project_name)
      error = True
      continue

    steps = get_build_steps_func(project_name, project_yaml,
                                 dockerfile_contents, config)
    if not steps:
      logging.error('No steps. Skipping %s.', project_name)
      error = True
      continue

    run_build(project_name,
              steps,
              credentials,
              build_type,
              experiment=args.experiment)
  return 0 if not error else 1


def main():
  """Build and run projects."""
  return build_script_main('Builds a project on GCB.', get_build_steps,
                           FUZZING_BUILD_TYPE)


if __name__ == '__main__':
  sys.exit(main())
