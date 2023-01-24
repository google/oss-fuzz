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
"""Starts and runs coverage build on Google Cloud Builder.

Usage: build_and_run_coverage.py <project>.
"""
import json
import logging
import os
import sys
import posixpath

import build_lib
import build_project

SANITIZER = 'coverage'
FUZZING_ENGINE = 'libfuzzer'
ARCHITECTURE = 'x86_64'

PLATFORM = 'linux'

COVERAGE_BUILD_TYPE = 'coverage'
INTROSPECTOR_BUILD_TYPE = 'introspector'

# This is needed for ClusterFuzz to pick up the most recent reports data.

LATEST_REPORT_INFO_CONTENT_TYPE = 'application/json'

# Languages from project.yaml that have code coverage support.
LANGUAGES_WITH_COVERAGE_SUPPORT = [
    'c', 'c++', 'go', 'jvm', 'rust', 'swift', 'python'
]

LANGUAGES_WITH_INTROSPECTOR_SUPPORT = ['c', 'c++', 'python', 'jvm']


class Bucket:  # pylint: disable=too-few-public-methods
  """Class representing the GCS bucket."""
  BUCKET_NAME = None

  def __init__(self, project, date, platform, testing):
    self.bucket_name = self.BUCKET_NAME
    if testing:
      self.bucket_name += '-testing'
    self.date = date
    self.project = project
    self.html_report_url = (
        f'{build_lib.GCS_URL_BASENAME}{self.bucket_name}/{project}'
        f'/reports/{date}/{platform}')
    self.latest_report_info_url = (f'/{self.bucket_name}'
                                   f'/latest_report_info/{project}.json')

  def get_upload_url(self, upload_type):
    """Returns an upload url for |upload_type|."""
    return (f'gs://{self.bucket_name}/{self.project}'
            f'/{upload_type}/{self.date}')


class CoverageBucket(Bucket):  # pylint: disable=too-few-public-methods
  """Class representing the coverage GCS bucket."""
  BUCKET_NAME = 'oss-fuzz-coverage'


class IntrospectorBucket(Bucket):  # pylint: disable=too-few-public-methods
  """Class representing the introspector GCS bucket."""
  BUCKET_NAME = 'oss-fuzz-introspector'


def get_compile_step_ood(fuzzing_engine, project, build, env):
  env.append('OSS_FUZZ_ON_DEMAND=1')
  compile_step = 'git clone https://github.com/google/fuzzbench.git --depth 1 --branch ood /opt/fuzzbench && apt-get install -y gcc gfortran python-dev libopenblas-dev liblapack-dev cython libpq-dev && pip3 install pip --upgrade && CFLAGS= CXXFLAGS= pip3 install -r /opt/fuzzbench/requirements.txt && OOD=1 OSS_FUZZ_ON_DEMAND=1 PYTHONPATH=/opt/fuzzbench python3 -u -c "from fuzzers import utils; utils.initialize_env(); from fuzzers.mopt import fuzzer; fuzzer.build()"'
  compile_step = {
      'name': f'gcr.io/oss-fuzz/{fuzzing_engine}/{project.name}',
      'env': env,
      'args': [
          'bash',
          '-c',
          # Remove /out to make sure there are non instrumented binaries.
          # `cd /src && cd {workdir}` (where {workdir} is parsed from the
          # Dockerfile). Container Builder overrides our workdir so we need
          # to add this step to set it back.
          (f'rm -r /out && cd /src && cd {project.workdir} && '
           f'mkdir -p {build.out} && {compile_step} || true'),
      ],
  }
  build_lib.dockerify_run_step(compile_step,
                               build,
                               use_architecture_image_name=build.is_arm)
  return compile_step


def get_build_steps(  # pylint: disable=too-many-locals, too-many-arguments
    project_name, project_yaml, dockerfile_lines, image_project,
    base_images_project, config):
  """Returns build steps for project."""
  project = build_project.Project(project_name, project_yaml, dockerfile_lines,
                                  image_project)
  assert len(project.fuzzing_engines) == 1, project.fuzzing_engines
  fuzzing_engine = project.fuzzing_engines[0]
  if project.disabled:
    logging.info('Project "%s" is disabled.', project.name)
    return []

  if project.fuzzing_language not in LANGUAGES_WITH_COVERAGE_SUPPORT:
    logging.info(
        'Project "%s" is written in "%s", coverage is not supported yet.',
        project.name, project.fuzzing_language)
    return []

  report_date = build_project.get_datetime_now().strftime('%Y%m%d')
  bucket = CoverageBucket(project.name, report_date, PLATFORM, config.testing)


  build_steps = build_lib.get_project_image_steps(project.name,
                                                  project.image,
                                                  project.fuzzing_language,
                                                  config=config)
  build_steps += build_lib.get_oss_fuzz_on_demand_build_steps(fuzzing_engine, project.image, project.name)

  build = build_project.Build(fuzzing_engine, 'address', ARCHITECTURE)
  env = build_project.get_env(project.fuzzing_language, build)
  logging.info('ood %s', config.oss_fuzz_on_demand)
  build_steps.append(get_compile_step_ood(fuzzing_engine, project, build, env))
  download_corpora_steps = build_lib.download_corpora_steps(
      project.name, test_image_suffix=config.test_image_suffix)
  if not download_corpora_steps:
    logging.info('Skipping code coverage build for %s.', project.name)
    return []

  build_steps.extend(download_corpora_steps)

  failure_msg = ('*' * 80 + '\nCode coverage report generation failed.\n'
                 'To reproduce, run:\n'
                 f'python infra/helper.py build_image {project.name}\n'
                 'python infra/helper.py build_fuzzers --sanitizer coverage '
                 f'{project.name}\n'
                 f'python infra/helper.py coverage {project.name}\n' + '*' * 80)

  # Unpack the corpus and run coverage script.
  coverage_env = env + [
      'HTTP_PORT=',
      f'COVERAGE_EXTRA_ARGS={project.coverage_extra_args.strip()}',
  ]

  build_steps.append({
      'name':
          build_lib.get_runner_image_name(base_images_project,
                                          config.test_image_suffix),
      'env':
          coverage_env,
      'args': [
          'bash', '-c',
          ('for f in /corpus/*.zip; do unzip -q $f -d ${f%%.*} || ('
           ' /out/ && exit 0'
           '); done && run_on_corpora')
      ],
      'volumes': [{
          'name': 'corpus',
          'path': '/corpus'
      }],
  })
  return build_steps


def main():
  """Build and run coverage for projects."""
  coverage_status = build_project.build_script_main(
      'Generates coverage report for project.', get_build_steps,
      COVERAGE_BUILD_TYPE)
  if coverage_status != 0:
    return coverage_status

if __name__ == '__main__':
  sys.exit(main())
