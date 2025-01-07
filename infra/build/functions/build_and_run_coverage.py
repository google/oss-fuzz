#!/usr/bin/env python3
#
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

LANGUAGES_WITH_INTROSPECTOR_SUPPORT = ['c', 'c++', 'python', 'jvm', 'rust']


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


def get_build_steps(  # pylint: disable=too-many-locals, too-many-arguments
    project_name, project_yaml, dockerfile_lines, config):
  """Returns build steps for project."""
  project = build_project.Project(project_name, project_yaml, dockerfile_lines)
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

  build = build_project.Build(FUZZING_ENGINE, 'coverage', ARCHITECTURE)
  env = build_project.get_env(project.fuzzing_language, build)
  build_steps.append(
      build_project.get_compile_step(project, build, env, config.parallel))
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
      'name': build_lib.get_runner_image_name(config.test_image_suffix),
      'env': coverage_env,
      'args': [
          'bash', '-c',
          ('for f in /corpus/*.zip; do unzip -q $f -d ${f%.*} || ('
           'echo "Failed to unpack the corpus for $(basename ${f%.*}). '
           'This usually means that corpus backup for a particular fuzz '
           'target does not exist. If a fuzz target was added in the last '
           '24 hours, please wait one more day. Otherwise, something is '
           'wrong with the fuzz target or the infrastructure, and corpus '
           'pruning task does not finish successfully." && exit 1'
           '); done && coverage || (echo "' + failure_msg + '" && false)')
      ],
      'volumes': [{
          'name': 'corpus',
          'path': '/corpus'
      }],
  })

  # Upload the report.
  upload_report_url = bucket.get_upload_url('reports')
  upload_report_by_target_url = bucket.get_upload_url('reports-by-target')

  # Delete the existing report as gsutil cannot overwrite it in a useful way due
  # to the lack of `-T` option (it creates a subdir in the destination dir).
  build_steps.append(build_lib.gsutil_rm_rf_step(upload_report_url))
  build_steps.append({
      'name':
          'gcr.io/cloud-builders/gsutil',
      'args': [
          '-m',
          'cp',
          '-r',
          os.path.join(build.out, 'report'),
          upload_report_url,
      ],
  })

  # TODO(navidem):
  # Currently python and jvm coverage does not produce per_target reports.
  # Skipping python for now to avoid breakage.
  if (project.fuzzing_language not in ['python', 'jvm'] and
      project.fuzzing_language in LANGUAGES_WITH_INTROSPECTOR_SUPPORT):
    build_steps.append(build_lib.gsutil_rm_rf_step(upload_report_by_target_url))
    build_steps.append({
        'name':
            'gcr.io/cloud-builders/gsutil',
        'args': [
            '-m',
            'cp',
            '-r',
            os.path.join(build.out, 'report_target'),
            upload_report_by_target_url,
        ],
    })

  # Upload the fuzzer stats. Delete the old ones just in case.
  upload_fuzzer_stats_url = bucket.get_upload_url('fuzzer_stats')

  build_steps.append(build_lib.gsutil_rm_rf_step(upload_fuzzer_stats_url))
  build_steps.append({
      'name':
          'gcr.io/cloud-builders/gsutil',
      'args': [
          '-m',
          'cp',
          '-r',
          os.path.join(build.out, 'fuzzer_stats'),
          upload_fuzzer_stats_url,
      ],
  })

  if project.fuzzing_language in LANGUAGES_WITH_INTROSPECTOR_SUPPORT:
    # Upload the text coverage reports. Delete the old ones just in case.
    upload_textcov_reports_url = bucket.get_upload_url('textcov_reports')

    build_steps.append(build_lib.gsutil_rm_rf_step(upload_textcov_reports_url))
    build_steps.append({
        'name':
            'gcr.io/cloud-builders/gsutil',
        'args': [
            '-m',
            'cp',
            '-r',
            os.path.join(build.out, 'textcov_reports'),
            upload_textcov_reports_url,
        ],
    })

  # Upload the fuzzer logs. Delete the old ones just in case
  upload_fuzzer_logs_url = bucket.get_upload_url('logs')
  build_steps.append(build_lib.gsutil_rm_rf_step(upload_fuzzer_logs_url))
  build_steps.append({
      'name':
          'gcr.io/cloud-builders/gsutil',
      'args': [
          '-m',
          'cp',
          '-r',
          os.path.join(build.out, 'logs'),
          upload_fuzzer_logs_url,
      ],
  })

  # Upload srcmap.
  srcmap_upload_url = bucket.get_upload_url('srcmap')
  srcmap_upload_url = srcmap_upload_url.rstrip('/') + '.json'
  build_steps.append({
      'name': 'gcr.io/cloud-builders/gsutil',
      'args': [
          'cp',
          '/workspace/srcmap.json',
          srcmap_upload_url,
      ],
  })

  # Update the latest report information file for ClusterFuzz.
  latest_report_info_url = build_lib.get_signed_url(
      bucket.latest_report_info_url,
      content_type=LATEST_REPORT_INFO_CONTENT_TYPE)
  latest_report_info_body = json.dumps({
      'fuzzer_stats_dir':
          upload_fuzzer_stats_url,
      'html_report_url':
          posixpath.join(bucket.html_report_url, 'index.html'),
      'report_date':
          report_date,
      'report_summary_path':
          os.path.join(upload_report_url, PLATFORM, 'summary.json'),
  })

  build_steps.append(
      build_lib.http_upload_step(latest_report_info_body,
                                 latest_report_info_url,
                                 LATEST_REPORT_INFO_CONTENT_TYPE))

  return build_steps


def get_fuzz_introspector_steps(  # pylint: disable=too-many-locals, too-many-arguments, unused-argument
    project_name, project_yaml, dockerfile_lines, config):
  """Returns build steps of fuzz introspector for project"""

  project = build_project.Project(project_name, project_yaml, dockerfile_lines)
  if project.disabled:
    logging.info('Project "%s" is disabled.', project.name)
    return []

  if project.fuzzing_language not in LANGUAGES_WITH_INTROSPECTOR_SUPPORT:
    logging.info(('Project "%s" is written in "%s", '
                  'Fuzz Introspector is not supported yet.'), project.name,
                 project.fuzzing_language)
    return []

  build_steps = []
  build = build_project.Build(FUZZING_ENGINE, 'introspector', ARCHITECTURE)

  report_date = build_project.get_datetime_now().strftime('%Y%m%d')
  bucket = IntrospectorBucket(project.name, report_date, PLATFORM,
                              config.testing)

  # TODO (navidem): find the latest coverage report.
  coverage_report_latest = report_date
  bucket_name = 'oss-fuzz-coverage'

  coverage_url = (f'{build_lib.GCS_URL_BASENAME}{bucket_name}/{project.name}'
                  f'/reports/{coverage_report_latest}/linux')

  download_coverage_steps = build_lib.download_coverage_data_steps(
      project.name, coverage_report_latest, bucket_name, build.out)
  if not download_coverage_steps:
    logging.warning(
        'Skipping introspector build for %s. No coverage data found.',
        project.name)
    return []
  build_steps.extend(download_coverage_steps)
  build_steps.extend(
      build_lib.get_project_image_steps(project.name,
                                        project.image,
                                        project.fuzzing_language,
                                        config=config))
  env = build_project.get_env(project.fuzzing_language, build)
  env.append(f'GIT_REPO={project.main_repo}')
  env.append(f'COVERAGE_URL={coverage_url}')
  env.append(f'PROJECT_NAME={project.name}')

  build_steps.append(
      build_project.get_compile_step(project,
                                     build,
                                     env,
                                     config.parallel,
                                     allow_failure=True))

  # Upload the report.
  upload_report_url = bucket.get_upload_url('inspector-report')

  # Delete the existing report as gsutil cannot overwrite it in a useful way due
  # to the lack of `-T` option (it creates a subdir in the destination dir).
  build_steps.append(build_lib.gsutil_rm_rf_step(upload_report_url))
  build_steps.append({
      'name':
          'gcr.io/cloud-builders/gsutil',
      'args': [
          '-m',
          'cp',
          '-r',
          os.path.join(build.out, 'inspector'),
          upload_report_url,
      ],
  })

  return build_steps


def main():
  """Build and run coverage for projects."""
  coverage_status = build_project.build_script_main(
      'Generates coverage report for project.', get_build_steps,
      COVERAGE_BUILD_TYPE)
  if coverage_status != 0:
    return coverage_status

  return build_project.build_script_main(
      'Generates introspector report for project.', get_fuzz_introspector_steps,
      INTROSPECTOR_BUILD_TYPE)


if __name__ == '__main__':
  sys.exit(main())
