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

import build_lib
import build_project

SANITIZER = 'coverage'
FUZZING_ENGINE = 'libfuzzer'
ARCHITECTURE = 'x86_64'

PLATFORM = 'linux'

COVERAGE_BUILD_TYPE = 'coverage'

# Where code coverage reports need to be uploaded to.
COVERAGE_BUCKET_NAME = 'oss-fuzz-coverage'
INTROSPECTOR_BUCKET_NAME = 'oss-fuzz-introspector'

# This is needed for ClusterFuzz to pick up the most recent reports data.

LATEST_REPORT_INFO_CONTENT_TYPE = 'application/json'

# Languages from project.yaml that have code coverage support.
LANGUAGES_WITH_COVERAGE_SUPPORT = ['c', 'c++', 'go', 'jvm', 'rust', 'swift']


class Bucket:  # pylint: disable=too-few-public-methods
  """Class representing the coverage GCS bucket."""

  def __init__(self, project, date, platform, testing):
    self.coverage_bucket_name = 'oss-fuzz-coverage'
    if testing:
      self.coverage_bucket_name += '-testing'

    self.date = date
    self.project = project
    self.html_report_url = (
        f'{build_lib.GCS_URL_BASENAME}{self.coverage_bucket_name}/{project}'
        f'/reports/{date}/{platform}/index.html')
    self.latest_report_info_url = (f'/{COVERAGE_BUCKET_NAME}'
                                   f'/latest_report_info/{project}.json')

  def get_upload_url(self, upload_type):
    """Returns an upload url for |upload_type|."""
    return (f'gs://{self.coverage_bucket_name}/{self.project}'
            f'/{upload_type}/{self.date}')


class IntrospectorBucket:  # pylint: disable=too-few-public-methods
  """Class representing the fuzz introspector GCS bucket."""

  def __init__(self, project, date, platform, testing):
    self.introspector_bucket_name = 'oss-fuzz-introspector'
    if testing:
      self.introspector_bucket_name += '-testing'

    self.date = date
    self.project = project
    self.html_report_url = (
        f'{build_lib.GCS_URL_BASENAME}{self.introspector_bucket_name}/{project}'
        f'/reports/{date}/{platform}/index.html')
    self.latest_report_info_url = (f'/{INTROSPECTOR_BUCKET_NAME}'
                                   f'/latest_report_info/{project}.json')

  def get_upload_url(self, upload_type):
    """Returns an upload url for |upload_type|."""
    return (f'gs://{self.introspector_bucket_name}/{self.project}'
            f'/{upload_type}/{self.date}')


def get_build_steps(  # pylint: disable=too-many-locals, too-many-arguments
    project_name, project_yaml_contents, dockerfile_lines, image_project,
    base_images_project, config):
  """Returns build steps for project."""
  project = build_project.Project(project_name, project_yaml_contents,
                                  dockerfile_lines, image_project)
  if project.disabled:
    logging.info('Project "%s" is disabled.', project.name)
    return []

  if project.fuzzing_language not in LANGUAGES_WITH_COVERAGE_SUPPORT:
    logging.info(
        'Project "%s" is written in "%s", coverage is not supported yet.',
        project.name, project.fuzzing_language)
    return []

  report_date = build_project.get_datetime_now().strftime('%Y%m%d')
  bucket = Bucket(project.name, report_date, PLATFORM, config.testing)

  build_steps = build_lib.project_image_steps(
      project.name,
      project.image,
      project.fuzzing_language,
      branch=config.branch,
      test_image_suffix=config.test_image_suffix)

  build = build_project.Build('libfuzzer', 'coverage', 'x86_64')
  env = build_project.get_env(project.fuzzing_language, build)
  build_steps.append(
      build_project.get_compile_step(project, build, env, config.parallel))
  download_corpora_steps = build_lib.download_corpora_steps(
      project.name, testing=config.testing)
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
  if 'dataflow' in project.fuzzing_engines:
    coverage_env.append('FULL_SUMMARY_PER_TARGET=1')

  build_steps.append({
      'name': 'gcr.io/oss-fuzz-base/base-runner:introspector',
      'env': coverage_env,
      'args': [
          'bash', '-c',
          ('for f in /corpus/*.zip; do unzip -q $f -d ${f%%.*} || ('
           'echo "Failed to unpack the corpus for $(basename ${f%%.*}). '
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
          bucket.html_report_url,
      'report_date':
          report_date,
      'report_summary_path':
          os.path.join(upload_report_url, PLATFORM, 'summary.json'),
  })

  build_steps.append(
      build_lib.http_upload_step(latest_report_info_body,
                                 latest_report_info_url,
                                 LATEST_REPORT_INFO_CONTENT_TYPE))

  #currently fuzz introspector only supports c and c++
  if project.fuzzing_language in ['c', 'c++']:
    #removes index.html from the end of url
    coverage_url = bucket.html_report_url[:-11]
    build_steps.extend(
        get_fuzz_introspector_steps(project, project_name, base_images_project,
                                    config, coverage_url))
  return build_steps


def get_fuzz_introspector_steps(project, project_name, base_images_project,
                                config, coverage_url):
  build_steps = []
  FI_dir = '/workspace/fuzz-introspector/'
  oss_integration_dir = 'oss_fuzz_integration/'

  report_date = build_project.get_datetime_now().strftime('%Y%m%d')
  bucket = IntrospectorBucket(project.name, report_date, PLATFORM,
                              config.testing)

  build = build_project.Build('libfuzzer', 'instrumentor', 'x86_64')
  env = build_project.get_env(project.fuzzing_language, build)

  clone_step = {
      'args': [
          'clone', 'https://github.com/ossf/fuzz-introspector.git', '--depth',
          '1'
      ],
      'name': 'gcr.io/cloud-builders/git',
  }
  build_steps.append(clone_step)

  build_steps.append({
      'name':
          build_project.get_runner_image_name(base_images_project,
                                              config.test_image_suffix),
      'args': [
          'bash', '-c',
          (f'cd {FI_dir} && cd {oss_integration_dir}'
           ' && sed -i \'s/\.\/infra\/base\-images\/all.sh/#\.\/infra\/base\-images\/all.sh/\''
           ' build_patched_oss_fuzz.sh'
           ' && ./build_patched_oss_fuzz.sh')
      ]
  })

  build_steps.append({
      'name':
          build_project.get_runner_image_name(base_images_project,
                                              config.test_image_suffix),
      'args': [
          'bash', '-c',
          ('sed -i s/base-builder/base-builder:introspector/g '
           f'{FI_dir}{oss_integration_dir}oss-fuzz/projects/{project_name}/Dockerfile'
           f' && cat {FI_dir}{oss_integration_dir}oss-fuzz/projects/{project_name}/Dockerfile'
          )
      ]
  })

  build_steps.append({
      'name':
          'gcr.io/cloud-builders/docker',
      'args': [
          'build',
          '-t',
          f'gcr.io/oss-fuzz/{project_name}',
          '--file',
          f'{FI_dir}{oss_integration_dir}oss-fuzz/projects/{project_name}/Dockerfile',
          f'{FI_dir}{oss_integration_dir}oss-fuzz/projects/{project_name}',
      ],
  })

  build_steps.append(
      build_project.get_compile_step(project, build, env, config.parallel))

  #adjust coverage url
  cov_url_escaped = coverage_url.replace("/", "\/").replace(":", "\:")
  set_cov_url = (
      f'sed -i \'s/http\:\/\/localhost\:8008\/covreport\/linux/{cov_url_escaped}/\''
      ' /src/post-processing/main.py && cat /src/post-processing/main.py && ')
  last_build_step = build_steps[-1]
  last_args = last_build_step['args']
  last_bash_cmd = last_args[2]
  last_bash_cmd = set_cov_url + last_bash_cmd
  build_steps[-1]['args'][2] = last_bash_cmd

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
          os.path.join(build.out, 'inspector-tmp'),
          upload_report_url,
      ],
  })

  return build_steps


def main():
  """Build and run coverage for projects."""
  return build_project.build_script_main(
      'Generates coverage report for project.', get_build_steps,
      COVERAGE_BUILD_TYPE)


if __name__ == '__main__':
  sys.exit(main())
