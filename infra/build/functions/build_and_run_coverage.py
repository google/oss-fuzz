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
"""Starts and runs coverage build on Google Cloud Builder.
Usage: build_and_run_coverage.py <project_dir>
"""
import datetime
import json
import logging
import os
import sys

import build_lib
import build_project

SANITIZER = 'coverage'
CONFIGURATION = ['FUZZING_ENGINE=libfuzzer', 'SANITIZER=%s' % SANITIZER]
PLATFORM = 'linux'

COVERAGE_BUILD_TAG = 'coverage'

# Where code coverage reports need to be uploaded to.
COVERAGE_BUCKET_NAME = 'oss-fuzz-coverage'

# Link to the code coverage report in HTML format.
HTML_REPORT_URL_FORMAT = (build_lib.GCS_URL_BASENAME + COVERAGE_BUCKET_NAME +
                          '/{project}/reports/{date}/{platform}/index.html')

# This is needed for ClusterFuzz to pick up the most recent reports data.
LATEST_REPORT_INFO_URL = ('/' + COVERAGE_BUCKET_NAME +
                          '/latest_report_info/{project}.json')
LATEST_REPORT_INFO_CONTENT_TYPE = 'application/json'

# Link where to upload code coverage report files to.
UPLOAD_URL_FORMAT = 'gs://' + COVERAGE_BUCKET_NAME + '/{project}/{type}/{date}'

# Languages from project.yaml that have code coverage support.
LANGUAGES_WITH_COVERAGE_SUPPORT = ['c', 'c++', 'go', 'jvm', 'rust']


def usage():
  """Exit with code 1 and display syntax to use this file."""
  sys.stderr.write("Usage: " + sys.argv[0] + " <project_dir>\n")
  sys.exit(1)


# pylint: disable=too-many-locals
def get_build_steps(project_name, project_yaml_file, dockerfile_lines,
                    image_project, base_images_project):
  """Returns build steps for project."""
  project_yaml = build_project.load_project_yaml(project_name,
                                                 project_yaml_file,
                                                 image_project)
  if project_yaml['disabled']:
    logging.info('Project "%s" is disabled.', project_name)
    return []

  if project_yaml['language'] not in LANGUAGES_WITH_COVERAGE_SUPPORT:
    logging.info(
        'Project "%s" is written in "%s", coverage is not supported yet.',
        project_name, project_yaml['language'])
    return []

  name = project_yaml['name']
  image = project_yaml['image']
  language = project_yaml['language']
  report_date = datetime.datetime.now().strftime('%Y%m%d')

  build_steps = build_lib.project_image_steps(name, image, language)

  env = CONFIGURATION[:]
  out = '/workspace/out/' + SANITIZER
  env.append('OUT=' + out)
  env.append('FUZZING_LANGUAGE=' + language)

  workdir = build_project.workdir_from_dockerfile(dockerfile_lines)
  if not workdir:
    workdir = '/src'

  failure_msg = ('*' * 80 + '\nCoverage build failed.\nTo reproduce, run:\n'
                 f'python infra/helper.py build_image {name}\n'
                 'python infra/helper.py build_fuzzers --sanitizer coverage '
                 f'{name}\n' + '*' * 80)

  # Compilation step.
  build_steps.append({
      'name':
          image,
      'env':
          env,
      'args': [
          'bash',
          '-c',
          # Remove /out to make sure there are non instrumented binaries.
          # `cd /src && cd {workdir}` (where {workdir} is parsed from the
          # Dockerfile). Container Builder overrides our workdir so we need
          # to add this step to set it back.
          (f'rm -r /out && cd /src && cd {workdir} && mkdir -p {out} && '
           f'compile || (echo "{failure_msg}" && false)'),
      ],
  })

  download_corpora_steps = build_lib.download_corpora_steps(project_name)
  if not download_corpora_steps:
    logging.info('Skipping code coverage build for %s.', project_name)
    return []

  build_steps.extend(download_corpora_steps)

  failure_msg = ('*' * 80 + '\nCode coverage report generation failed.\n'
                 'To reproduce, run:\n'
                 f'python infra/helper.py build_image {name}\n'
                 'python infra/helper.py build_fuzzers --sanitizer coverage '
                 f'{name}\n'
                 f'python infra/helper.py coverage {name}\n' + '*' * 80)

  # Unpack the corpus and run coverage script.
  coverage_env = env + [
      'HTTP_PORT=',
      'COVERAGE_EXTRA_ARGS=%s' % project_yaml['coverage_extra_args'].strip(),
  ]
  if 'dataflow' in project_yaml['fuzzing_engines']:
    coverage_env.append('FULL_SUMMARY_PER_TARGET=1')

  build_steps.append({
      'name': f'gcr.io/{base_images_project}/base-runner',
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
  upload_report_url = UPLOAD_URL_FORMAT.format(project=project_name,
                                               type='reports',
                                               date=report_date)

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
          os.path.join(out, 'report'),
          upload_report_url,
      ],
  })

  # Upload the fuzzer stats. Delete the old ones just in case.
  upload_fuzzer_stats_url = UPLOAD_URL_FORMAT.format(project=project_name,
                                                     type='fuzzer_stats',
                                                     date=report_date)
  build_steps.append(build_lib.gsutil_rm_rf_step(upload_fuzzer_stats_url))
  build_steps.append({
      'name':
          'gcr.io/cloud-builders/gsutil',
      'args': [
          '-m',
          'cp',
          '-r',
          os.path.join(out, 'fuzzer_stats'),
          upload_fuzzer_stats_url,
      ],
  })

  # Upload the fuzzer logs. Delete the old ones just in case
  upload_fuzzer_logs_url = UPLOAD_URL_FORMAT.format(project=project_name,
                                                    type='logs',
                                                    date=report_date)
  build_steps.append(build_lib.gsutil_rm_rf_step(upload_fuzzer_logs_url))
  build_steps.append({
      'name':
          'gcr.io/cloud-builders/gsutil',
      'args': [
          '-m',
          'cp',
          '-r',
          os.path.join(out, 'logs'),
          upload_fuzzer_logs_url,
      ],
  })

  # Upload srcmap.
  srcmap_upload_url = UPLOAD_URL_FORMAT.format(project=project_name,
                                               type='srcmap',
                                               date=report_date)
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
      LATEST_REPORT_INFO_URL.format(project=project_name),
      content_type=LATEST_REPORT_INFO_CONTENT_TYPE)
  latest_report_info_body = json.dumps({
      'fuzzer_stats_dir':
          upload_fuzzer_stats_url,
      'html_report_url':
          HTML_REPORT_URL_FORMAT.format(project=project_name,
                                        date=report_date,
                                        platform=PLATFORM),
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


def main():
  """Build and run coverage for projects."""
  if len(sys.argv) != 2:
    usage()

  image_project = 'oss-fuzz'
  base_images_project = 'oss-fuzz-base'
  project_dir = sys.argv[1].rstrip(os.path.sep)
  project_name = os.path.basename(project_dir)
  dockerfile_path = os.path.join(project_dir, 'Dockerfile')
  project_yaml_path = os.path.join(project_dir, 'project.yaml')

  with open(dockerfile_path) as docker_file:
    dockerfile_lines = docker_file.readlines()

  with open(project_yaml_path) as project_yaml_file:
    steps = get_build_steps(project_name, project_yaml_file, dockerfile_lines,
                            image_project, base_images_project)

  build_project.run_build(steps, project_name, COVERAGE_BUILD_TAG)


if __name__ == "__main__":
  main()
