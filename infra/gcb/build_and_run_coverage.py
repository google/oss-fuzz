#!/usr/bin/python2
"""Starts and runs coverage build on Google Cloud Builder.

Usage: build_and_run_coverage.py <project_dir>
"""

import datetime
import json
import os
import requests
import sys
import urlparse

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

# Link where to upload code coverage report files to.
UPLOAD_URL_FORMAT = 'gs://' + COVERAGE_BUCKET_NAME + '/{project}/{type}/{date}'

# Languages from project.yaml that have code coverage support.
LANGUAGES_WITH_COVERAGE_SUPPORT = ['c', 'cpp']


def skip_build(message):
  """Exit with 0 code not to mark code coverage job as failed."""
  sys.stderr.write('%s\n' % message)

  # Since the script should print build_id, print '0' as a special value.
  print '0'
  exit(0)


def usage():
  sys.stderr.write("Usage: " + sys.argv[0] + " <project_dir>\n")
  exit(1)


def get_build_steps(project_dir):
  project_name = os.path.basename(project_dir)
  project_yaml = build_project.load_project_yaml(project_dir)
  if project_yaml['disabled']:
    skip_build('Project "%s" is disabled.' % project_name)

  build_script_path = os.path.join(project_dir, 'build.sh')
  if os.path.exists(build_script_path):
    with open(build_script_path) as fh:
      if project_yaml['language'] not in LANGUAGES_WITH_COVERAGE_SUPPORT:
        skip_build(('Project "{project_name}" is written in "{language}", '
                    'coverage is not supported yet.').format(
                        project_name=project_name,
                        language=project_yaml['language']))

  dockerfile_path = os.path.join(project_dir, 'Dockerfile')
  name = project_yaml['name']
  image = project_yaml['image']
  report_date = datetime.datetime.now().strftime('%Y%m%d')

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
          'name': image,
          'args': [
              'bash', '-c',
              'srcmap > /workspace/srcmap.json && cat /workspace/srcmap.json'
          ],
          'env': ['OSSFUZZ_REVISION=$REVISION_ID'],
      },
  ]

  env = CONFIGURATION[:]
  out = '/workspace/out/' + SANITIZER
  env.append('OUT=' + out)

  workdir = build_project.workdir_from_dockerfile(dockerfile_path)
  if not workdir:
    workdir = '/src'

  failure_msg = ('*' * 80 + '\nCoverage build failed.\nTo reproduce, run:\n'
                 'python infra/helper.py build_image {name}\n'
                 'python infra/helper.py build_fuzzers --sanitizer coverage '
                 '{name}\n' + '*' * 80).format(name=name)

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
          ('rm -r /out && cd /src && cd {workdir} && mkdir -p {out} && '
           'compile || (echo "{failure_msg}" && false)'
          ).format(workdir=workdir, out=out, failure_msg=failure_msg),
      ],
  })

  download_corpora_step = build_lib.download_corpora_step(project_name)
  if not download_corpora_step:
    skip_build("Skipping code coverage build for %s.\n" % project_name)

  build_steps.append(download_corpora_step)

  failure_msg = ('*' * 80 + '\nCode coverage report generation failed.\n'
                 'To reproduce, run:\n'
                 'python infra/helper.py build_image {name}\n'
                 'python infra/helper.py build_fuzzers --sanitizer coverage '
                 '{name}\n'
                 'python infra/helper.py coverage {name}\n' +
                 '*' * 80).format(name=name)

  # Unpack the corpus and run coverage script.
  build_steps.append({
      'name':
          'gcr.io/oss-fuzz-base/base-runner',
      'env':
          env + [
              'HTTP_PORT=',
              'COVERAGE_EXTRA_ARGS=%s' %
              project_yaml['coverage_extra_args'].strip()
          ],
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

  # Upload the fuzzer stats.
  upload_fuzzer_stats_url = UPLOAD_URL_FORMAT.format(project=project_name,
                                                     type='fuzzer_stats',
                                                     date=report_date)
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

  # Upload the fuzzer logs.
  build_steps.append({
      'name':
          'gcr.io/cloud-builders/gsutil',
      'args': [
          '-m',
          'cp',
          '-r',
          os.path.join(out, 'logs'),
          UPLOAD_URL_FORMAT.format(project=project_name,
                                   type='logs',
                                   date=report_date),
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
      method='PUT',
      content_type='application/json')
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

  build_steps.append({
      'name':
          'gcr.io/cloud-builders/curl',
      'args': [
          '-H',
          'Content-Type: application/json',
          '-X',
          'PUT',
          '-d',
          latest_report_info_body,
          latest_report_info_url,
      ],
  })
  return build_steps


def main():
  if len(sys.argv) != 2:
    usage()

  project_dir = sys.argv[1].rstrip(os.path.sep)
  project_name = os.path.basename(project_dir)
  steps = get_build_steps(project_dir)
  build_project.run_build(steps, project_name, COVERAGE_BUILD_TAG)


if __name__ == "__main__":
  main()
