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

import build_project

SANITIZER = 'coverage'
CONFIGURATION = ['FUZZING_ENGINE=libfuzzer', 'SANITIZER=%s' % SANITIZER]
PLATFORM = 'linux'

# Where corpus backups can be downloaded from.
CORPUS_BACKUP_URL = ('/{project}-backup.clusterfuzz-external.appspot.com/'
                     'corpus/libFuzzer/{fuzzer}/latest.zip')

# Cloud Builder has a limit of 100 build steps and 100 arguments for each step.
CORPUS_DOWNLOAD_BATCH_SIZE = 100

COVERAGE_BUILD_TAG = 'coverage'

# Needed for reading public target.list.* files.
GCS_URL_BASENAME = 'https://storage.googleapis.com/'

# Where code coverage reports need to be uploaded to.
COVERAGE_BUCKET_NAME = 'oss-fuzz-coverage'

# Link to the code coverage report in HTML format.
HTML_REPORT_URL_FORMAT = (
    GCS_URL_BASENAME + COVERAGE_BUCKET_NAME +
    '/{project}/reports/{date}/{platform}/index.html')

# This is needed for ClusterFuzz to pick up the most recent reports data.
LATEST_REPORT_INFO_URL = (
    '/' + COVERAGE_BUCKET_NAME + '/latest_report_info/{project}.json')

# Link where to upload code coverage report files to.
UPLOAD_URL_FORMAT = 'gs://' + COVERAGE_BUCKET_NAME + '/{project}/{type}/{date}'


def skip_build(message):
  """Exit with 0 code not to mark code coverage job as failed."""
  sys.stderr.write('%s\n' % message)

  # Since the script should print build_id, print '0' as a special value.
  print '0'
  exit(0)


def usage():
  sys.stderr.write(
    "Usage: " + sys.argv[0] + " <project_dir>\n")
  exit(1)


def get_build_steps(project_dir):
  project_name = os.path.basename(project_dir)
  project_yaml = build_project.load_project_yaml(project_dir)
  if project_yaml['disabled']:
    skip_build('Project "%s" is disabled.' % project_name)

  fuzz_targets = get_targets_list(project_name)
  if not fuzz_targets:
    skip_build('No fuzz targets found for project "%s".' % project_name)

  dockerfile_path = os.path.join(project_dir, 'Dockerfile')
  name = project_yaml['name']
  image = project_yaml['image']
  report_date = datetime.datetime.now().strftime('%Y%m%d')

  build_steps = [
      {
          'args': [
              'clone', 'https://github.com/google/oss-fuzz.git',
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
  ]

  env = CONFIGURATION[:]
  out = '/workspace/out/' + SANITIZER
  env.append('OUT=' + out)

  workdir = build_project.workdir_from_dockerfile(dockerfile_path)
  if not workdir:
    workdir = '/src'

  # Compilation step.
  build_steps.append(
      {
          'name': image,
          'env': env,
          'args': [
              'bash',
              '-c',
               # Remove /out to make sure there are non instrumented binaries.
               # `cd /src && cd {workdir}` (where {workdir} is parsed from the
               # Dockerfile). Container Builder overrides our workdir so we need
               # to add this step to set it back.
               'rm -r /out && cd /src && cd {1} && mkdir -p {0} && compile'.format(out, workdir),
          ],
      }
  )

  # Split fuzz targets into batches of CORPUS_DOWNLOAD_BATCH_SIZE.
  for i in xrange(0,  len(fuzz_targets), CORPUS_DOWNLOAD_BATCH_SIZE):
    download_corpus_args = []
    for binary_name in fuzz_targets[i : i+CORPUS_DOWNLOAD_BATCH_SIZE]:
      qualified_name = binary_name
      qualified_name_prefix = '%s_' % project_name
      if not binary_name.startswith(qualified_name_prefix):
        qualified_name = qualified_name_prefix + binary_name

      url = build_project.get_signed_url(
          CORPUS_BACKUP_URL.format(
              project=project_name, fuzzer=qualified_name),
          method='GET')

      corpus_archive_path = os.path.join('/corpus', binary_name + '.zip')
      download_corpus_args.append('%s %s' % (corpus_archive_path, url))

    # Download corpus.
    build_steps.append(
        {
            'name': 'gcr.io/oss-fuzz-base/base-runner',
            'entrypoint': 'download_corpus',
            'args': download_corpus_args,
            'volumes': [{'name': 'corpus', 'path': '/corpus'}],
        }
    )

  # Unpack the corpus and run coverage script.
  build_steps.append(
      {
          'name': 'gcr.io/oss-fuzz-base/base-runner',
          'env': env + [
              'HTTP_PORT=',
              'COVERAGE_EXTRA_ARGS=%s' % project_yaml['coverage_extra_args'].strip()
          ],
          'args': [
              'bash',
              '-c',
              'for f in /corpus/*.zip; do unzip -q $f -d ${f%%.*}; done && coverage',
          ],
          'volumes': [{'name': 'corpus', 'path': '/corpus'}],
      }
  )

  # Upload the report.
  upload_report_url = UPLOAD_URL_FORMAT.format(
      project=project_name, type='reports', date=report_date)
  build_steps.append(
      {
          'name': 'gcr.io/cloud-builders/gsutil',
          'args': [
              '-m', 'rsync', '-r', '-d',
              os.path.join(out, 'report'),
              upload_report_url,
          ],
      }
  )

  # Upload the fuzzer stats.
  upload_fuzzer_stats_url = UPLOAD_URL_FORMAT.format(
      project=project_name, type='fuzzer_stats', date=report_date)
  build_steps.append(
      {
          'name': 'gcr.io/cloud-builders/gsutil',
          'args': [
              '-m', 'rsync', '-r', '-d',
              os.path.join(out, 'fuzzer_stats'),
              upload_fuzzer_stats_url,
          ],
      }
  )

  # Upload the fuzzer logs.
  build_steps.append(
      {
          'name': 'gcr.io/cloud-builders/gsutil',
          'args': [
              '-m', 'rsync', '-r', '-d',
              os.path.join(out, 'logs'),
              UPLOAD_URL_FORMAT.format(
                  project=project_name, type='logs', date=report_date),
          ],
      }
  )

  # Upload srcmap.
  srcmap_upload_url = UPLOAD_URL_FORMAT.format(
      project=project_name, type='srcmap', date=report_date)
  srcmap_upload_url = srcmap_upload_url.rstrip('/') + '.json'
  build_steps.append(
      {
          'name': 'gcr.io/cloud-builders/gsutil',
          'args': [
              'cp',
              '/workspace/srcmap.json',
              srcmap_upload_url,
          ],
      }
  )

  # Update the latest report information file for ClusterFuzz.
  latest_report_info_url = build_project.get_signed_url(
      LATEST_REPORT_INFO_URL.format(project=project_name),
      method='PUT',
      content_type='application/json')
  latest_report_info_body = json.dumps(
      {
          'fuzzer_stats_dir': upload_fuzzer_stats_url,
          'html_report_url': HTML_REPORT_URL_FORMAT.format(
              project=project_name, date=report_date, platform=PLATFORM),
          'report_date': report_date,
          'report_summary_path': os.path.join(
              upload_report_url, PLATFORM, 'summary.json'),
      }
  )

  build_steps.append(
      {
          'name': 'gcr.io/cloud-builders/curl',
          'args': [
              '-H', 'Content-Type: application/json',
              '-X', 'PUT',
              '-d', latest_report_info_body,
              latest_report_info_url,
          ],
      }
  )
  return build_steps, image


def get_targets_list(project_name):
  # libFuzzer ASan is the default configuration, get list of targets from it.
  url = build_project.get_targets_list_url(
      build_project.ENGINE_INFO['libfuzzer'].upload_bucket,
      project_name,
      'address')

  url = urlparse.urljoin(GCS_URL_BASENAME , url)
  r = requests.get(url)
  if not r.status_code == 200:
    sys.stderr.write('Failed to get list of targets from "%s".\n' % url)
    sys.stderr.write('Status code: %d \t\tText:\n%s\n' % (r.status_code, r.text))
    return None

  return r.text.split()


def main():
  if len(sys.argv) != 2:
    usage()

  project_dir = sys.argv[1].rstrip(os.path.sep)
  steps, image = get_build_steps(project_dir)
  build_project.run_build(steps, image, COVERAGE_BUILD_TAG)


if __name__ == "__main__":
  main()
