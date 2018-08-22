#!/usr/bin/python2
"""Starts and runs coverage build on Google Cloud Builder.

Usage: build_and_run_coverage.py <project_dir>
"""

import datetime
import os
import requests
import sys
import urlparse

import build_project

SANITIZER = 'profile'
CONFIGURATION = ['FUZZING_ENGINE=libfuzzer', 'SANITIZER=%s' % SANITIZER]

# Where corpus backups can be downloaded from.
CORPUS_BACKUP_URL = ('/{0}-backup.clusterfuzz-external.appspot.com/corpus/'
                     'libFuzzer/{1}/latest.zip')

# Cloud Builder has a limit of 100 build steps and 100 arguments for each step.
CORPUS_DOWNLOAD_BATCH_SIZE = 100

# Needed for reading public target.list.* files.
GCS_URL_BASENAME = 'https://storage.googleapis.com/'

# Where code coverage reports need to be uploaded to.
COVERAGE_BUCKET_NAME = 'oss-fuzz-coverage'
UPLOAD_FUZZER_STATS_URL_FORMAT = (
    'gs://%s/{0}/fuzzer_stats/{1}' % COVERAGE_BUCKET_NAME)
UPLOAD_REPORT_URL_FORMAT = 'gs://%s/{0}/reports/{1}' % COVERAGE_BUCKET_NAME


def usage():
  sys.stderr.write(
    "Usage: " + sys.argv[0] + " <project_dir>\n")
  exit(1)


def get_build_steps(project_dir):
  project_name = os.path.basename(project_dir)
  fuzz_targets = get_targets_list(project_name)
  if not fuzz_targets:
    sys.stderr.write('No fuzz targets found for project "%s".\n' % project_name)

    # Exit with 0 not to mark code coverage job as failed in a case when project
    # did not have any successful builds and there are no fuzz targets recorded.
    # The script should print build_id, print '0' as a special value.
    print '0'
    exit(0)

  project_yaml = build_project.load_project_yaml(project_dir)
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
        CORPUS_BACKUP_URL.format(project_name, qualified_name), method='GET')

      corpus_archive_path = os.path.join('/corpus', binary_name + '.zip')
      download_corpus_args.append('%s %s' % (corpus_archive_path, url))

    build_steps.append(
        # Download corpus.
        {
            'name': 'gcr.io/oss-fuzz-base/base-runner',
            'entrypoint': 'download_corpus',
            'args': download_corpus_args,
            'volumes': [{'name': 'corpus', 'path': '/corpus'}],
        }
    )

  build_steps.extend([
      # Unpack the corpus and run coverage script.
      {
          'name': 'gcr.io/oss-fuzz-base/base-runner',
          'env': env + ['HTTP_PORT=', 'COVERAGE_EXTRA_ARGS='],
          'args': [
              'bash',
              '-c',
              'for f in /corpus/*.zip; do unzip -q $f -d ${f%%.*}; done && coverage',
          ],
          'volumes': [{'name': 'corpus', 'path': '/corpus'}],
      },
      # Upload the report.
      {
          'name': 'gcr.io/cloud-builders/gsutil',
          'args': [
              '-m', 'rsync', '-r', '-d',
              os.path.join(out, 'report'),
              UPLOAD_REPORT_URL_FORMAT.format(project_name, report_date),
          ],
      },
      # Upload the fuzzer stats.
      {
          'name': 'gcr.io/cloud-builders/gsutil',
          'args': [
              '-m', 'rsync', '-r', '-d',
              os.path.join(out, 'fuzzer_stats'),
              UPLOAD_FUZZER_STATS_URL_FORMAT.format(project_name, report_date),
          ],
      },
  ])

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
    sys.stderr.write('Status code: %d \t\tText:\n%s' % (r.status_code, r.text))
    return None

  return r.text.split()


def main():
  if len(sys.argv) != 2:
    usage()

  project_dir = sys.argv[1].rstrip(os.path.sep)
  steps, image = get_build_steps(project_dir)
  build_project.run_build(steps, image)


if __name__ == "__main__":
  main()
