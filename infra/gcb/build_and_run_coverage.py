#!/usr/bin/python2

"""Starts and runs coverage build on Google Cloud Builder.

Usage: build_and_run_coverage.py <project_dir>
"""

import datetime
import os
import sys
import requests
import urlparse

import build_project

BUILD_TIMEOUT = 10 * 60 * 60

CONFIGURATION = ['FUZZING_ENGINE=libfuzzer', 'SANITIZER=profile']

SANITIZER = 'profile'

CORPUS_BACKUP_URL = ('/{0}-backup.clusterfuzz-external.appspot.com/corpus/'
                     'libFuzzer/{1}/latest.zip')
COVERAGE_BUCKET_FORMAT = '{0}-coverage.clusterfuzz-external.appspot.com'

GCS_URL_BASENAME = 'https://storage.googleapis.com/'


def usage():
  sys.stderr.write(
    "Usage: " + sys.argv[0] + " <project_dir>\n")
  exit(1)

def get_build_steps(project_dir):
  project_name = os.path.basename(project_dir)
  # temporary testing code
#  sys.exit(0)
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

  build_steps.extend([
      # compile
      {'name': image,
       'env': env,
       'args': [
         'bash',
         '-c',
         # Remove /out to make sure there are non instrumented binaries.
         # `cd /src && cd {workdir}` (where {workdir} is parsed from the
         # Dockerfile). Container Builder overrides our workdir so we need to add
         # this step to set it back.
         # Container Builder doesn't pass --rm to docker run yet.
         'rm -r /out && cd /src && cd {1} && mkdir -p {0} && compile'.format(out, workdir),
       ],
      },
  ])

  fuzz_targets = get_targets_list(project_name)
  print(fuzz_targets)
  for binary_name in fuzz_targets:
    qualified_name = binary_name
    if not binary_name.startswith(project_name):
      qualified_name = '%s_%s' % (project_name, binary_name)

    url = build_project.get_signed_url(
        CORPUS_BACKUP_URL.format(project_name, qualified_name), method='GET')
    archive_name = binary_name + '.zip'
    corpus_dir = os.path.join('/corpus', binary_name)

    build_steps.extend([
      {'name': 'gcr.io/cloud-builders/wget',
        'args': ['-O', corpus_dir + '.zip', url],
        'volumes': [{'name': 'corpus', 'path': '/corpus'}],
      },
    ])

  build_steps.extend([
      {'name': 'gcr.io/oss-fuzz-base/base-runner',
        'env': env + ['HTTP_PORT=', 'COVERAGE_EXTRA_ARGS='],
        'args': [
          'bash',
          '-c',
          'for f in /corpus/*.zip; do unzip -q $f -d ${f%%.*}; done && coverage',
        ],
        'volumes': [{'name': 'corpus', 'path': '/corpus'}],
      },
  ])

  build_steps.extend([
      # Upload the report.
      {'name': 'gcr.io/cloud-builders/gsutil',
        'args': [
          '-m', 'cp', '-r',
          os.path.join(out, 'report'),
          # TODO: use {0}-coverage.clusterfuzz-external.appspot.com bucket:
          # COVERAGE_BUCKET_FORMAT
          'gs://oss-fuzz-test-coverage/{0}/'.format(project_name) + report_date,
        ],
      },
      # Cleanup.
      {'name': image,
        'args': [
          'bash',
          '-c',
          'rm -r ' + out,
        ],
      },
  ])

  return build_steps, image


def get_corpus_backup(project_name):

  for fuzz_target in fuzz_targets:
    url = CORPUS_BACKUP_URL.format(project_name, fuzz_target)
    url = build_project.get_signed_url(url)
    r = requests.get(url) #, params={'delimiter': '/'})
    print(r.status_code)
    print(r.text)
    data = r.json()
    print(data)


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
