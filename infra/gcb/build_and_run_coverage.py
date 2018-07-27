#!/usr/bin/python2

"""Starts and runs coverage build on Google Cloud Builder.

Usage: build_and_run_coverage.py <project_dir>
"""

import datetime
import os
import sys
import requests

import build_project

BUILD_TIMEOUT = 10 * 60 * 60

CONFIGURATION = ['FUZZING_ENGINE=libfuzzer', 'SANITIZER=profile']

SANITIZER = 'profile'

CORPUS_BACKUP_URL = ('/{0}-backup.clusterfuzz-external.appspot.com/corpus/'
                     'libFuzzer/{1]/latest.zip')

def usage():
  sys.stderr.write(
    "Usage: " + sys.argv[0] + " <project_dir>\n")
  exit(1)

def get_build_steps(project_dir):
  project_name = os.path.basename(project_dir)
#  temporary testing code
#  get_corpus_backup(project_name)
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


  build_steps.extend([
      # Download and unzip corpus backup for every target.
      # {
      #   # TODO.
      # },
      # test binaries
      {'name': 'gcr.io/oss-fuzz-base/base-runner',
        'env': env + ['HTTP_PORT=', 'COVERAGE_EXTRA_ARGS='],
        'args': [
          'bash',
          '-c',
          'coverage'
        ],
      },
  ])

  build_steps.extend([
      # Upload the report.
      {'name': 'gcr.io/cloud-builders/gsutil',
        'args': [
          '-m', 'cp', '-r',
          os.path.join(out, 'report'),
          # TODO: use {0}-coverage.clusterfuzz-external.appspot.com bucket:
          # 'gs://{0}-coverage.clusterfuzz-external.appspot.com/reports/'.
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
      ENGINE_INFO['libfuzzer'].upload_bucket, project_name, 'address')
  r = requests.get(url)
  if not r.status_code == 200:
    sys.stderr.write('Failed to get list of targets from "%s".\n' % url)
    return None
    


def main():
  if len(sys.argv) != 2:
    usage()

  project_dir = sys.argv[1].rstrip(os.path.sep)
  steps, image = get_build_steps(project_dir)
  build_project.run_build(steps, image)


if __name__ == "__main__":
  main()
