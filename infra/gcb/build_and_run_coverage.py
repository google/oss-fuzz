#!/usr/bin/python2

"""Starts and runs coverage build on Google Cloud Builder.

Usage: build_and_run_coverage.py <project_dir>
"""

import datetime
import os
import sys

import build_projects

BUILD_TIMEOUT = 10 * 60 * 60

CONFIGURATION = ['FUZZING_ENGINE=libfuzzer', 'SANITIZER=profile']

SANITIZER = 'coverage'

def usage():
  sys.stderr.write(
    "Usage: " + sys.argv[0] + " <project_dir>\n")
  exit(1)

def get_build_steps(project_dir):
  project_name = os.path.basename(project_dir)
  project_yaml = build_projects.load_project_yaml(project_dir)
  dockerfile_path = os.path.join(project_dir, 'Dockerfile')
  name = project_yaml['name']
  image = project_yaml['image']

  ts = datetime.datetime.now().strftime('%Y%m%d%H%M')

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
  stamped_name = name + '-' + SANITIZER + '-' + ts
  zip_file = stamped_name + '.zip'
  bucket = '%s-coverage.clusterfuzz-external.appspot.com' % project_name
  upload_url = build_projects.get_signed_url('/{0}/{1}/{2}'.format(
      bucket, name, zip_file))

  env.append('OUT=' + out)

  workdir = build_projects.workdir_from_dockerfile(dockerfile_path)
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
      # Download and unzip corpus backup for every target.
      {
        # TODO.
      }
      # test binaries
      {'name': 'gcr.io/oss-fuzz-base/base-runner',
        'env': env + ['HTTP_PORT=0'],
        'args': [
          'bash',
          '-c',
          'coverage'
        ],
      },
  ])

  build_steps.extend([
      # Archive code coverage report.
      {'name': image,
        'args': [
          'bash',
          '-c',
          'cd {0} && zip -rq {1} report'.format(out, zip_file)
        ],
      },
      # Upload the archive.
      {'name': 'gcr.io/oss-fuzz-base/uploader',
       'args': [
           os.path.join(out, zip_file),
           upload_url,
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

  return build_steps


def main():
  if len(sys.argv) != 2:
    usage()

  project_dir = sys.argv[1]
  build_projects.build(get_build_steps(project_dir))


if __name__ == "__main__":
  main()
