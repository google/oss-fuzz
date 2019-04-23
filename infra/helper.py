#!/usr/bin/env python
# Copyright 2016 Google Inc.
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

from __future__ import print_function
from multiprocessing.dummy import Pool as ThreadPool
import argparse
import datetime
import errno
import multiprocessing
import os
import pipes
import re
import subprocess
import sys
import tempfile
import templates

OSSFUZZ_DIR = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
BUILD_DIR = os.path.join(OSSFUZZ_DIR, 'build')

BASE_IMAGES = [
    'gcr.io/oss-fuzz-base/base-image',
    'gcr.io/oss-fuzz-base/base-clang',
    'gcr.io/oss-fuzz-base/base-builder',
    'gcr.io/oss-fuzz-base/base-runner',
    'gcr.io/oss-fuzz-base/base-runner-debug',
    'gcr.io/oss-fuzz-base/base-msan-builder',
    'gcr.io/oss-fuzz-base/msan-builder',
]

VALID_PROJECT_NAME_REGEX = re.compile(r'^[a-zA-Z0-9_-]+$')
MAX_PROJECT_NAME_LENGTH = 26

if sys.version_info[0] >= 3:
    raw_input = input

CORPUS_URL_FORMAT = (
    'gs://{project_name}-corpus.clusterfuzz-external.appspot.com/libFuzzer/'
    '{fuzz_target}/')
CORPUS_BACKUP_URL_FORMAT = (
    'gs://{project_name}-backup.clusterfuzz-external.appspot.com/corpus/'
    'libFuzzer/{fuzz_target}/')


def main():
  os.chdir(OSSFUZZ_DIR)
  if not os.path.exists(BUILD_DIR):
    os.mkdir(BUILD_DIR)

  parser = argparse.ArgumentParser('helper.py', description='oss-fuzz helpers')
  subparsers = parser.add_subparsers(dest='command')

  generate_parser = subparsers.add_parser(
      'generate', help='Generate files for new project.')
  generate_parser.add_argument('project_name')

  build_image_parser = subparsers.add_parser(
      'build_image', help='Build an image.')
  build_image_parser.add_argument('project_name')
  build_image_parser.add_argument('--pull', action='store_true',
                                  help='Pull latest base image.')
  build_image_parser.add_argument('--no-pull', action='store_true',
                                  help='Do not pull latest base image.')

  build_fuzzers_parser = subparsers.add_parser(
      'build_fuzzers', help='Build fuzzers for a project.')
  _add_engine_args(build_fuzzers_parser)
  _add_sanitizer_args(build_fuzzers_parser)
  _add_environment_args(build_fuzzers_parser)
  build_fuzzers_parser.add_argument('project_name')
  build_fuzzers_parser.add_argument('source_path', help='path of local source',
                                    nargs='?')
  build_fuzzers_parser.add_argument('--clean', dest='clean',
                                    action='store_true',
                                    help='clean existing artifacts.')
  build_fuzzers_parser.add_argument('--no-clean', dest='clean',
                                    action='store_false',
                                    help='do not clean existing artifacts '
                                    '(default).')
  build_fuzzers_parser.set_defaults(clean=False)

  check_build_parser = subparsers.add_parser(
      'check_build', help='Checks that fuzzers execute without errors.')
  _add_engine_args(check_build_parser, choices=['libfuzzer', 'afl'])
  _add_sanitizer_args(
      check_build_parser, choices=['address', 'memory', 'undefined'])
  _add_environment_args(check_build_parser)
  check_build_parser.add_argument('project_name', help='name of the project')
  check_build_parser.add_argument(
      'fuzzer_name', help='name of the fuzzer', nargs='?')

  run_fuzzer_parser = subparsers.add_parser(
      'run_fuzzer', help='Run a fuzzer in the emulated fuzzing environment.')
  _add_engine_args(run_fuzzer_parser)
  _add_sanitizer_args(run_fuzzer_parser)
  _add_environment_args(run_fuzzer_parser)
  run_fuzzer_parser.add_argument('project_name', help='name of the project')
  run_fuzzer_parser.add_argument('fuzzer_name', help='name of the fuzzer')
  run_fuzzer_parser.add_argument('fuzzer_args', help='arguments to pass to the fuzzer',
                                 nargs=argparse.REMAINDER)

  coverage_parser = subparsers.add_parser(
      'coverage', help='Generate code coverage report for the project.')
  coverage_parser.add_argument('--no-corpus-download', action='store_true',
                               help='do not download corpus backup from '
                               'OSS-Fuzz; use corpus located in '
                               'build/corpus/<project>/<fuzz_target>/')
  coverage_parser.add_argument('--port', default='8008', help='specify port for'
                               ' a local HTTP server rendering coverage report')
  coverage_parser.add_argument('--fuzz-target', help='specify name of a fuzz '
                               'target to be run for generating coverage '
                               'report')
  coverage_parser.add_argument('--corpus-dir', help='specify location of corpus'
                               ' to be used (requires --fuzz-target argument)')
  coverage_parser.add_argument('project_name', help='name of the project')
  coverage_parser.add_argument('extra_args', help='additional arguments to '
                               'pass to llvm-cov utility.', nargs='*')

  download_corpora_parser = subparsers.add_parser(
      'download_corpora', help='Download all corpora for a project.')
  download_corpora_parser.add_argument('--fuzz-target', help='specify name of a fuzz target')
  download_corpora_parser.add_argument('project_name', help='name of the project')

  reproduce_parser = subparsers.add_parser(
      'reproduce', help='Reproduce a crash.')
  reproduce_parser.add_argument('--valgrind', action='store_true',
                                help='run with valgrind')
  reproduce_parser.add_argument('project_name', help='name of the project')
  reproduce_parser.add_argument('fuzzer_name', help='name of the fuzzer')
  reproduce_parser.add_argument('testcase_path', help='path of local testcase')
  reproduce_parser.add_argument('fuzzer_args', help='arguments to pass to the fuzzer',
                                nargs=argparse.REMAINDER)
  _add_environment_args(reproduce_parser)

  shell_parser = subparsers.add_parser(
      'shell', help='Run /bin/bash within the builder container.')
  shell_parser.add_argument('project_name', help='name of the project')
  _add_engine_args(shell_parser)
  _add_sanitizer_args(shell_parser)
  _add_environment_args(shell_parser)

  pull_images_parser = subparsers.add_parser('pull_images',
                                             help='Pull base images.')

  args = parser.parse_args()
  if args.command == 'generate':
    return generate(args)
  elif args.command == 'build_image':
    return build_image(args)
  elif args.command == 'build_fuzzers':
    return build_fuzzers(args)
  elif args.command == 'check_build':
    return check_build(args)
  elif args.command == 'download_corpora':
    return download_corpora(args)
  elif args.command == 'run_fuzzer':
    return run_fuzzer(args)
  elif args.command == 'coverage':
    return coverage(args)
  elif args.command == 'reproduce':
    return reproduce(args)
  elif args.command == 'shell':
    return shell(args)
  elif args.command == 'pull_images':
    return pull_images(args)

  return 0


def _is_base_image(image_name):
  """Checks if the image name is a base image."""
  return os.path.exists(os.path.join('infra', 'base-images', image_name))


def _check_project_exists(project_name):
  """Checks if a project exists."""
  if not os.path.exists(_get_project_dir(project_name)):
    print(project_name, 'does not exist', file=sys.stderr)
    return False

  return True


def _check_fuzzer_exists(project_name, fuzzer_name):
  """Checks if a fuzzer exists."""
  command = ['docker', 'run', '--rm']
  command.extend(['-v', '%s:/out' % _get_output_dir(project_name)])
  command.append('ubuntu:16.04')

  command.extend(['/bin/bash', '-c', 'test -f /out/%s' % fuzzer_name])

  try:
    subprocess.check_call(command)
  except subprocess.CalledProcessError:
    print(fuzzer_name,
          'does not seem to exist. Please run build_fuzzers first.',
          file=sys.stderr)
    return False

  return True


def _get_absolute_path(path):
  """Returns absolute path with user expansion."""
  return os.path.abspath(os.path.expanduser(path))


def _get_command_string(command):
  """Returns a shell escaped command string."""
  return ' '.join(pipes.quote(part) for part in command)


def _get_project_dir(project_name):
  """Returns path to the project."""
  return os.path.join(OSSFUZZ_DIR, 'projects', project_name)


def _get_dockerfile_path(project_name):
  """Returns path to the project Dockerfile."""
  return os.path.join(_get_project_dir(project_name), 'Dockerfile')


def _get_corpus_dir(project_name=''):
  """Returns path to /corpus directory for the given project (if specified)."""
  return os.path.join(BUILD_DIR, 'corpus', project_name)


def _get_output_dir(project_name=''):
  """Returns path to /out directory for the given project (if specified)."""
  return os.path.join(BUILD_DIR, 'out', project_name)


def _get_work_dir(project_name=''):
  """Returns path to /work directory for the given project (if specified)."""
  return os.path.join(BUILD_DIR, 'work', project_name)


def _add_architecture_args(parser, choices=('i386', 'x86_64')):
  """Add common architecture args."""
  parser.add_argument('--architecture', default='x86_64', choices=choices)


def _add_engine_args(
        parser,
        choices=('libfuzzer', 'afl', 'honggfuzz', 'dataflow', 'none')):
  """Add common engine args."""
  parser.add_argument('--engine', default='libfuzzer', choices=choices)


def _add_sanitizer_args(
        parser,
        choices=('address', 'memory', 'undefined', 'coverage', 'dataflow')):
  """Add common sanitizer args."""
  parser.add_argument('--sanitizer', default='address', choices=choices)


def _add_environment_args(parser):
  """Add common environment args."""
  parser.add_argument('-e', action='append',
                      help="set environment variable e.g. VAR=value")


def _build_image(image_name, no_cache=False, pull=False):
  """Build image."""

  is_base_image = _is_base_image(image_name)
  if is_base_image:
    image_project = 'oss-fuzz-base'
    dockerfile_dir = os.path.join('infra', 'base-images', image_name)
  else:
    image_project = 'oss-fuzz'
    if not _check_project_exists(image_name):
      return False

    dockerfile_dir = os.path.join('projects', image_name)

  build_args = []
  if no_cache:
    build_args.append('--no-cache')

  build_args += ['-t', 'gcr.io/%s/%s' % (image_project, image_name), dockerfile_dir]

  return docker_build(build_args, pull=pull)


def _env_to_docker_args(env_list):
  """Turn envirnoment variable list into docker arguments."""
  return sum([['-e', v] for v in env_list], [])


def _workdir_from_dockerfile(project_name):
  """Parse WORKDIR from the Dockerfile for the given project."""
  WORKDIR_REGEX = re.compile(r'\s*WORKDIR\s*([^\s]+)')
  dockerfile_path = _get_dockerfile_path(project_name)

  with open(dockerfile_path) as f:
    lines = f.readlines()

  for line in reversed(lines):  # reversed to get last WORKDIR.
    match = re.match(WORKDIR_REGEX, line)
    if match:
      workdir = match.group(1)
      workdir = workdir.replace('$SRC', '/src')

      if not os.path.isabs(workdir):
        workdir = os.path.join('/src', workdir)

      return os.path.normpath(workdir)

  return os.path.join('/src', project_name)


def docker_run(run_args, print_output=True):
  """Call `docker run`."""
  command = ['docker', 'run', '--rm', '-i', '--privileged']
  command.extend(run_args)

  print('Running:', _get_command_string(command))
  stdout = None
  if not print_output:
    stdout = open(os.devnull, 'w')

  try:
    subprocess.check_call(command, stdout=stdout, stderr=subprocess.STDOUT)
  except subprocess.CalledProcessError as e:
    return e.returncode

  return 0


def docker_build(build_args, pull=False):
  """Call `docker build`."""
  command = ['docker', 'build']
  if pull:
    command.append('--pull')

  command.extend(build_args)
  print('Running:', _get_command_string(command))

  try:
    subprocess.check_call(command)
  except subprocess.CalledProcessError:
    print('docker build failed.', file=sys.stderr)
    return False

  return True


def docker_pull(image, pull=False):
  """Call `docker pull`."""
  command = ['docker', 'pull', image]
  print('Running:', _get_command_string(command))

  try:
    subprocess.check_call(command)
  except subprocess.CalledProcessError:
    print('docker pull failed.', file=sys.stderr)
    return False

  return True


def build_image(args):
  """Build docker image."""
  if args.pull and args.no_pull:
    print('Incompatible arguments --pull and --no-pull.')
    return 1

  if args.pull:
    pull = True
  elif args.no_pull:
    pull = False
  else:
    y_or_n = raw_input('Pull latest base images (compiler/runtime)? (y/N): ')
    pull = y_or_n.lower() == 'y'

  if pull:
    print('Pulling latest base images...')
  else:
    print('Using cached base images...')

  # If build_image is called explicitly, don't use cache.
  if _build_image(args.project_name, no_cache=True, pull=pull):
    return 0

  return 1


def build_fuzzers(args):
  """Build fuzzers."""
  project_name = args.project_name
  if not _build_image(args.project_name):
    return 1

  project_out_dir = _get_output_dir(project_name)
  if args.clean:
    print('Cleaning existing build artifacts.')

    # Clean old and possibly conflicting artifacts in project's out directory.
    docker_run([
        '-v', '%s:/out' % project_out_dir,
        '-t', 'gcr.io/oss-fuzz/%s' % project_name,
        '/bin/bash', '-c', 'rm -rf /out/*'
    ])
  else:
    print('Keeping existing build artifacts as-is (if any).')

  env = [
      'FUZZING_ENGINE=' + args.engine,
      'SANITIZER=' + args.sanitizer,
      'ARCHITECTURE=' + args.architecture
  ]
  if args.e:
    env += args.e

  project_work_dir = _get_work_dir(project_name)

  # Copy instrumented libraries.
  if args.sanitizer == 'memory':
    docker_run([
        '-v', '%s:/work' % project_work_dir,
        'gcr.io/oss-fuzz-base/msan-builder',
        'bash', '-c', 'cp -r /msan /work'])
    env.append('MSAN_LIBS_PATH=' + '/work/msan')

  command = (
      ['docker', 'run', '--rm', '-i', '--cap-add', 'SYS_PTRACE'] +
      _env_to_docker_args(env))
  if args.source_path:
    workdir = _workdir_from_dockerfile(args.project_name)
    if workdir == '/src':
      print('Cannot use local checkout with "WORKDIR /src".', file=sys.stderr)
      return 1

    command += [
        '-v',
        '%s:%s' % (_get_absolute_path(args.source_path), workdir),
    ]
  command += [
      '-v', '%s:/out' % project_out_dir,
      '-v', '%s:/work' % project_work_dir,
      '-t', 'gcr.io/oss-fuzz/%s' % project_name
  ]

  print('Running:', _get_command_string(command))

  try:
    subprocess.check_call(command)
  except subprocess.CalledProcessError:
    print('Fuzzers build failed.', file=sys.stderr)
    return 1

  # Patch MSan builds to use instrumented shared libraries.
  if args.sanitizer == 'memory':
    docker_run([
        '-v', '%s:/out' % project_out_dir,
        '-v', '%s:/work' % project_work_dir
    ] + _env_to_docker_args(env) + [
        'gcr.io/oss-fuzz-base/base-msan-builder',
        'patch_build.py', '/out'
    ])

  return 0


def check_build(args):
  """Checks that fuzzers in the container execute without errors."""
  if not _check_project_exists(args.project_name):
    return 1

  if (args.fuzzer_name and
      not _check_fuzzer_exists(args.project_name, args.fuzzer_name)):
    return 1

  env = [
      'FUZZING_ENGINE=' + args.engine,
      'SANITIZER=' + args.sanitizer
  ]
  if args.e:
    env += args.e

  run_args = _env_to_docker_args(env) + [
      '-v', '%s:/out' % _get_output_dir(args.project_name),
      '-t', 'gcr.io/oss-fuzz-base/base-runner'
  ]

  if args.fuzzer_name:
    run_args += [
        'bad_build_check',
        os.path.join('/out', args.fuzzer_name)
    ]
  else:
    run_args.append('test_all')

  exit_code = docker_run(run_args)
  if exit_code == 0:
    print('Check build passed.')
  else:
    print('Check build failed.')

  return exit_code


def _get_fuzz_targets(project_name):
  """Return names of fuzz targest build in the project's /out directory."""
  fuzz_targets = []
  for name in os.listdir(_get_output_dir(project_name)):
    path = os.path.join(_get_output_dir(project_name), name)
    if os.path.isfile(path) and os.access(path, os.X_OK):
      fuzz_targets.append(name)

  return fuzz_targets


def _get_latest_corpus(project_name, fuzz_target, base_corpus_dir):
  """Download the latest corpus for the given fuzz target."""
  corpus_dir = os.path.join(base_corpus_dir, fuzz_target)
  if not os.path.exists(corpus_dir):
    os.makedirs(corpus_dir)

  if not fuzz_target.startswith(project_name):
    fuzz_target = '%s_%s' % (project_name, fuzz_target)

  corpus_backup_url = CORPUS_BACKUP_URL_FORMAT.format(project_name=project_name,
                                                      fuzz_target=fuzz_target)
  command = [
      'gsutil',
      'ls',
      corpus_backup_url
  ]

  corpus_listing = subprocess.Popen(
      command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
  output, error = corpus_listing.communicate()

  # Some fuzz targets (e.g. new ones) may not have corpus yet, just skip those.
  if corpus_listing.returncode:
    print('WARNING: corpus for {0} not found:\n{1}'.format(fuzz_target, error),
          file=sys.stderr)
    return

  if output:
    latest_backup_url = output.splitlines()[-1]
    archive_path = corpus_dir + '.zip'
    command = [
        'gsutil',
        '-q',
        'cp',
        latest_backup_url,
        archive_path
    ]
    subprocess.check_call(command)

    command = [
        'unzip',
        '-q',
        '-o',
        archive_path,
        '-d',
        corpus_dir
    ]
    subprocess.check_call(command)
    os.remove(archive_path)
  else:
    # Sync the working corpus copy if a minimized backup is not available.
    corpus_url = CORPUS_URL_FORMAT.format(project_name=project_name,
                                          fuzz_target=fuzz_target)
    command = [
        'gsutil',
        '-m',
        '-q',
        'rsync',
        '-R',
        corpus_url,
        corpus_dir
    ]
    subprocess.check_call(command)


def download_corpora(args):
  """Download most recent corpora from GCS for the given project."""
  if not _check_project_exists(args.project_name):
    return 1

  try:
    with open(os.devnull, 'w') as stdout:
      subprocess.check_call(['gsutil', '--version'], stdout=stdout)
  except OSError:
    print('ERROR: gsutil not found. Please install it from '
          'https://cloud.google.com/storage/docs/gsutil_install',
          file=sys.stderr)
    return False

  if args.fuzz_target:
    fuzz_targets = [args.fuzz_target]
  else:
    fuzz_targets = _get_fuzz_targets(args.project_name)

  corpus_dir = _get_corpus_dir(args.project_name)
  if not os.path.exists(corpus_dir):
    os.makedirs(corpus_dir)

  def _download_for_single_target(fuzz_target):
    try:
      _get_latest_corpus(args.project_name, fuzz_target, corpus_dir)
      return True
    except Exception as e:
      print('ERROR: corpus download for %s failed: %s' % (fuzz_target, str(e)),
            file=sys.stderr)
      return False

  print('Downloading corpora for %s project to %s' % (args.project_name, corpus_dir))
  thread_pool = ThreadPool(multiprocessing.cpu_count())
  return all(thread_pool.map(_download_for_single_target, fuzz_targets))


def coverage(args):
  """Generate code coverage using clang source based code coverage."""
  if args.corpus_dir and not args.fuzz_target:
    print('ERROR: --corpus-dir requires specifying a particular fuzz target '
          'using --fuzz-target',
          file=sys.stderr)
    return 1

  if not _check_project_exists(args.project_name):
    return 1

  if not args.no_corpus_download and not args.corpus_dir:
    if not download_corpora(args):
      return 1

  env = [
      'FUZZING_ENGINE=libfuzzer',
      'PROJECT=%s' % args.project_name,
      'SANITIZER=coverage',
      'HTTP_PORT=%s' % args.port,
      'COVERAGE_EXTRA_ARGS=%s' % ' '.join(args.extra_args),
  ]

  run_args = _env_to_docker_args(env)

  if args.corpus_dir:
    if not os.path.exists(args.corpus_dir):
      print('ERROR: the path provided in --corpus-dir argument does not exist',
          file=sys.stderr)
      return 1
    corpus_dir = os.path.realpath(args.corpus_dir)
    run_args.extend(['-v', '%s:/corpus/%s' % (corpus_dir,  args.fuzz_target)])
  else:
    run_args.extend(['-v', '%s:/corpus' % _get_corpus_dir(args.project_name)])

  run_args.extend([
      '-v', '%s:/out' % _get_output_dir(args.project_name),
      '-p', '%s:%s' % (args.port, args.port),
      '-t', 'gcr.io/oss-fuzz-base/base-runner',
  ])

  run_args.append('coverage')
  if args.fuzz_target:
    run_args.append(args.fuzz_target)

  exit_code = docker_run(run_args)
  if exit_code == 0:
    print('Successfully generated clang code coverage report.')
  else:
    print('Failed to generate clang code coverage report.')

  return exit_code


def run_fuzzer(args):
  """Runs a fuzzer in the container."""
  if not _check_project_exists(args.project_name):
    return 1

  if not _check_fuzzer_exists(args.project_name, args.fuzzer_name):
    return 1

  env = [
      'FUZZING_ENGINE=' + args.engine,
      'SANITIZER=' + args.sanitizer,
      'RUN_FUZZER_MODE=interactive',
  ]

  if args.e:
    env += args.e

  run_args = _env_to_docker_args(env) + [
      '-v', '%s:/out' % _get_output_dir(args.project_name),
      '-t', 'gcr.io/oss-fuzz-base/base-runner',
      'run_fuzzer',
      args.fuzzer_name,
  ] + args.fuzzer_args

  return docker_run(run_args)


def reproduce(args):
  """Reproduces a testcase in the container."""
  if not _check_project_exists(args.project_name):
    return 1

  if not _check_fuzzer_exists(args.project_name, args.fuzzer_name):
    return 1

  debugger = ''
  env = []
  image_name = 'base-runner'

  if args.valgrind:
    debugger = 'valgrind --tool=memcheck --track-origins=yes --leak-check=full'

  if debugger:
    image_name = 'base-runner-debug'
    env += ['DEBUGGER=' + debugger]

  if args.e:
    env += args.e

  run_args = _env_to_docker_args(env) + [
      '-v', '%s:/out' % _get_output_dir(args.project_name),
      '-v', '%s:/testcase' % _get_absolute_path(args.testcase_path),
      '-t', 'gcr.io/oss-fuzz-base/%s' % image_name,
      'reproduce',
      args.fuzzer_name,
      '-runs=100',
  ] + args.fuzzer_args

  return docker_run(run_args)


def generate(args):
  """Generate empty project files."""
  if len(args.project_name) > MAX_PROJECT_NAME_LENGTH:
    print('Project name needs to be less than or equal to %d characters.' %
          MAX_PROJECT_NAME_LENGTH, file=sys.stderr)
    return 1

  if not VALID_PROJECT_NAME_REGEX.match(args.project_name):
    print('Invalid project name.', file=sys.stderr)
    return 1

  dir = os.path.join('projects', args.project_name)

  try:
    os.mkdir(dir)
  except OSError as e:
    if e.errno != errno.EEXIST:
      raise
    print(dir, 'already exists.', file=sys.stderr)
    return 1

  print('Writing new files to', dir)

  template_args = {
    'project_name': args.project_name,
    'year': datetime.datetime.now().year
  }
  with open(os.path.join(dir, 'project.yaml'), 'w') as f:
    f.write(templates.PROJECT_YAML_TEMPLATE % template_args)

  with open(os.path.join(dir, 'Dockerfile'), 'w') as f:
    f.write(templates.DOCKER_TEMPLATE % template_args)

  build_sh_path = os.path.join(dir, 'build.sh')
  with open(build_sh_path, 'w') as f:
    f.write(templates.BUILD_TEMPLATE % template_args)

  os.chmod(build_sh_path, 0o755)
  return 0


def shell(args):
  """Runs a shell within a docker image."""
  if not _build_image(args.project_name):
    return 1

  env = [
      'FUZZING_ENGINE=' + args.engine,
      'SANITIZER=' + args.sanitizer
  ]

  if args.e:
    env += args.e

  if _is_base_image(args.project_name):
    image_project = 'oss-fuzz-base'
    out_dir = _get_output_dir()
  else:
    image_project = 'oss-fuzz'
    out_dir = _get_output_dir(args.project_name)

  run_args = _env_to_docker_args(env) + [
      '-v', '%s:/out' % out_dir,
      '-v', '%s:/work' % _get_work_dir(args.project_name),
      '-t', 'gcr.io/%s/%s' % (image_project, args.project_name),
      '/bin/bash'
  ]

  docker_run(run_args)
  return 0


def pull_images(args):
  """Pull base images."""
  for base_image in BASE_IMAGES:
    if not docker_pull(base_image):
      return 1

  return 0


if __name__ == '__main__':
  sys.exit(main())
