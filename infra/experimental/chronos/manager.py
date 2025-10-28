# Copyright 2025 Google LLC
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
"""Module for managing Chronos cached builds."""

import os
import sys
import logging
import argparse
import time
import json
import subprocess

import bad_patch
import logic_error_patch

logger = logging.getLogger(__name__)


def _get_project_cached_named(project, sanitizer='address'):
  """Gets the name of the cached project image."""
  return f'us-central1-docker.pkg.dev/oss-fuzz/oss-fuzz-gen/{project}-ofg-cached-{sanitizer}'


def _get_project_cached_named_local(project, sanitizer='address'):
  return f'{project}-origin-{sanitizer}'


def build_project_image(project):
  """Build OSS-Fuzz base image for a project."""

  cmd = ['docker', 'build', '-t', 'gcr.io/oss-fuzz/' + project, '.']
  try:
    subprocess.check_call(' '.join(cmd),
                          shell=True,
                          cwd=os.path.join('projects', project))
  except subprocess.CalledProcessError:
    pass


def build_cached_project(project, cleanup=True, sanitizer='address'):
  """Build cached image for a project."""
  container_name = _get_project_cached_named_local(project, sanitizer)
  logger.info('Building cached image for project: %s', project)
  # Clean up the container if it exists.
  if cleanup:
    try:
      subprocess.check_call(['docker', 'container', 'rm', '-f', container_name],
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError:
      pass

  project_language = 'c++'
  cwd = os.getcwd()
  # Build the cached image.
  cmd = [
      'docker', 'run', '--env=SANITIZER=' + sanitizer,
      '--env=CCACHE_DIR=/workspace/ccache',
      f'--env=FUZZING_LANGUAGE={project_language}',
      '--env=CAPTURE_REPLAY_SCRIPT=1', f'--name={container_name}',
      f'-v={cwd}/ccaches/{project}/ccache:/workspace/ccache',
      f'-v={cwd}/build/out/{project}/:/out/',
      '-v=' + os.path.join(os.getcwd(), 'infra', 'experimental', 'chronos') +
      ':/chronos/', f'gcr.io/oss-fuzz/{project}', 'bash', '-c',
      ('"export PATH=/ccache/bin:\$PATH && python3.11 -m pip install -r /chronos/requirements.txt && '
       'rm -rf /out/* && compile && cp -n /usr/local/bin/replay_build.sh \$SRC/"'
      )
  ]

  logger.info('Command: %s', ' '.join(cmd))

  start = time.time()
  try:
    subprocess.check_call(' '.join(cmd), shell=True)
    end = time.time()
    logger.info('%s vanilla build Succeeded: Duration: %.2f seconds', project,
                end - start)
  except subprocess.CalledProcessError:
    end = time.time()
    logger.info('%s vanilla build Failed: Duration: %.2f seconds', project,
                end - start)
    return False

  # Copy the coverage script into the container.
  # Ensure we're are the right cwd.
  coverage_host_script = os.path.join('infra', 'experimental', 'chronos',
                                      'coverage_test_collection.py')
  if not os.path.exists(coverage_host_script):
    logger.info('Coverage script does not exist at %s', coverage_host_script)
  else:
    # Copy the coverage script into the container.
    logger.info('Copying coverage script to container: %s', container_name)
    cmd = [
        'docker', 'container', 'cp', coverage_host_script,
        f'{container_name}:/usr/local/bin/coverage_test_collection.py'
    ]
    subprocess.check_call(' '.join(cmd),
                          shell=True,
                          stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL)

  # Save the container.
  cmd = [
      'docker', 'container', 'commit', '-c', '"ENV REPLAY_ENABLED=1"', '-c',
      '"ENV CAPTURE_REPLAY_SCRIPT=1"', container_name,
      _get_project_cached_named(project, sanitizer)
  ]
  logger.info('Saving image: [%s]', ' '.join(cmd))
  try:
    subprocess.check_call(' '.join(cmd),
                          shell=True,
                          stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL)

  except subprocess.CalledProcessError as e:
    logger.error('Failed to save cached image: %s', e)

    return False
  return True


def check_cached_replay(project, sanitizer='address', integrity_check=False):
  """Checks if a cache build succeeds and times is."""
  build_project_image(project)
  if not build_cached_project(project, sanitizer=sanitizer):
    logger.info('Failed to build cached image for project: %s', project)
    return

  start = time.time()
  base_cmd = 'export PATH=/ccache/bin:\\$PATH && rm -rf /out/* && compile'
  cmd = [
      'docker',
      'run',
      '--rm',
      '--network',
      'none',
      '--env=SANITIZER=' + sanitizer,
      '--env=FUZZING_LANGUAGE=c++',
      '-v=' + os.path.join(os.getcwd(), 'build', 'out', project) + ':/out',
      '-v=' + os.path.join(os.getcwd(), 'infra', 'experimental', 'chronos') +
      ':/chronos',
      '--name=' + project + '-origin-' + sanitizer + '-replay-recached',
      _get_project_cached_named(project, sanitizer),
      '/bin/bash',
      '-c',
  ]

  if integrity_check:
    # Use different bad patches to test the cached replay build
    failed = []
    for bad_patch_name, bad_patch_map in bad_patch.BAD_PATCH_GENERATOR.items():
      # Generate bad patch command using different approaches
      expected_rc = bad_patch_map['rc']
      bad_patch_command = (f'python3 /chronos/bad_patch.py {bad_patch_name}')
      cmd_to_run = cmd[:]
      cmd_to_run.append(
          f'"set -euo pipefail && {bad_patch_command} && {base_cmd}"')

      # Run the cached replay script with bad patches
      result = subprocess.run(' '.join(cmd_to_run), shell=True, check=False)

      if result.returncode not in expected_rc:
        failed.append(bad_patch_name)
        logger.info(('%s check cached replay failed on bad patches %s. '
                     'Return code: %d. Expected return code: %s'), project,
                    bad_patch_name, result.returncode, str(expected_rc))

    if failed:
      logger.info(
          '%s check cached replay failed to detect these bad patches: %s',
          project, ' '.join(failed))
    else:
      logger.info('%s check cached replay success to detect all bad patches.',
                  project)
  else:
    # Normal run with no integrity check
    cmd.append(f'"{base_cmd}"')
    replay_success = False
    try:
      subprocess.run(' '.join(cmd), shell=True, check=True)
      replay_success = True
    except subprocess.CalledProcessError as e:
      logger.error('Failed to run cached replay: %s', e)
      replay_success = False
    logger.info('%s check cached replay: %s.', project,
                'succeeded' if replay_success else 'failed')

  end = time.time()
  logger.info('%s check cached replay completion time: %.2f seconds', project,
              (end - start))


def check_test(project,
               sanitizer='address',
               run_full_cache_replay=False,
               integrity_check=False,
               stop_on_failure=False):
  """Run the `run_tests.sh` script for a specific project. Will
    build a cached container first."""

  script_path = os.path.join('projects', project, 'run_tests.sh')

  if not os.path.exists(script_path):
    logger.info('Error: The script for project "%s" does not exist at %s',
                project, script_path)
    sys.exit(1)

  logger.info('Building image for project for use in check-tests: %s', project)
  # Build an OSS-Fuzz image of the project
  if run_full_cache_replay:
    check_cached_replay(project, sanitizer)
  else:
    build_project_image(project)
    # build a cached version of the project
    if not build_cached_project(project, sanitizer=sanitizer):
      return False

  # Run the test script
  start = time.time()
  run_tests_cmd = 'chmod +x /src/run_tests.sh && /src/run_tests.sh'
  docker_cmd = [
      'docker',
      'run',
      '--rm',
      '-ti',
      '--network',
      'none',
      '-v=' + os.path.join(os.getcwd(), 'infra', 'experimental', 'chronos') +
      ':/chronos',
      _get_project_cached_named(project, sanitizer),
      '/bin/bash',
      '-c',
  ]
  if integrity_check:
    integrity_checks = []

    # Patch the code with some logic error and see if build_test able to detect
    # them.
    for logic_patch in logic_error_patch.LOGIC_ERROR_PATCHES:
      logger.info('Checking logic patch: %s', logic_patch.name)
      patch_command = (
          'python3 -m pip install -r /chronos/requirements.txt &&'
          f'python3 /chronos/logic_error_patch.py {logic_patch.name} && '
          'compile')
      cmd_to_run = docker_cmd[:]

      # In the below, we will apply a set of changes in the source code, rebuild
      # the target and then run the run_tests.sh script.
      # The patches are meant to check the semantics of the code, but they are
      # not bulletproof, which means they may break the build in exceptional
      # circumstances. So, we first try to compile the code after having applied
      # the patches, but without running the tests, and if this step fails, then
      # we skip running the tests for this patch as well.
      # Patch and build first.
      cmd_to_run.append(f'"set -euo pipefail && {patch_command}"')
      try:
        subprocess.check_call(' '.join(cmd_to_run), shell=True)
      except subprocess.CalledProcessError:
        logger.info('%s skipping logic patch %s that failed to compile.',
                    project, logic_patch.name)
        integrity_checks.append({
            'patch': logic_patch.name,
            'result': 'compile_fail'
        })
        continue

      # Patch and build succeeded, now proceed to patch, build and run tests in
      # one go. This will indicate if the patch was detected by the tests or
      # not.
      cmd_to_run[
          -1] = f'"set -euo pipefail && {patch_command} && {run_tests_cmd}"'
      try:
        subprocess.check_call(' '.join(cmd_to_run), shell=True)
        exception_thrown = False
      except subprocess.CalledProcessError:
        exception_thrown = True

      if ((exception_thrown and not logic_patch.expected_result) or
          (not exception_thrown and logic_patch.expected_result)):
        # The patch was detected by the tests as it should have been.
        integrity_checks.append({
            'patch': logic_patch.name,
            'result': 'Success'
        })
      else:
        if stop_on_failure:
          logger.info(
              '%s integrity check failed on patch %s, stopping as requested.',
              project, logic_patch.name)
          return False
        integrity_checks.append({'patch': logic_patch.name, 'result': 'Failed'})

    logger.info('%s integrity check results:', project)
    for check in integrity_checks:
      logger.info('%s integrity check patch %s result: %s', project,
                  check['patch'], check['result'])
    succeeded = any([chk['result'] == 'Success' for chk in integrity_checks])
  else:
    # Run normal build_test
    docker_cmd.append(f'"{run_tests_cmd}"')
    try:
      subprocess.check_call(' '.join(docker_cmd), shell=True)
      succeeded = True
    except subprocess.CalledProcessError:
      succeeded = False

  end = time.time()
  logger.info('%s test completion %s: Duration of run_tests.sh: %.2f seconds',
              project, 'failed' if not succeeded else 'succeeded',
              (end - start))

  return succeeded


def check_run_tests_script(project,
                           sanitizer='address',
                           ignore_new_files=False):
  """Checks if the run_tests.sh changes the source files in the current directory."""

  build_project_image(project)
  build_cached_project(project, sanitizer=sanitizer)

  ignore = ''
  if ignore_new_files:
    ignore = '--ignore-new-files'

  start = time.time()
  cmd = [
      'docker', 'run', '--rm',
      '-v=' + os.path.join(os.getcwd(), 'infra', 'experimental', 'chronos') +
      ':/chronos',
      '--name=' + project + '-origin-' + sanitizer + '-run-tests-check',
      _get_project_cached_named(project, sanitizer), '/bin/bash', '-c',
      f'"python3 -m pip install -r /chronos/requirements.txt && python3 /chronos/run_tests_check.py {ignore}"'
  ]
  # Normal run with no integrity check
  result = subprocess.run(' '.join(cmd), shell=True, check=False)

  end = time.time()
  logger.info('%s run_test.sh check completion time: %.2f seconds', project,
              (end - start))

  if not result.returncode:
    logger.info(
        '%s run_test.sh does not alter any files or directories content.',
        project)
  else:
    logger.info(
        'Error: %s run_test.sh does alter files or directories content.',
        project)


def extract_test_coverage(project):
  """Extract code coverage report from run_tests.sh script."""
  build_project_image(project)
  build_cached_project(project, sanitizer='coverage')

  os.makedirs(os.path.join('build', 'out', project), exist_ok=True)

  shared_folder = os.path.join(os.getcwd(), 'build', 'out', project)
  cmd = [
      'docker', 'run', '--rm', '--network', 'none', '-v',
      f'{shared_folder}:/out', '-ti',
      _get_project_cached_named(project, 'coverage'), '/bin/bash', '-c',
      ('"chmod +x /src/run_tests.sh && '
       'find /src/ -name "*.profraw" -exec rm -f {} \\; && '
       '/src/run_tests.sh && '
       'python3 /usr/local/bin/coverage_test_collection.py && '
       'chmod -R 755 /out/test-html-generation/"')
  ]
  try:
    subprocess.check_call(' '.join(cmd), shell=True)
  except subprocess.CalledProcessError as e:
    logger.error('Error occurred while running coverage collection: %s', e)
    return False

  # If the summary file is created, dump the total lines covered.
  if os.path.isfile(
      os.path.join('build', 'out', project, 'test-html-generation',
                   'summary.json')):
    summary_json = os.path.join('build', 'out', project, 'test-html-generation',
                                'summary.json')
    with open(summary_json, 'r', encoding='utf-8') as f:
      summary = json.load(f)
      total_lines_covered = summary['data'][0]['totals']['lines']
      logger.info('Total lines covered for %s: %s', project,
                  json.dumps(total_lines_covered))
  return True


def _cmd_dispatcher_check_test(args):
  check_test(args.project, args.sanitizer, args.run_full_cache_replay,
             args.integrity_check, args.stop_on_failure)


def _cmd_dispatcher_check_replay(args):
  check_cached_replay(args.project,
                      args.sanitizer,
                      integrity_check=args.integrity_check)


def _cmd_dispatcher_build_cached_image(args):
  build_cached_project(args.project, sanitizer=args.sanitizer)


def _cmd_dispatcher_extract_coverage(args):
  extract_test_coverage(args.project)


def _cmd_check_run_tests_script(args):
  check_run_tests_script(args.project,
                         sanitizer=args.sanitizer,
                         ignore_new_files=args.ignore_new_files)


def parse_args():
  """Parses command line arguments for the manager script."""
  parser = argparse.ArgumentParser(
      'manager.py',
      description='Chronos Manager: a tool for managing cached OSS-Fuzz builds.'
  )
  subparsers = parser.add_subparsers(dest='command')

  check_test_parser = subparsers.add_parser(
      'check-test', help='Checks run_test.sh for specific project.')
  check_test_parser.add_argument(
      'project',
      type=str,
      help='The name of the project to check (e.g., "libpng").',
  )
  check_test_parser.add_argument(
      '--stop-on-failure',
      action='store_true',
      help='If set, will stop integrity checks on first failure.')
  check_test_parser.add_argument(
      '--sanitizer',
      default='address',
      help='The sanitizer to use (default: address).')
  check_test_parser.add_argument(
      '--container-output',
      choices=['silent', 'file', 'stdout'],
      default='stdout',
      help='How to handle output from the container. ')
  check_test_parser.add_argument(
      '--run-full-cache-replay',
      action='store_true',
      help=
      'If set, will run the full cache replay instead of just checking the script.'
  )
  check_test_parser.add_argument(
      '--integrity-check',
      action='store_true',
      help=
      'If set, will patch and test with logic errors to ensure build integrity.'
  )

  check_replay_parser = subparsers.add_parser(
      'check-replay',
      help='Checks if the replay script works for a specific project.')

  check_replay_parser.add_argument('project',
                                   help='The name of the project to check.')
  check_replay_parser.add_argument(
      '--sanitizer',
      default='address',
      help='The sanitizer to use for the cached build (default: address).')
  check_replay_parser.add_argument(
      '--integrity-check',
      action='store_true',
      help='If set, will test the integrity of the replay script.')

  check_run_tests_script_parser = subparsers.add_parser(
      'check-run-tests-script',
      help=
      'Checks if the run_tests.sh alter files in the current WORKDIR after execution'
  )

  check_run_tests_script_parser.add_argument(
      'project', help='The name of the project to check.')
  check_run_tests_script_parser.add_argument('--ignore-new-files',
                                             action='store_true')
  check_run_tests_script_parser.add_argument(
      '--sanitizer',
      default='address',
      help='The sanitizer to use for the cached build (default: address).')

  build_cached_image_parser = subparsers.add_parser(
      'build-cached-image',
      help='Builds a cached image for a specific project.')
  build_cached_image_parser.add_argument(
      'project', help='The name of the project to build.')
  build_cached_image_parser.add_argument(
      '--sanitizer',
      default='address',
      help='The sanitizer to use for the cached build (default: address).')
  build_cached_image_parser.add_argument(
      '--container-output',
      choices=['silent', 'file', 'stdout'],
      default='stdout',
      help='How to handle output from the container. ')

  extract_coverage_parser = subparsers.add_parser(
      'extract-test-coverage',
      help='Extract code coverage reports from run_tests.sh script')
  extract_coverage_parser.add_argument(
      'project', help='The name of the project to extract coverage for.')

  return parser.parse_args()


def main():
  """Main"""
  logging.basicConfig(level=logging.INFO)

  args = parse_args()

  dispatch_map = {
      'check-test': _cmd_dispatcher_check_test,
      'check-replay': _cmd_dispatcher_check_replay,
      'build-cached-image': _cmd_dispatcher_build_cached_image,
      'extract-test-coverage': _cmd_dispatcher_extract_coverage,
      'check-run-tests-script': _cmd_check_run_tests_script
  }

  dispatch_cmd = dispatch_map.get(args.command, None)
  if not dispatch_cmd:
    logger.error('Unknown command: %s', args.command)
    sys.exit(1)
  logger.info('Dispatching command: %s', args.command)
  dispatch_cmd(args)


if __name__ == '__main__':
  main()
