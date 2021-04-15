# Copyright 2020 Google LLC
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
"""A module to handle running a fuzz target for a specified amount of time."""
import collections
import logging
import os
import re
import shutil
import stat
import sys

import docker

# pylint: disable=wrong-import-position,import-error
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import utils

logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.DEBUG)

# Use a fixed seed for determinism. Use len_control=0 since we don't have enough
# time fuzzing for len_control to make sense (probably).
LIBFUZZER_OPTIONS = '-seed=1337 -len_control=0'

# The number of reproduce attempts for a crash.
REPRODUCE_ATTEMPTS = 10

# Seconds on top of duration until a timeout error is raised.
BUFFER_TIME = 10

# Log message if we can't check if crash reproduces on an recent build.
COULD_NOT_TEST_ON_RECENT_MESSAGE = (
    'Crash is reproducible. Could not run recent build of '
    'target to determine if this code change (pr/commit) introduced crash. '
    'Assuming this code change introduced crash.')

FuzzResult = collections.namedtuple('FuzzResult', ['testcase', 'stacktrace'])


class ReproduceError(Exception):
  """Error for when we can't attempt to reproduce a crash."""


class FuzzTarget:
  """A class to manage a single fuzz target.

  Attributes:
    target_name: The name of the fuzz target.
    duration: The length of time in seconds that the target should run.
    target_path: The location of the fuzz target binary.
    out_dir: The location of where output artifacts are stored.
  """

  # pylint: disable=too-many-arguments
  def __init__(self, target_path, duration, out_dir, clusterfuzz_deployment,
               config):
    """Represents a single fuzz target.

    Args:
      target_path: The location of the fuzz target binary.
      duration: The length of time  in seconds the target should run.
      out_dir: The location of where the output from crashes should be stored.
      clusterfuzz_deployment: The object representing the ClusterFuzz
          deployment.
      config: The config of this project.
    """
    self.target_path = target_path
    self.target_name = os.path.basename(self.target_path)
    self.duration = int(duration)
    self.out_dir = out_dir
    self.clusterfuzz_deployment = clusterfuzz_deployment
    self.config = config
    self.latest_corpus_path = None

  def fuzz(self):
    """Starts the fuzz target run for the length of time specified by duration.

    Returns:
      FuzzResult namedtuple with stacktrace and testcase if applicable.
    """
    logging.info('Fuzzer %s, started.', self.target_name)
    docker_container = utils.get_container_name()
    command_arguments = []
    if docker_container:
      command_arguments += [
          '--volumes-from', docker_container, '-e', 'OUT=' + self.out_dir
      ]
    else:
      command_arguments += ['-v', '%s:%s' % (self.out_dir, '/out')]

    command_arguments += [
        '-e', 'FUZZING_ENGINE=libfuzzer', '-e',
        'SANITIZER=' + self.config.sanitizer, '-e', 'CIFUZZ=True', '-e',
        'RUN_FUZZER_MODE=interactive', docker.BASE_RUNNER_TAG, 'bash', '-c'
    ]

    run_fuzzer_command = 'run_fuzzer {fuzz_target} {options}'.format(
        fuzz_target=self.target_name,
        options=LIBFUZZER_OPTIONS + ' -max_total_time=' + str(self.duration))

    # If corpus can be downloaded use it for fuzzing.
    self.latest_corpus_path = self.clusterfuzz_deployment.download_corpus(
        self.target_name, self.out_dir)
    if self.latest_corpus_path:
      run_fuzzer_command = run_fuzzer_command + ' ' + self.latest_corpus_path
    command_arguments.append(run_fuzzer_command)
    result = docker.run_container_command(command_arguments,
                                          timeout=self.duration + BUFFER_TIME)

    if result.timed_out:
      logging.info('Stopped docker container before timeout.')

    if not result.retcode:
      logging.info('Fuzzer %s finished with no crashes discovered.',
                   self.target_name)
      return FuzzResult(None, None)

    if result.stderr is None:
      return FuzzResult(None, None)

    # Crash was discovered.
    logging.info('Fuzzer %s, ended before timeout.', self.target_name)

    # TODO(metzman): Replace this with artifact_prefix so we don't have to
    # parse.
    testcase = self.get_testcase(result.stderr)

    if not testcase:
      logging.error(b'No testcase found in stacktrace: %s.', result.stderr)
      return FuzzResult(None, None)

    utils.binary_print(b'Fuzzer: %s. Detected bug:\n%s' %
                       (self.target_name.encode(), result.stderr))
    if self.is_crash_reportable(testcase):
      # We found a bug in the fuzz target and we will report it.
      return FuzzResult(testcase, result.stderr)

    # We found a bug but we won't report it.
    return FuzzResult(None, None)

  def free_disk_if_needed(self):
    """Deletes things that are no longer needed from fuzzing this fuzz target to
    save disk space if needed."""
    if not self.config.low_disk_space:
      return
    logging.info(
        'Deleting corpus, seed corpus and fuzz target of %s to save disk.',
        self.target_name)

    # Delete the seed corpus, corpus, and fuzz target.
    if self.latest_corpus_path and os.path.exists(self.latest_corpus_path):
      # Use ignore_errors=True to fix
      # https://github.com/google/oss-fuzz/issues/5383.
      shutil.rmtree(self.latest_corpus_path, ignore_errors=True)

    os.remove(self.target_path)
    target_seed_corpus_path = self.target_path + '_seed_corpus.zip'
    if os.path.exists(target_seed_corpus_path):
      os.remove(target_seed_corpus_path)
    logging.info('Done deleting.')

  def is_reproducible(self, testcase, target_path):
    """Checks if the testcase reproduces.

      Args:
        testcase: The path to the testcase to be tested.
        target_path: The path to the fuzz target to be tested

      Returns:
        True if crash is reproducible and we were able to run the
        binary.

      Raises:
        ReproduceError if we can't attempt to reproduce the crash.
    """

    if not os.path.exists(target_path):
      raise ReproduceError('Target %s not found.' % target_path)

    os.chmod(target_path, stat.S_IRWXO)

    target_dirname = os.path.dirname(target_path)
    command = ['docker', 'run', '--rm', '--privileged']
    container = utils.get_container_name()
    if container:
      command += [
          '--volumes-from', container, '-e', 'OUT=' + target_dirname, '-e',
          'TESTCASE=' + testcase
      ]
    else:
      command += [
          '-v',
          '%s:/out' % target_dirname, '-v',
          '%s:/testcase' % testcase
      ]

    command += [
        '-t', docker.BASE_RUNNER_TAG, 'reproduce', self.target_name, '-runs=100'
    ]

    logging.info('Running reproduce command: %s.', ' '.join(command))
    for _ in range(REPRODUCE_ATTEMPTS):
      _, _, returncode = utils.execute(command)
      if returncode != 0:
        logging.info('Reproduce command returned: %s. Reproducible on %s.',
                     returncode, target_path)

        return True

    logging.info('Reproduce command returned 0. Not reproducible on %s.',
                 target_path)
    return False

  def is_crash_reportable(self, testcase):
    """Returns True if a crash is reportable. This means the crash is
    reproducible but not reproducible on a build from the ClusterFuzz deployment
    (meaning the crash was introduced by this PR/commit/code change).

    Args:
      testcase: The path to the testcase that triggered the crash.

    Returns:
      True if the crash was introduced by the current pull request.

    Raises:
      ReproduceError if we can't attempt to reproduce the crash on the PR build.
    """
    if not os.path.exists(testcase):
      raise ReproduceError('Testcase %s not found.' % testcase)

    try:
      reproducible_on_code_change = self.is_reproducible(
          testcase, self.target_path)
    except ReproduceError as error:
      logging.error('Could not run target when checking for reproducibility.'
                    'Please file an issue:'
                    'https://github.com/google/oss-fuzz/issues/new.')
      raise error

    if not reproducible_on_code_change:
      logging.info('Failed to reproduce the crash using the obtained testcase.')
      return False

    clusterfuzz_build_dir = self.clusterfuzz_deployment.download_latest_build(
        self.out_dir)
    if not clusterfuzz_build_dir:
      # Crash is reproducible on PR build and we can't test on a recent
      # ClusterFuzz/OSS-Fuzz build.
      logging.info(COULD_NOT_TEST_ON_RECENT_MESSAGE)
      return True

    clusterfuzz_target_path = os.path.join(clusterfuzz_build_dir,
                                           self.target_name)
    try:
      reproducible_on_clusterfuzz_build = self.is_reproducible(
          testcase, clusterfuzz_target_path)
    except ReproduceError:
      # This happens if the project has ClusterFuzz builds, but the fuzz target
      # is not in it (e.g. because the fuzz target is new).
      logging.info(COULD_NOT_TEST_ON_RECENT_MESSAGE)
      return True

    if not reproducible_on_clusterfuzz_build:
      logging.info('The crash is reproducible. The crash doesn\'t reproduce '
                   'on old builds. This code change probably introduced the '
                   'crash.')
      return True

    logging.info('The crash is reproducible on old builds '
                 '(without the current code change).')
    return False

  def get_testcase(self, error_bytes):
    """Gets the file from a fuzzer run stacktrace.

    Args:
      error_bytes: The bytes containing the output from the fuzzer.

    Returns:
      The path to the testcase or None if not found.
    """
    match = re.search(rb'\bTest unit written to \.\/([^\s]+)', error_bytes)
    if match:
      return os.path.join(self.out_dir, match.group(1).decode('utf-8'))
    return None
