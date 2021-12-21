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
import shutil
import stat
import tempfile

import clusterfuzz.environment
import clusterfuzz.fuzz

import config_utils
import logs

logs.init()

# Use len_control=0 since we don't have enough time fuzzing for len_control to
# make sense (probably).
LIBFUZZER_OPTIONS_BATCH = ['-len_control=0']
# Use a fixed seed for determinism for code change fuzzing.
LIBFUZZER_OPTIONS_CODE_CHANGE = LIBFUZZER_OPTIONS_BATCH + ['-seed=1337']
LIBFUZZER_OPTIONS_NO_REPORT_OOM = ['-rss_limit_mb=0']

# The number of reproduce attempts for a crash.
REPRODUCE_ATTEMPTS = 10

REPRODUCE_TIME_SECONDS = 30

# Seconds on top of duration until a timeout error is raised.
BUFFER_TIME = 10

# Log message if we can't check if crash reproduces on an recent build.
COULD_NOT_TEST_ON_CLUSTERFUZZ_MESSAGE = (
    'Could not run previous build of target to determine if this code change '
    '(pr/commit) introduced crash. Assuming crash was newly introduced.')

FuzzResult = collections.namedtuple('FuzzResult',
                                    ['testcase', 'stacktrace', 'corpus_path'])


class ReproduceError(Exception):
  """Error for when we can't attempt to reproduce a crash."""


def get_fuzz_target_corpus_dir(workspace, target_name):
  """Returns the directory for storing |target_name|'s corpus in |workspace|."""
  return os.path.join(workspace.corpora, target_name)


def get_fuzz_target_pruned_corpus_dir(workspace, target_name):
  """Returns the directory for storing |target_name|'s puned corpus in
  |workspace|."""
  return os.path.join(workspace.pruned_corpora, target_name)


class FuzzTarget:  # pylint: disable=too-many-instance-attributes
  """A class to manage a single fuzz target.

  Attributes:
    target_name: The name of the fuzz target.
    duration: The length of time in seconds that the target should run.
    target_path: The location of the fuzz target binary.
    workspace: The workspace for storing things related to fuzzing.
  """

  # pylint: disable=too-many-arguments
  def __init__(self, target_path, duration, workspace, clusterfuzz_deployment,
               config):
    """Represents a single fuzz target.

    Args:
      target_path: The location of the fuzz target binary.
      duration: The length of time  in seconds the target should run.
      workspace: The path used for storing things needed for fuzzing.
      clusterfuzz_deployment: The object representing the ClusterFuzz
          deployment.
      config: The config of this project.
    """
    self.target_path = target_path
    self.target_name = os.path.basename(self.target_path)
    self.duration = int(duration)
    self.workspace = workspace
    self.clusterfuzz_deployment = clusterfuzz_deployment
    self.config = config
    self.latest_corpus_path = get_fuzz_target_corpus_dir(
        self.workspace, self.target_name)
    os.makedirs(self.latest_corpus_path, exist_ok=True)
    self.pruned_corpus_path = get_fuzz_target_pruned_corpus_dir(
        self.workspace, self.target_name)
    os.makedirs(self.pruned_corpus_path, exist_ok=True)

  def _download_corpus(self):
    """Downloads the corpus for the target from ClusterFuzz and returns the path
    to the corpus. An empty directory is provided if the corpus can't be
    downloaded or is empty."""
    self.clusterfuzz_deployment.download_corpus(self.target_name,
                                                self.latest_corpus_path)
    return self.latest_corpus_path

  def _target_artifact_path(self):
    """Target artifact path."""
    artifact_path = os.path.join(self.workspace.artifacts, self.target_name,
                                 self.config.sanitizer)
    os.makedirs(artifact_path, exist_ok=True)
    return artifact_path

  def _save_crash(self, crash):
    """Add stacktraces to crashes."""
    target_reproducer_path = os.path.join(self._target_artifact_path(),
                                          os.path.basename(crash.input_path))
    shutil.copy(crash.input_path, target_reproducer_path)

    bug_summary_artifact_path = target_reproducer_path + '.summary'
    with open(bug_summary_artifact_path, 'w') as handle:
      handle.write(crash.stacktrace)

    return target_reproducer_path

  def prune(self):
    """Prunes the corpus and returns the result."""
    self._download_corpus()
    with clusterfuzz.environment.Environment(config_utils.DEFAULT_ENGINE,
                                             self.config.sanitizer,
                                             self.target_path,
                                             interactive=True):
      engine_impl = clusterfuzz.fuzz.get_engine(config_utils.DEFAULT_ENGINE)
      result = engine_impl.minimize_corpus(self.target_path, [],
                                           [self.latest_corpus_path],
                                           self.pruned_corpus_path,
                                           self._target_artifact_path(),
                                           self.duration)

    return FuzzResult(None, result.logs, self.pruned_corpus_path)

  def fuzz(self, batch=False):
    """Starts the fuzz target run for the length of time specified by duration.

    Returns:
      FuzzResult namedtuple with stacktrace and testcase if applicable.
    """
    logging.info('Running fuzzer: %s.', self.target_name)

    self._download_corpus()
    corpus_path = self.latest_corpus_path

    logging.info('Starting fuzzing')
    with tempfile.TemporaryDirectory() as artifacts_dir:
      with clusterfuzz.environment.Environment(config_utils.DEFAULT_ENGINE,
                                               self.config.sanitizer,
                                               self.target_path,
                                               interactive=True) as env:
        engine_impl = clusterfuzz.fuzz.get_engine(config_utils.DEFAULT_ENGINE)
        options = engine_impl.prepare(corpus_path, env.target_path,
                                      env.build_dir)
        options.merge_back_new_testcases = False
        options.analyze_dictionary = False
        if batch:
          options.arguments.extend(LIBFUZZER_OPTIONS_BATCH)
        else:
          options.arguments.extend(LIBFUZZER_OPTIONS_CODE_CHANGE)

        if not self.config.report_ooms:
          options.arguments.extend(LIBFUZZER_OPTIONS_NO_REPORT_OOM)

        result = engine_impl.fuzz(self.target_path, options, artifacts_dir,
                                  self.duration)

      if not result.crashes:
        # Libfuzzer max time was reached.
        logging.info('Fuzzer %s finished with no crashes discovered.',
                     self.target_name)
        return FuzzResult(None, None, self.latest_corpus_path)

      # Only report first crash.
      crash = result.crashes[0]
      logging.info('Fuzzer: %s. Detected bug.', self.target_name)

      is_reportable = self.is_crash_reportable(crash.input_path,
                                               crash.reproduce_args,
                                               batch=batch)
      if is_reportable or self.config.upload_all_crashes:
        fuzzer_logs = result.logs
        testcase_path = self._save_crash(crash)
      else:
        fuzzer_logs = None
        testcase_path = None

    return FuzzResult(testcase_path, fuzzer_logs, self.latest_corpus_path)

  def free_disk_if_needed(self, delete_fuzz_target=True):
    """Deletes things that are no longer needed from fuzzing this fuzz target to
    save disk space if needed."""
    if not self.config.low_disk_space:
      logging.info('Not freeing disk space after running fuzz target.')
      return
    logging.info('Deleting corpus and seed corpus of %s to save disk.',
                 self.target_name)

    # Delete the seed corpus, corpus, and fuzz target.
    for corpus_path in [self.latest_corpus_path, self.pruned_corpus_path]:
      # Use ignore_errors=True to fix
      # https://github.com/google/oss-fuzz/issues/5383.
      shutil.rmtree(corpus_path, ignore_errors=True)

    target_seed_corpus_path = self.target_path + '_seed_corpus.zip'
    if os.path.exists(target_seed_corpus_path):
      os.remove(target_seed_corpus_path)

    if delete_fuzz_target:
      logging.info('Deleting fuzz target: %s.', self.target_name)
      os.remove(self.target_path)
    logging.info('Done deleting.')

  def is_reproducible(self, testcase, target_path, reproduce_args):
    """Checks if the testcase reproduces.

      Args:
        testcase: The path to the testcase to be tested.
        target_path: The path to the fuzz target to be tested
        reproduce_args: The arguments to pass to the target to reproduce the
          crash.

      Returns:
        True if crash is reproducible and we were able to run the
        binary.

      Raises:
        ReproduceError if we can't attempt to reproduce the crash.
    """
    if not os.path.exists(target_path):
      logging.info('Target: %s does not exist.', target_path)
      raise ReproduceError(f'Target {target_path} not found.')

    os.chmod(target_path, stat.S_IRWXO)

    logging.info('Trying to reproduce crash using: %s.', testcase)
    with clusterfuzz.environment.Environment(config_utils.DEFAULT_ENGINE,
                                             self.config.sanitizer,
                                             target_path,
                                             interactive=False):
      for _ in range(REPRODUCE_ATTEMPTS):
        engine_impl = clusterfuzz.fuzz.get_engine(config_utils.DEFAULT_ENGINE)
        try:
          result = engine_impl.reproduce(target_path,
                                         testcase,
                                         arguments=reproduce_args,
                                         max_time=REPRODUCE_TIME_SECONDS)
        except TimeoutError as error:
          logging.error('%s.', error)
          return False

        if result.return_code != 0:
          logging.info('Reproduce command returned: %s. Reproducible on %s.',
                       result.return_code, target_path)

          return True

    logging.info('Reproduce command returned: 0. Not reproducible on %s.',
                 target_path)
    return False

  def is_crash_reportable(self, testcase, reproduce_args, batch=False):
    """Returns True if a crash is reportable. This means the crash is
    reproducible but not reproducible on a build from the ClusterFuzz deployment
    (meaning the crash was introduced by this PR/commit/code change).

    Args:
      testcase: The path to the testcase that triggered the crash.
      reproduce_args: The arguments to pass to the target to reproduce the
      crash.

    Returns:
      True if the crash was introduced by the current pull request.

    Raises:
      ReproduceError if we can't attempt to reproduce the crash on the PR build.
    """

    if not self.is_crash_type_reportable(testcase):
      return False

    if not os.path.exists(testcase):
      raise ReproduceError(f'Testcase {testcase} not found.')

    try:
      reproducible_on_code_change = self.is_reproducible(
          testcase, self.target_path, reproduce_args)
    except ReproduceError as error:
      logging.error('Could not check for crash reproducibility.'
                    'Please file an issue:'
                    'https://github.com/google/oss-fuzz/issues/new.')
      raise error

    if not reproducible_on_code_change:
      logging.info('Crash is not reproducible.')
      return self.config.report_unreproducible_crashes

    logging.info('Crash is reproducible.')
    if batch:
      # We don't need to check if the crash is novel for batch fuzzing.
      return True

    return self.is_crash_novel(testcase, reproduce_args)

  def is_crash_type_reportable(self, testcase):
    """Returns True if |testcase| is an actual crash. If crash is a timeout or
    OOM then returns True if config says we should report those."""
    # TODO(metzman): Use a less hacky method.
    testcase = os.path.basename(testcase)
    if testcase.startswith('oom-'):
      return self.config.report_ooms
    if testcase.startswith('timeout-'):
      return self.config.report_timeouts
    return True

  def is_crash_novel(self, testcase, reproduce_args):
    """Returns whether or not the crash is new. A crash is considered new if it
    can't be reproduced on an older ClusterFuzz build of the target."""
    if not os.path.exists(testcase):
      raise ReproduceError('Testcase %s not found.' % testcase)
    clusterfuzz_build_dir = self.clusterfuzz_deployment.download_latest_build()
    if not clusterfuzz_build_dir:
      # Crash is reproducible on PR build and we can't test on a recent
      # ClusterFuzz/OSS-Fuzz build.
      logging.info(COULD_NOT_TEST_ON_CLUSTERFUZZ_MESSAGE)
      return True

    clusterfuzz_target_path = os.path.join(clusterfuzz_build_dir,
                                           self.target_name)

    try:
      reproducible_on_clusterfuzz_build = self.is_reproducible(
          testcase, clusterfuzz_target_path, reproduce_args)
    except ReproduceError:
      # This happens if the project has ClusterFuzz builds, but the fuzz target
      # is not in it (e.g. because the fuzz target is new).
      logging.info(COULD_NOT_TEST_ON_CLUSTERFUZZ_MESSAGE)
      return True

    if reproducible_on_clusterfuzz_build:
      logging.info('The crash is reproducible on previous build. '
                   'Code change (pr/commit) did not introduce crash.')
      return False
    logging.info('The crash is not reproducible on previous build. '
                 'Code change (pr/commit) introduced crash.')
    return True
