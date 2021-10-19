# Copyright 2021 Google LLC
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
"""Module for running fuzzers."""
import enum
import logging
import os
import shutil
import sys
import time

import clusterfuzz_deployment
import fuzz_target
import generate_coverage_report
import stack_parser
import workspace_utils

# pylint: disable=wrong-import-position,import-error
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import utils


class RunFuzzersResult(enum.Enum):
  """Enum result from running fuzzers."""
  ERROR = 0
  BUG_FOUND = 1
  NO_BUG_FOUND = 2


class BaseFuzzTargetRunner:
  """Base class for fuzzer runners."""

  def __init__(self, config):
    self.config = config
    self.workspace = workspace_utils.Workspace(config)
    self.clusterfuzz_deployment = (
        clusterfuzz_deployment.get_clusterfuzz_deployment(
            self.config, self.workspace))

    # Set by the initialize method.
    self.fuzz_target_paths = None

  def get_fuzz_targets(self):
    """Returns fuzz targets in out directory."""
    return utils.get_fuzz_targets(self.workspace.out)

  def initialize(self):
    """Initialization method. Must be called before calling run_fuzz_targets.
    Returns True on success."""
    # Use a seperate initialization function so we can return False on failure
    # instead of exceptioning like we need to do if this were done in the
    # __init__ method.

    logging.info('Using %s sanitizer.', self.config.sanitizer)

    # TODO(metzman) Add a check to ensure we aren't over time limit.
    if not self.config.fuzz_seconds or self.config.fuzz_seconds < 1:
      logging.error(
          'Fuzz_seconds argument must be greater than 1, but was: %s.',
          self.config.fuzz_seconds)
      return False

    if not os.path.exists(self.workspace.out):
      logging.error('Out directory: %s does not exist.', self.workspace.out)
      return False

    if not os.path.exists(self.workspace.artifacts):
      os.makedirs(self.workspace.artifacts)
    elif (not os.path.isdir(self.workspace.artifacts) or
          os.listdir(self.workspace.artifacts)):
      logging.error('Artifacts path: %s exists and is not an empty directory.',
                    self.workspace.artifacts)
      return False

    self.fuzz_target_paths = self.get_fuzz_targets()
    logging.info('Fuzz targets: %s', self.fuzz_target_paths)
    if not self.fuzz_target_paths:
      logging.error('No fuzz targets were found in out directory: %s.',
                    self.workspace.out)
      return False

    return True

  def cleanup_after_fuzz_target_run(self, fuzz_target_obj):  # pylint: disable=no-self-use
    """Cleans up after running |fuzz_target_obj|."""
    raise NotImplementedError('Child class must implement method.')

  def run_fuzz_target(self, fuzz_target_obj):  # pylint: disable=no-self-use
    """Fuzzes with |fuzz_target_obj| and returns the result."""
    raise NotImplementedError('Child class must implement method.')

  @property
  def quit_on_bug_found(self):
    """Property that is checked to determine if fuzzing should quit after first
    bug is found."""
    raise NotImplementedError('Child class must implement method.')

  def get_fuzz_target_artifact(self, target, artifact_name):
    """Returns the path of a fuzzing artifact named |artifact_name| for
    |fuzz_target|."""
    artifact_name = (f'{target.target_name}-{self.config.sanitizer}-'
                     f'{artifact_name}')
    return os.path.join(self.workspace.artifacts, artifact_name)

  def create_fuzz_target_obj(self, target_path, run_seconds):
    """Returns a fuzz target object."""
    return fuzz_target.FuzzTarget(target_path, run_seconds, self.workspace,
                                  self.clusterfuzz_deployment, self.config)

  def run_fuzz_targets(self):
    """Runs fuzz targets. Returns True if a bug was found."""
    fuzzers_left_to_run = len(self.fuzz_target_paths)

    # Make a copy since we will mutate it.
    fuzz_seconds = self.config.fuzz_seconds

    min_seconds_per_fuzzer = fuzz_seconds // fuzzers_left_to_run
    bug_found = False
    for target_path in self.fuzz_target_paths:
      # By doing this, we can ensure that every fuzz target runs for at least
      # min_seconds_per_fuzzer, but that other fuzzers will have longer to run
      # if one ends early.
      run_seconds = max(fuzz_seconds // fuzzers_left_to_run,
                        min_seconds_per_fuzzer)

      target = self.create_fuzz_target_obj(target_path, run_seconds)
      start_time = time.time()
      result = self.run_fuzz_target(target)
      self.cleanup_after_fuzz_target_run(target)

      # It's OK if this goes negative since we take max when determining
      # run_seconds.
      fuzz_seconds -= time.time() - start_time

      fuzzers_left_to_run -= 1
      if not result.testcase or not result.stacktrace:
        logging.info('Fuzzer %s finished running without crashes.',
                     target.target_name)
        continue

      # TODO(metzman): Do this with filestore.
      testcase_artifact_path = self.get_fuzz_target_artifact(
          target, os.path.basename(result.testcase))
      shutil.move(result.testcase, testcase_artifact_path)
      bug_summary_artifact_path = self.get_fuzz_target_artifact(
          target, 'bug-summary.txt')
      stack_parser.parse_fuzzer_output(result.stacktrace,
                                       bug_summary_artifact_path)

      bug_found = True
      if self.quit_on_bug_found:
        logging.info('Bug found. Stopping fuzzing.')
        return bug_found

    return bug_found


class PruneTargetRunner(BaseFuzzTargetRunner):
  """Runner that prunes corpora."""

  @property
  def quit_on_bug_found(self):
    return False

  def run_fuzz_target(self, fuzz_target_obj):
    """Prunes with |fuzz_target_obj| and returns the result."""
    result = fuzz_target_obj.prune()
    logging.debug('Corpus path contents: %s.', os.listdir(result.corpus_path))
    self.clusterfuzz_deployment.upload_corpus(fuzz_target_obj.target_name,
                                              result.corpus_path,
                                              replace=True)
    return result

  def cleanup_after_fuzz_target_run(self, fuzz_target_obj):  # pylint: disable=no-self-use
    """Cleans up after pruning with |fuzz_target_obj|."""
    fuzz_target_obj.free_disk_if_needed()


class CoverageTargetRunner(BaseFuzzTargetRunner):
  """Runner that runs the 'coverage' command."""

  @property
  def quit_on_bug_found(self):
    raise NotImplementedError('Not implemented for CoverageTargetRunner.')

  def get_fuzz_targets(self):
    """Returns fuzz targets in out directory."""
    # We only want fuzz targets from the root because during the coverage build,
    # a lot of the image's filesystem is copied into /out for the purpose of
    # generating coverage reports.
    # TOOD(metzman): Figure out if top_level_only should be the only behavior
    # for this function.
    return utils.get_fuzz_targets(self.workspace.out, top_level_only=True)

  def run_fuzz_targets(self):
    """Generates a coverage report. Always returns False since it never finds
    any bugs."""
    generate_coverage_report.generate_coverage_report(
        self.fuzz_target_paths, self.workspace, self.clusterfuzz_deployment,
        self.config)
    return False

  def run_fuzz_target(self, fuzz_target_obj):  # pylint: disable=no-self-use
    """Fuzzes with |fuzz_target_obj| and returns the result."""
    raise NotImplementedError('Not implemented for CoverageTargetRunner.')

  def cleanup_after_fuzz_target_run(self, fuzz_target_obj):  # pylint: disable=no-self-use
    """Cleans up after running |fuzz_target_obj|."""
    raise NotImplementedError('Not implemented for CoverageTargetRunner.')


class CiFuzzTargetRunner(BaseFuzzTargetRunner):
  """Runner for fuzz targets used in CI (patch-fuzzing) context."""

  @property
  def quit_on_bug_found(self):
    return True

  def cleanup_after_fuzz_target_run(self, fuzz_target_obj):  # pylint: disable=no-self-use
    """Cleans up after running |fuzz_target_obj|."""
    fuzz_target_obj.free_disk_if_needed()

  def run_fuzz_target(self, fuzz_target_obj):  # pylint: disable=no-self-use
    return fuzz_target_obj.fuzz()


class BatchFuzzTargetRunner(BaseFuzzTargetRunner):
  """Runner for fuzz targets used in batch fuzzing context."""

  @property
  def quit_on_bug_found(self):
    return False

  def run_fuzz_target(self, fuzz_target_obj):
    """Fuzzes with |fuzz_target_obj| and returns the result."""
    result = fuzz_target_obj.fuzz()
    logging.debug('Corpus path contents: %s.', os.listdir(result.corpus_path))
    self.clusterfuzz_deployment.upload_corpus(fuzz_target_obj.target_name,
                                              result.corpus_path)
    return result

  def cleanup_after_fuzz_target_run(self, fuzz_target_obj):
    """Cleans up after running |fuzz_target_obj|."""
    # This must be done after we upload the corpus, otherwise it will be deleted
    # before we get a chance to upload it. We can't delete the fuzz target
    # because it is needed when we upload the build.
    fuzz_target_obj.free_disk_if_needed(delete_fuzz_target=False)

  def run_fuzz_targets(self):
    result = super().run_fuzz_targets()
    self.clusterfuzz_deployment.upload_crashes()
    return result


_RUN_FUZZERS_MODE_RUNNER_MAPPING = {
    'batch': BatchFuzzTargetRunner,
    'coverage': CoverageTargetRunner,
    'prune': PruneTargetRunner,
    'code-change': CiFuzzTargetRunner,
}


def get_fuzz_target_runner(config):
  """Returns a fuzz target runner object based on the run_fuzzers_mode of
  |config|."""
  runner = _RUN_FUZZERS_MODE_RUNNER_MAPPING[config.run_fuzzers_mode](config)
  logging.info('RUN_FUZZERS_MODE is: %s. Runner: %s.', config.run_fuzzers_mode,
               runner)
  return runner


def run_fuzzers(config):  # pylint: disable=too-many-locals
  """Runs fuzzers for a specific OSS-Fuzz project.

  Args:
    config: A RunFuzzTargetsConfig.

  Returns:
    A RunFuzzersResult enum value indicating what happened during fuzzing.
  """
  fuzz_target_runner = get_fuzz_target_runner(config)
  if not fuzz_target_runner.initialize():
    # We didn't fuzz at all because of internal (CIFuzz) errors. And we didn't
    # find any bugs.
    return RunFuzzersResult.ERROR

  if not fuzz_target_runner.run_fuzz_targets():
    # We fuzzed successfully, but didn't find any bugs (in the fuzz target).
    return RunFuzzersResult.NO_BUG_FOUND

  # We fuzzed successfully and found bug(s) in the fuzz targets.
  return RunFuzzersResult.BUG_FOUND
