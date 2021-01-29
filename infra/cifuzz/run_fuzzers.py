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
import logging
import os
import shutil
import sys
import time

import clusterfuzz_deployment
import fuzz_target
import stack_parser

# pylint: disable=wrong-import-position,import-error
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import utils


class BaseFuzzTargetRunner:
  """Base class for fuzzer runners."""

  def __init__(self, config):
    self.config = config
    self.clusterfuzz_deployment = (
        clusterfuzz_deployment.get_clusterfuzz_deployment(self.config))
    # Set by the initialize method.
    self.out_dir = None
    self.fuzz_target_paths = None
    self.artifacts_dir = None

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

    self.out_dir = os.path.join(self.config.workspace, 'out')
    if not os.path.exists(self.out_dir):
      logging.error('Out directory: %s does not exist.', self.out_dir)
      return False

    self.artifacts_dir = os.path.join(self.out_dir, 'artifacts')
    if not os.path.exists(self.artifacts_dir):
      os.mkdir(self.artifacts_dir)
    elif (not os.path.isdir(self.artifacts_dir) or
          os.listdir(self.artifacts_dir)):
      logging.error('Artifacts path: %s exists and is not an empty directory.',
                    self.artifacts_dir)
      return False

    self.fuzz_target_paths = utils.get_fuzz_targets(self.out_dir)
    logging.info('Fuzz targets: %s', self.fuzz_target_paths)
    if not self.fuzz_target_paths:
      logging.error('No fuzz targets were found in out directory: %s.',
                    self.out_dir)
      return False

    return True

  def run_fuzz_target(self, fuzz_target_obj):  # pylint: disable=no-self-use
    """Fuzzes with |fuzz_target_obj| and returns the result."""
    # TODO(metzman): Make children implement this so that the batch runner can
    # do things differently.
    return fuzz_target_obj.fuzz()

  @property
  def quit_on_bug_found(self):
    """Property that is checked to determine if fuzzing should quit after first
    bug is found."""
    raise NotImplementedError('Child class must implement method')

  def get_fuzz_target_artifact(self, target, artifact_name):
    """Returns the path of a fuzzing |artifact| named |artifact_name| for
    |target|."""
    artifact_name = target.target_name + '-' + artifact_name
    return os.path.join(self.artifacts_dir, artifact_name)

  def create_fuzz_target_obj(self, target_path, run_seconds):
    """Returns a fuzz target object."""
    return fuzz_target.FuzzTarget(target_path, run_seconds, self.out_dir,
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
      testcase, stacktrace = self.run_fuzz_target(target)

      # It's OK if this goes negative since we take max when determining
      # run_seconds.
      fuzz_seconds -= time.time() - start_time

      fuzzers_left_to_run -= 1
      if not testcase or not stacktrace:
        logging.info('Fuzzer %s finished running without crashes.',
                     target.target_name)
        continue

      # We found a bug in the fuzz target.
      utils.binary_print(b'Fuzzer: %s. Detected bug:\n%s' %
                         (target.target_name.encode(), stacktrace))

      # TODO(metzman): Do this with filestore.
      testcase_artifact = self.get_fuzz_target_artifact(target, 'testcase')
      shutil.move(testcase, testcase_artifact)
      bug_summary_artifact = self.get_fuzz_target_artifact(
          target, 'bug-summary.txt')
      stack_parser.parse_fuzzer_output(stacktrace, bug_summary_artifact)

      bug_found = True
      if self.quit_on_bug_found:
        logging.info('Bug found. Stopping fuzzing.')
        return bug_found

    return bug_found


class CiFuzzTargetRunner(BaseFuzzTargetRunner):
  """Runner for fuzz targets used in CI (patch-fuzzing) context."""

  @property
  def quit_on_bug_found(self):
    return True


class BatchFuzzTargetRunner(BaseFuzzTargetRunner):
  """Runner for fuzz targets used in batch fuzzing context."""

  @property
  def quit_on_bug_found(self):
    return False


def get_fuzz_target_runner(config):
  """Returns a fuzz target runner object based on the run_fuzzers_mode of
  |config|."""
  logging.info('RUN_FUZZERS_MODE is: %s', config.run_fuzzers_mode)
  if config.run_fuzzers_mode == 'batch':
    return BatchFuzzTargetRunner(config)
  return CiFuzzTargetRunner(config)


def run_fuzzers(config):  # pylint: disable=too-many-locals
  """Runs fuzzers for a specific OSS-Fuzz project.

  Args:
    config: A RunFuzzTargetsConfig.

  Returns:
    (True if no (internal) errors fuzzing, True if bug found fuzzing).
  """
  fuzz_target_runner = get_fuzz_target_runner(config)
  # TODO(metzman): Multiple return bools is confusing. Change to one enum
  # return value.
  if not fuzz_target_runner.initialize():
    # We didn't fuzz at all because of internal (CIFuzz) errors. And we didn't
    # find any bugs.
    return False, False

  if not fuzz_target_runner.run_fuzz_targets():
    # We fuzzed successfully, but didn't find any bugs (in the fuzz target).
    return True, False

  # We fuzzed successfully and found bug(s) in the fuzz targets.
  return True, True
