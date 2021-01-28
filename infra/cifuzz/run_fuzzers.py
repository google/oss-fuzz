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

import fuzz_target
import stack_parser

# pylint: disable=wrong-import-position,import-error
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import utils


def run_fuzzers(config):  # pylint: disable=too-many-locals
  """Runs fuzzers for a specific OSS-Fuzz project.

  Args:
    fuzz_seconds: The total time allotted for fuzzing.
    workspace: The location in a shared volume to store a git repo and build
      artifacts.
    project_name: The name of the relevant OSS-Fuzz project.
    sanitizer: The sanitizer the fuzzers should be run with.

  Returns:
    (True if run was successful, True if bug was found).
  """
  # Validate inputs.
  logging.info('Using %s sanitizer.', config.sanitizer)

  out_dir = os.path.join(config.workspace, 'out')
  artifacts_dir = os.path.join(out_dir, 'artifacts')
  os.makedirs(artifacts_dir, exist_ok=True)

  if not config.fuzz_seconds or config.fuzz_seconds < 1:
    logging.error('Fuzz_seconds argument must be greater than 1, but was: %s.',
                  config.fuzz_seconds)
    return False, False

  # Get fuzzer information.
  fuzzer_paths = utils.get_fuzz_targets(out_dir)
  if not fuzzer_paths:
    logging.error('No fuzzers were found in out directory: %s.', out_dir)
    return False, False

  # Run fuzzers for allotted time.
  total_num_fuzzers = len(fuzzer_paths)
  fuzzers_left_to_run = total_num_fuzzers
  min_seconds_per_fuzzer = config.fuzz_seconds // total_num_fuzzers
  for fuzzer_path in fuzzer_paths:
    run_seconds = max(config.fuzz_seconds // fuzzers_left_to_run,
                      min_seconds_per_fuzzer)

    target = fuzz_target.FuzzTarget(fuzzer_path,
                                    run_seconds,
                                    out_dir,
                                    config.project_name,
                                    sanitizer=config.sanitizer)
    start_time = time.time()
    testcase, stacktrace = target.fuzz()
    config.fuzz_seconds -= (time.time() - start_time)
    if not testcase or not stacktrace:
      logging.info('Fuzzer %s, finished running.', target.target_name)
    else:
      utils.binary_print(b'Fuzzer %s, detected error:\n%s' %
                         (target.target_name.encode(), stacktrace))
      shutil.move(testcase, os.path.join(artifacts_dir, 'test_case'))
      stack_parser.parse_fuzzer_output(stacktrace, artifacts_dir)
      return True, True
    fuzzers_left_to_run -= 1

  return True, False
