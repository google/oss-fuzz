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
"""Module for dealing with fuzz targets affected by the change-under-test
(CUT)."""
import logging
import os
import sys

# pylint: disable=wrong-import-position,import-error
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import utils


def remove_unaffected_fuzz_targets(clusterfuzz_deployment, out_dir,
                                   files_changed, repo_path):
  """Removes all non affected fuzz targets in the out directory.

  Args:
    clusterfuzz_deployment: The ClusterFuzz deployment object.
    out_dir: The location of the fuzz target binaries.
    files_changed: A list of files changed compared to HEAD.
    repo_path: The location of the OSS-Fuzz repo in the docker image.

  This function will not delete fuzz targets unless it knows that the fuzz
  targets are unaffected. For example, this means that fuzz targets which don't
  have coverage data on will not be deleted.
  """
  if not files_changed:
    # Don't remove any fuzz targets if there is no difference from HEAD.
    logging.info('No files changed compared to HEAD.')
    return

  logging.info('Files changed in PR: %s', files_changed)

  fuzz_target_paths = utils.get_fuzz_targets(out_dir)
  if not fuzz_target_paths:
    # Nothing to remove.
    logging.error('No fuzz targets found in out dir.')
    return

  coverage = clusterfuzz_deployment.get_coverage(repo_path)
  if not coverage:
    # Don't remove any fuzz targets unless we have data.
    logging.error('Could not find latest coverage report.')
    return

  affected_fuzz_targets = get_affected_fuzz_targets(coverage, fuzz_target_paths,
                                                    files_changed)

  if not affected_fuzz_targets:
    logging.info('No affected fuzz targets detected, keeping all as fallback.')
    return

  logging.info('Using affected fuzz targets: %s.', affected_fuzz_targets)
  unaffected_fuzz_targets = set(fuzz_target_paths) - affected_fuzz_targets
  logging.info('Removing unaffected fuzz targets: %s.', unaffected_fuzz_targets)

  # Remove all the targets that are not affected.
  for fuzz_target_path in unaffected_fuzz_targets:
    try:
      os.remove(fuzz_target_path)
    except OSError as error:
      logging.error('%s occurred while removing file %s', error,
                    fuzz_target_path)


def is_fuzz_target_affected(coverage, fuzz_target_path, files_changed):
  """Returns True if a fuzz target (|fuzz_target_path|) is affected by
  |files_changed|."""
  fuzz_target = os.path.basename(fuzz_target_path)
  covered_files = coverage.get_files_covered_by_target(fuzz_target)
  if not covered_files:
    # Assume a fuzz target is affected if we can't get its coverage from
    # OSS-Fuzz.
    # TODO(metzman): Figure out what we should do if covered_files is [].
    # Should we act as if we couldn't get the coverage?
    logging.info('Could not get coverage for %s. Treating as affected.',
                 fuzz_target)
    return True

  covered_files = [
      os.path.normpath(covered_file) for covered_file in covered_files
  ]
  logging.info('Fuzz target %s is affected by: %s', fuzz_target, covered_files)
  for filename in files_changed:
    if filename in covered_files:
      logging.info('Fuzz target %s is affected by changed file: %s',
                   fuzz_target, filename)
      return True

  logging.info('Fuzz target %s is not affected.', fuzz_target)
  return False


def get_affected_fuzz_targets(coverage, fuzz_target_paths, files_changed):
  """Returns a list of paths of affected targets."""
  affected_fuzz_targets = set()
  for fuzz_target_path in fuzz_target_paths:
    if is_fuzz_target_affected(coverage, fuzz_target_path, files_changed):
      affected_fuzz_targets.add(fuzz_target_path)

  return affected_fuzz_targets
