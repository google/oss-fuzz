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
"""Module for determining the code change CIFuzz needs to fuzz."""
import logging
import os
import sys

# pylint: disable=wrong-import-position,import-error
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import utils


class ChangeUnderTest:
  """An object representing the code change that CIFuzz should test."""

  def __init__(self, config, repo_manager_obj):
    self.config = config
    self.repo_manager = repo_manager_obj

  @property
  def is_pr(self):
    """Returns True if fuzzing a PR."""
    return bool(self.config.pr_ref)

  def diff(self):
    """Returns the changed files that need to be tested."""
    if self.config.platform == self.config.Platform.INTERNAL_GENERIC_CI:
      self.fix_git_repo_for_diff()  # TODO(metzman): Look into removing this.
      logging.info('Diffing against "origin...".')
      return self.repo_manager.get_git_diff('origin...')

    # On GitHub.
    if self.is_pr:
      logging.info('Diffing against "%s".', self.config.base_ref)
      return self.repo_manager.get_git_diff(self.config.base_ref)

    # Commit fuzzing.
    # TODO(https://github.com/google/oss-fuzz/issues/5010): Figure out what to
    # do here.
    logging.info('Commit fuzzing. '
                 'Pretending no files changed so all fuzzers run. '
                 'See https://github.com/google/oss-fuzz/issues/5010')
    return []

  def fix_git_repo_for_diff(self):
    """Fixes git repos cloned by the "checkout" action so that diffing works on
    them."""
    command = [
        'git', 'symbolic-ref', 'refs/remotes/origin/HEAD',
        'refs/remotes/origin/master'
    ]
    return utils.execute(command, location=self.repo_manager.repo_dir)
