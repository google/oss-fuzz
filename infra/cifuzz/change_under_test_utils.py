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
    base = None
    if self.config.platform == self.config.Platform.INTERNAL_GENERIC_CI:
      # TODO(metzman): Enforce something like Github's API for external users.
      self.fix_git_repo_for_diff()  # TODO(metzman): Look into removing this.
      base = 'origin...'
      logging.info('external')
    elif self.is_pr:
      # On GitHub.
      base = self.config.base_ref
      logging.info('gh pr')
    else:
      # Commit fuzzing.
      base = self.config.base_commit
      logging.info('gh commit')

    logging.info('Diffing against "%s".', base)
    return self.repo_manager.get_git_diff(base)

  def fix_git_repo_for_diff(self):
    """Fixes git repos cloned by the "checkout" action so that diffing works on
    them."""
    command = [
        'git', 'symbolic-ref', 'refs/remotes/origin/HEAD',
        'refs/remotes/origin/master'
    ]
    return utils.execute(command, location=self.repo_manager.repo_dir)
