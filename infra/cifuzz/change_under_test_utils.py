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

  def __init__(self, ci_system, repo_manager_obj):
    self.ci_system = ci_system
    self.repo_manager = repo_manager_obj

  def diff(self):
    """Returns the changed files that need to be tested."""
    base = self.ci_system.get_diff_base()
    logging.info('Diffing against "%s".', base)
    return self.repo_manager.get_git_diff(base)
