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
"""Module for dealing with fuzzers affected by the change-under-test (CUT)."""
import os
import sys

import coverage

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import utils


def fix_git_repo_for_diff(repo_dir):
  """Fixes git repos cloned by the "checkout" action so that diffing works on
  them."""
  command = [
      'git', 'symbolic-ref', 'refs/remotes/origin/HEAD',
      'refs/remotes/origin/master'
  ]
  return utils.execute(command, location=repo_dir)
