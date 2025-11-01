# Copyright 2022 Google LLC
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
#
################################################################################
"""Sanitizer for regular expression dos."""

# pylint: disable=protected-access

import time
import os
from pysecsan import sanlib

START_RE_TIME = None


# Hooks for regular expressions.
# Main problem is to identify ReDOS attemps. This is a non-trivial task
# - https://arxiv.org/pdf/1701.04045.pdf
# - https://dl.acm.org/doi/pdf/10.1145/3236024.3236027
# and the current approach we use is simply check for extensive computing time.
# In essence, this is more of a refinement of traditional timeout checker from
# the fuzzer, which, effectively will detect these types of attacks by way of
# timeouts.
#
# Perhaps the smartest would be to use something like e.g.
# https://github.com/doyensec/regexploit to scan the regex patterns.
# Other heuristics without going too technical on identifying super-linear
# regexes:
# - check
#   - if 'taint' exists in re.compile(xx)
# - check
#   - for backtracking possbility in PATTERN within re.comile(PATTERN)
#   - and
#   - 'taint' in findall(XX) calls.
# pylint: disable=global-statement
def hook_post_exec_re_pattern_findall(self, re_str):
  """Hook post exeution re.compile().findall()."""
  _ = self  # Satisfy lint
  global START_RE_TIME
  try:
    endtime = time.time() - START_RE_TIME
    if endtime > 4:
      sanlib.abort_with_issue(f'Potential ReDOS attack.\n {re_str}', 'ReDOS')
  except NameError:
    sanlib.sanitizer_log(
        'starttime is not set, which it should have. Error in PySecSan',
        sanlib.LOG_INFO)
    os._exit(1)


def hook_pre_exec_re_pattern_findall(self, string):
  """Hook pre execution of re.pattern().findall()."""
  _ = (self, string)  # Satisfy lint
  global START_RE_TIME
  START_RE_TIME = time.time()


def hook_post_exec_re_compile(retval, pattern, flags=None):
  """Hook for re.compile post execution to hook returned objects functions."""
  _ = (pattern, flags)  # Satisfy lint
  sanlib.sanitizer_log('Inside of post compile hook', sanlib.LOG_DEBUG)
  wrapper_object = sanlib.create_object_wrapper(
      findall=(hook_pre_exec_re_pattern_findall,
               hook_post_exec_re_pattern_findall))
  hooked_object = wrapper_object(retval)
  return hooked_object


def hook_pre_exec_re_compile(pattern, flags=None):
  """Check if tainted input exists in pattern. If so, likely chance of making
    ReDOS possible."""
  _ = (pattern, flags)  # Satisfy lint
  sanlib.sanitizer_log('Inside re compile hook', sanlib.LOG_DEBUG)
