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

import time
import sys
from pysecsan import sanlib

# Hooks for regular expressions.
# Main problem is to identify ReDOS attemps. This is a non-trivial task
# - https://arxiv.org/pdf/1701.04045.pdf
# - https://dl.acm.org/doi/pdf/10.1145/3236024.3236027
# and the current approach we use is simply check for extensive computing time.
# In essence, this is more of a refinement of traditional timeout checker from
# the fuzzer, which, effectivelly will detect these types of attacks by way of
# timeouts.
#
# Perhaps the smartest would be to use something like e.g.
# https://github.com/doyensec/regexploit to scan the regex patterns.
# Other heuristics without going too technical on identifying super-linear
# regexes:
# - check
#   - if "taint" exists in re.compile(xx)
# - check 
#   - for backtracking possbility in PATTERN within re.comile(PATTERN)
#   - and
#   - "taint" in findall(XX) calls.
def pysan_hook_re_pattern_findall_post(self, s):
    global starttime
    try:
        endtime = time.time() - starttime
        if endtime > 4:
            #print("param: %s"%(s))
            raise Exception("Potential ReDOS attack")
    except NameError:
        #print("For some reason starttime is not set, which it should have")
        sys.exit(1)
        pass

def pysan_hook_re_pattern_findall_pre(self, s):
    global starttime
    starttime = time.time()

def pysan_hook_post_re_compile(retval, pattern, flags=None):
    """Hook for re.compile post execution to hook returned objects functions"""
    sanlib.sanitizer_log("Inside of post compile hook", 0)
    wrapper_object = sanlib.create_object_wrapper(
            findall = (pysan_hook_re_pattern_findall_pre, pysan_hook_re_pattern_findall_post)
    )
    hooked_object = wrapper_object(retval)
    return hooked_object


def pysan_hook_re_compile(pattern, flags=None):
    """Check if tainted input exists in pattern. If so, likely chance of making
    ReDOS possible."""
    sanlib.sanitizer_log("Inside re compile hook", 0)
