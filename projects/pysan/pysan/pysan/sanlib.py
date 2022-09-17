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

from typing import Any, Callable, Optional
import functools
import re
import sys
import time
import os
import subprocess

sanitizer_log_level = 0
def sanitizer_log(msg, log_level):
    global sanitizer_log_level
    if log_level >= sanitizer_log_level:
        print(f"[PYSAN] {msg}")

#################
# Hooking logic #
#################
def create_object_wrapper(**methods):
  """Hooks functions in an object

  This is needed for hooking built-in types and object attributes.

  Example use case is if we want to find ReDOS vulnerabilities, that
  have a pattern of

  ```
  import re
  r = re.compile(REGEX)
  for _ in r.findall(...)
  ```

  In the above case r.findall is a reference to
  re.Pattern.findall, which is a built-in type that is non-writeable.

  In order to hook such calls we need to wrap the object, and also hook the
  re.compile function to return the wrapped/hooked object.
  """

  class Wrapper(object):
    def __init__(self, instance):
      object.__setattr__(self, 'instance',instance)

    def __setattr__(self, name, value):
      object.__setattr__(object.__getattribute__(self,'instance'), name, value)

    def __getattribute__(self, name):
      instance = object.__getattribute__(self, 'instance')

      def _hook_func(self, pre_hook, post_hook, orig, *args, **kargs):
          if pre_hook is not None:
              pre_hook(self, *args, **kargs)
          # No need to pass instance here because when we extracted
          # the funcion we used instance.__getattribute__(name) which
          # seems to include it. I think.
          r = orig(*args, **kargs)

          if post_hook is not None:
              post_hook(self, *args, **kargs)
          return r

      # If this is a wrapped method, return a bound method
      if name in methods:
          pre_hook = methods[name][0]
          post_hook = methods[name][1]
          orig = instance.__getattribute__(name)
          return (
            lambda *args, **kargs: _hook_func(
                self, pre_hook, post_hook, orig, *args, **kargs
            )
          )

      # Otherwise, just return attribute of instance
      return instance.__getattribute__(name)

  return Wrapper




def pysan_add_hook(function: Callable[[Any], Any],
                   pre_exec_hook: Optional[Callable[[Any], Any]] = None,
                   post_exec_hook: Optional[Callable[[Any], Any]] = None):
    """Hook a function.

    Hooks can be placed pre and post function call. At least one hook is
    needed.

    This hooking is intended on non-object hooks. In order to hook functions
    in objects the `create_object_wrapper` function is used in combination with function
    hooking initialisation functions post execution.
    """
    if pre_exec_hook is None and post_exec_hook is None:
        raise Exception("Some hooks must be included")

    @functools.wraps(function)
    def run(*args, **kwargs):
        sanitizer_log(f"Hook start {str(function)}", 0)

        # Call hook
        if pre_exec_hook is not None:
            pre_exec_hook(*args, **kwargs)

        # Call the original function in the even the hook did not indicate
        # failure.
        ret = function(*args, **kwargs)

        # Post execution hook. Overwrite return value if anything is returned
        # by post hook.
        if post_exec_hook is not None:
            tmp_ret = post_exec_hook(ret, *args, **kwargs)
            if tmp_ret is not None:
                print("Overwriting ret value")
                ret = tmp_ret
        sanitizer_log(f"Hook end {str(function)}", 0)
        return ret
    return run


##############
# Sanitizers #
##############

#############################
# Code injection sanitizers #
#############################
def check_code_injection_match(elem) -> Optional[str]:
    # Check exact match
    if elem == "exec-sanitizer":
        return "Explicit command injection found."

    # Check potential for injecting into a string
    if "FROMFUZZ" in elem:
        return "Fuzzer controlled content in data. Code injection potential."
    return None


def pysan_hook_subprocess_Popen(cmd, **kwargs):
    """Hook for subprocess.Popen"""
    # Check first argument
    if type(cmd) is str:
        res = check_code_injection_match(cmd)
        if res != None:
            raise Exception(
                    f"Potental code injection in subprocess.Popen\n{res}")
    if type(cmd) is list:
        for elem in cmd:
            res = check_code_injection_match(elem)
            if res != None:
                print(res)
                raise Exception(
                    f"Potential code injection in subprocess.Popen\n{res}")


def pysan_hook_os_system(cmd):
    """Hook for os.system"""
    res = check_code_injection_match(cmd)
    if res != None:
        raise Exception(f"Potential code injection by way of os.system\n{res}")


def pysan_hook_eval(cmd):
    """Hook for eval"""
    res = check_code_injection_match(cmd)
    if res != None:
        raise Exception(f"Potential code injection by way of eval\n{res}")


# Hooks for regular expressions.
# Main problem is to identify ReDOS attemps. This is a non-trivial task
# - https://arxiv.org/pdf/1701.04045.pdf
# - https://dl.acm.org/doi/pdf/10.1145/3236024.3236027
# and the current approach we use is simply check for extensive computing time.
# In essence, this is more of a refinement of traditional timeout checker from
# the fuzzer, however, that's the consequence of ReDOS attacks as well.
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
    print("In post hook")
    try:
        endtime = time.time() - starttime
        if endtime > 4:
            print("param: %s"%(s))
            raise Exception("Potential ReDOS attack")
    except NameError:
        #print("For some reason starttime is not set, which it should have")
        sys.exit(1)
        pass

def pysan_hook_re_pattern_findall_pre(self, s):
    global starttime
    starttime = time.time()
    #time.sleep(5)
    #print("Pattern")
    #print(self.pattern)

def pysan_hook_post_re_compile(retval, pattern, flags=None):
    """Hook for re.compile post execution to hook returned objects functions"""
    sanitizer_log("Inside of post compile hook", 0)
    wrapper_object = create_object_wrapper(methods = {
            "findall" : (pysan_hook_re_pattern_findall_pre, pysan_hook_re_pattern_findall_post)
        }
    )
    hooked_object = wrapper_object(retval)
    return hooked_object


def pysan_hook_re_compile(pattern, flags=None):
    """Check if tainted input exists in pattern. If so, likely chance of making
    ReDOS possible."""
    sanitizer_log("Inside re compile hook", 0)


############################################
# Set up the hooks
############################################
def pysan_add_hooks(experimental = False):
    os.system = pysan_add_hook(os.system,
                               pre_exec_hook = pysan_hook_os_system)
    if experimental:
        re.compile = pysan_add_hook(
            re.compile,
            pre_exec_hook = pysan_hook_re_compile,
            post_exec_hook = pysan_hook_post_re_compile
        )
        subprocess.Popen = pysan_add_hook(
            subprocess.Popen,
            pre_exec_hook = pysan_hook_subprocess_Popen
        )

#pysan_add_hooks()
