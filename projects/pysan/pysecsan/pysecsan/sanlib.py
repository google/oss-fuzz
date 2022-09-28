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

import re
import os
import sys
import time
import functools
import subprocess
import pkg_resources

from typing import Any, Callable, Optional
from pysecsan import command_injection, redos, yaml_deserialization


sanitizer_log_level = 0
def sanitizer_log(msg, log_level):
    global sanitizer_log_level
    if log_level >= sanitizer_log_level:
        print(f"[PYSAN] {msg}")


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
                #print("Overwriting ret value")
                ret = tmp_ret
        sanitizer_log(f"Hook end {str(function)}", 0)
        return ret
    return run


def pysan_add_hooks():
    """Sets up hooks"""
    os.system = pysan_add_hook(os.system,
                               pre_exec_hook = command_injection.pysan_hook_os_system)
    subprocess.Popen = pysan_add_hook(
        subprocess.Popen,
        pre_exec_hook = command_injection.pysan_hook_subprocess_Popen
    )
    re.compile = pysan_add_hook(
        re.compile,
        pre_exec_hook = redos.pysan_hook_re_compile,
        post_exec_hook = redos.pysan_hook_post_re_compile
    )


    # Hack to determine if yaml is elligible, because pkg_resources does
    # not seem to work from pyinstaller.
    do_yaml = True
    try:
        import yaml
    except:
        do_yaml = False
    if do_yaml:
        sanitizer_log("Hooking pyyaml.load", 0)
        yaml.load = pysan_add_hook(
            yaml.load,
            pre_exec_hook = yaml_deserialization.prehook_pyyaml_load,
        )
    else:
        sanitizer_log("pyyaml not found. No hooks here", 0)
