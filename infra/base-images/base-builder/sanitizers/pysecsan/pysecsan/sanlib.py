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
"""Core routines for pysecsan library."""

# pylint: disable=protected-access

import re
import os
import functools
import subprocess
import traceback
import importlib

from typing import Any, Callable, Optional
from pysecsan import command_injection, redos, yaml_deserialization

LOG_DEBUG = 0
LOG_INFO = 1
PYSECSAN_LOG_LVL = LOG_INFO

# Message that will be printed to stdout when an issue is found.
PYSECSAN_BUG_LABEL = r'===BUG DETECTED: PySecSan:'


# pylint: disable=global-statement
def sanitizer_log(msg, log_level, force=False, log_prefix=True):
  """Helper printing function."""
  global PYSECSAN_LOG_LVL
  if log_level >= PYSECSAN_LOG_LVL or force:
    if log_prefix:
      print(f'[PYSECSAN] {msg}')
    else:
      print(f'{msg}')


def sanitizer_log_always(msg, log_prefix=True):
  """Wrapper for sanitizer logging. Will always log"""
  sanitizer_log(msg, 0, force=True, log_prefix=log_prefix)


def is_module_present(mod_name):
  """Identify if module is importable."""
  # pylint: disable=deprecated-method
  return importlib.find_loader(mod_name) is not None


def _log_bug(bug_title):
  sanitizer_log_always('%s %s ===' % (PYSECSAN_BUG_LABEL, bug_title),
                       log_prefix=False)


def abort_with_issue(msg, bug_title):
  """Print message, display stacktrace and force process exit.

  Use this function for signalling an issue is found and use the messages
  logged from this function to determine if a fuzzer found a bug.
  """
  # Show breaker string using an ASAN approach (uses 65 =)
  sanitizer_log_always("=" * 65, log_prefix=False)

  # Log issue message
  _log_bug(bug_title)
  sanitizer_log_always(msg)

  # Log stacktrace
  sanitizer_log_always("Stacktrace:")
  traceback.print_stack()

  # Force exit
  # Use os._exit here to force exit. sys.exit will exit
  # by throwing a SystemExit exception which the interpreter
  # handles by exiting. However, code may catch this exception,
  # and thus to avoid this we exit the process without exceptions.
  # pylint: disable=protected-access
  sanitizer_log_always("Exiting")
  os._exit(1)


def is_exact_taint(stream) -> bool:
  """Checks if stream is an exact match for taint from fuzzer."""
  # The fuzzer has to get 8 characters right. This may be a bit much,
  # however, when found it shows a high level of control over the data.
  if stream == 'FROMFUZZ':
    return True

  return False


def create_object_wrapper(**methods):
  """Hooks functions in an object.

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

  class Wrapper():
    """Wrap an object by hiding attributes."""

    def __init__(self, instance):
      object.__setattr__(self, 'instance', instance)

    def __setattr__(self, name, value):
      object.__setattr__(object.__getattribute__(self, 'instance'), name, value)

    def __getattribute__(self, name):
      instance = object.__getattribute__(self, 'instance')

      def _hook_func(self, pre_hook, post_hook, orig, *args, **kargs):
        if pre_hook is not None:
          pre_hook(self, *args, **kargs)
        # No need to pass instance here because when we extracted
        # the function we used instance.__getattribute__(name) which
        # seems to include it. I think.
        orig_retval = orig(*args, **kargs)

        if post_hook is not None:
          post_hook(self, *args, **kargs)
        return orig_retval

      # If this is a wrapped method, return a bound method
      if name in methods:
        pre_hook = methods[name][0]
        post_hook = methods[name][1]
        orig = instance.__getattribute__(name)
        return (lambda *args, **kargs: _hook_func(self, pre_hook, post_hook,
                                                  orig, *args, **kargs))

      # Otherwise, just return attribute of instance
      return instance.__getattribute__(name)

  return Wrapper


def add_hook(function: Callable[[Any], Any],
             pre_exec_hook: Optional[Callable[[Any], Any]] = None,
             post_exec_hook: Optional[Callable[[Any], Any]] = None):
  """Hook a function.

    Hooks can be placed pre and post function call. At least one hook is
    needed.

    This hooking is intended on non-object hooks. In order to hook functions
    in objects the `create_object_wrapper` function is used in combination
    with function hooking initialisation functions post execution.
    """
  if pre_exec_hook is None and post_exec_hook is None:
    raise Exception('Some hooks must be included')

  @functools.wraps(function)
  def run(*args, **kwargs):
    sanitizer_log(f'Hook start {str(function)}', LOG_DEBUG)

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
        sanitizer_log('Overwriting return value', LOG_DEBUG)
        ret = tmp_ret
    sanitizer_log(f'Hook end {str(function)}', LOG_DEBUG)
    return ret

  return run


def add_hooks():
  """Sets up hooks."""
  sanitizer_log('Starting', LOG_INFO)
  os.system = add_hook(os.system,
                       pre_exec_hook=command_injection.hook_pre_exec_os_system)
  subprocess.Popen = add_hook(
      subprocess.Popen,
      pre_exec_hook=command_injection.hook_pre_exec_subprocess_Popen)

  __builtins__['eval'] = add_hook(
      __builtins__['eval'], pre_exec_hook=command_injection.hook_pre_exec_eval)

  re.compile = add_hook(re.compile,
                        pre_exec_hook=redos.hook_pre_exec_re_compile,
                        post_exec_hook=redos.hook_post_exec_re_compile)

  # Hack to determine if yaml is elligible, because pkg_resources does
  # not seem to work from pyinstaller.
  # pylint: disable=import-outside-toplevel
  if is_module_present('yaml'):
    import yaml
    sanitizer_log('Hooking pyyaml.load', LOG_DEBUG)
    yaml.load = add_hook(
        yaml.load,
        pre_exec_hook=yaml_deserialization.hook_pre_exec_pyyaml_load,
    )
