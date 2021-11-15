# Copyright 2020 Google LLC
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
"""Retry decorator. Copied from ClusterFuzz source."""

import functools
import inspect
import logging
import sys
import time

# pylint: disable=too-many-arguments,broad-except


def sleep(seconds):
  """Invoke time.sleep. This is to avoid the flakiness of time.sleep. See:
    crbug.com/770375"""
  time.sleep(seconds)


def get_delay(num_try, delay, backoff):
  """Compute backoff delay."""
  return delay * (backoff**(num_try - 1))


def wrap(retries,
         delay,
         backoff=2,
         exception_type=Exception,
         retry_on_false=False):
  """Retry decorator for a function."""

  assert delay > 0
  assert backoff >= 1
  assert retries >= 0

  def decorator(func):
    """Decorator for the given function."""
    tries = retries + 1
    is_generator = inspect.isgeneratorfunction(func)
    function_with_type = func.__qualname__
    if is_generator:
      function_with_type += ' (generator)'

    def handle_retry(num_try, exception=None):
      """Handle retry."""
      if (exception is None or
          isinstance(exception, exception_type)) and num_try < tries:
        logging.info('Retrying on %s failed with %s. Retrying again.',
                     function_with_type,
                     sys.exc_info()[1])
        sleep(get_delay(num_try, delay, backoff))
        return True

      logging.error('Retrying on %s failed with %s. Raise.', function_with_type,
                    sys.exc_info()[1])
      return False

    @functools.wraps(func)
    def _wrapper(*args, **kwargs):
      """Regular function wrapper."""
      for num_try in range(1, tries + 1):
        try:
          result = func(*args, **kwargs)
          if retry_on_false and not result:
            if not handle_retry(num_try):
              return result

            continue
          return result
        except Exception as error:
          if not handle_retry(num_try, exception=error):
            raise

    @functools.wraps(func)
    def _generator_wrapper(*args, **kwargs):
      """Generator function wrapper."""
      # This argument is not applicable for generator functions.
      assert not retry_on_false
      already_yielded_element_count = 0
      for num_try in range(1, tries + 1):
        try:
          for index, result in enumerate(func(*args, **kwargs)):
            if index >= already_yielded_element_count:
              yield result
              already_yielded_element_count += 1
          break
        except Exception as error:
          if not handle_retry(num_try, exception=error):
            raise

    if is_generator:
      return _generator_wrapper
    return _wrapper

  return decorator
