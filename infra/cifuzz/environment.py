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
"""Module for dealing with env vars."""

import ast
import os


def _eval_value(value_string):
  """Returns evaluated value."""
  try:
    return ast.literal_eval(value_string)
  except:  # pylint: disable=bare-except
    # String fallback.
    return value_string


def get(env_var, default_value=None):
  """Returns an environment variable value."""
  value_string = os.getenv(env_var)
  if value_string is None:
    return default_value

  return _eval_value(value_string)


def get_bool(env_var, default_value=None):
  """Returns a boolean environment variable value. This is needed because a lot
  of CIFuzz users specified 'false' for dry-run. So we need to special case
  this."""
  value = get(env_var, default_value)
  if not isinstance(value, str):
    return bool(value)

  lower_value = value.lower()
  allowed_values = {'true', 'false'}
  if lower_value not in allowed_values:
    raise Exception(f'Bool env var {env_var} value {value} is invalid. '
                    f'Must be one of {allowed_values}.')
  return lower_value == 'true'
