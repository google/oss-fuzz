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
"""Log helpers."""

import logging
import os


class FuzzerOutputFormatter(logging.Formatter):
  """Includes structured engine output in console logs."""

  def format(self, record):
    message = super().format(record)
    output = getattr(record, 'extras', {}).get('fuzzer_output')
    if output:
      message += '\n' + output
    return message


def init():
  """Initialize logging."""
  log_level = logging.DEBUG if os.getenv('CIFUZZ_DEBUG') else logging.INFO
  handler = logging.StreamHandler()
  handler.setFormatter(
      FuzzerOutputFormatter(
          '%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
  logging.basicConfig(handlers=[handler], level=log_level)
