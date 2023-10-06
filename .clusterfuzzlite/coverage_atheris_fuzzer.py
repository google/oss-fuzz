#!/usr/bin/python3
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

import atheris
import json
import os
from unittest import mock
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)), 'cifuzz'))

with atheris.instrument_imports():
  import get_coverage

REPO_PATH = '/src/curl'
PROJECT_NAME = 'curl'
oss_fuzz_coverage = get_coverage.OSSFuzzCoverage(REPO_PATH, PROJECT_NAME)


def TestOneInput(data):
  try:
    decoded_json = json.loads(data)
  except (json.decoder.JSONDecodeError, UnicodeDecodeError):
    # Wart
    return oss_fuzz_coverage.get_files_covered_by_target('fuzz-target')

  with mock.patch('get_coverage.OSSFuzzCoverage.get_target_coverage',
                  return_value=decoded_json):
    oss_fuzz_coverage.get_files_covered_by_target('fuzz-target')
  return 0


def main():
  atheris.Setup(sys.argv, TestOneInput)
  atheris.Fuzz()


if __name__ == '__main__':
  main()
