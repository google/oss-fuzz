#!/usr/bin/env python
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
"""Script for running wycheproof."""

import logging
import sys
import subprocess


def main():
  """Runs wycheproof."""
  if len(sys.argv) < 3:
    logging.error('Usage: %s <test_app> <testcase>.', sys.argv[0])
    return 1

  return subprocess.run(sys.argv[1:], check=False).returncode


if __name__ == '__main__':
  sys.exit(main())
