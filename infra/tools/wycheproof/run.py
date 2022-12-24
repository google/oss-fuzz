#!/usr/bin/env python3
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
"""Script for creating "testcases" to run wycheproof on."""

import argparse
import os
import sys


def get_args():
  """Returns parsed program arguments."""
  parser = argparse.ArgumentParser()
  parser.add_argument(
      '--input_dir',
      help='Ignored.',
  )
  parser.add_argument('--output_dir',
                      help='Directory for writing testcases.',
                      required=True)
  parser.add_argument('--no_of_files', type=int, help='Ignored.')
  return parser.parse_args()


def main():
  """Generates a dummy testcase for use by a ClusterFuzz blackbox fuzzer."""
  args = get_args()
  if not os.path.exists(args.output_dir):
    os.mkdir(args.output_dir)
  testcase = os.path.join(args.output_dir, 'fuzz-0')
  with open(testcase, 'w') as file_handle:
    file_handle.write(' ')
  return 0


if __name__ == '__main__':
  sys.exit(main())
