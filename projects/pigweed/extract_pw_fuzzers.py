#!/usr/bin/env python

# Copyright 2020 Google Inc.
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
"""Script to find fuzzers in a Pigweed build."""

import argparse
import json
import os
import shutil
import sys


def main():
  """ Use pw_module_tests.testinfo.json files to find and copy fuzzers. """
  parser = argparse.ArgumentParser()
  parser.add_argument('--buildroot')
  parser.add_argument('--out')
  args = parser.parse_args()
  print('  buildroot: ' + args.buildroot)
  print('        out: ' + args.out)

  testinfo = os.path.join(args.buildroot, 'host_clang_fuzz',
                          'obj',
                          'pw_module_tests.testinfo.json')
  tests = []
  with open(testinfo) as json_file:
    tests = json.load(json_file)
  for test in tests:
    if test['type'] != 'fuzzer':
      # Skip unit tests
      continue
    fuzzer = test['test_name']
    objdir = test['test_directory']
    module = os.path.basename(os.path.dirname(objdir))
    if module == 'pw_fuzzer':
      # Skip examples
      continue
    src = os.path.join(args.buildroot, objdir, fuzzer)
    dst = os.path.join(args.out, '{}_{}'.format(module, fuzzer))
    print('Copying {} to {}'.format(src, dst))
    shutil.copy(src, dst)
  return 0


if __name__ == '__main__':
  sys.exit(main())
