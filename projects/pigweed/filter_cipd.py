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

import argparse
import json
import os
import sys


def parse_args():
  parser = argparse.ArgumentParser()
  parser.add_argument('--root', default=os.path.join(os.getcwd(), 'pigweed'))
  parser.add_argument(
      '--json', default='pw_env_setup/py/pw_env_setup/cipd_setup/pigweed.json')
  parser.add_argument('--excludes', default='clang', nargs='*')
  return parser.parse_args()


def load_prebuilts(jsonfile):
  try:
    with open(jsonfile, 'r') as f:
      return json.load(f)
  except:
    print('Encountered error attempting to load ' + jsonfile)
    raise


def filter_prebuilts(prebuilts, excludes):
  for exclude in excludes:
    prebuilts[:] = [p for p in prebuilts if exclude not in str(p['path'])]
  return prebuilts


def dump_prebuilts(prebuilts, jsonfile):
  try:
    os.rename(jsonfile, jsonfile + '.orig')
  except:
    print('Encountered error attempting to rename ' + jsonfile)
    raise
  try:
    with open(jsonfile, 'w') as f:
      json.dump(prebuilts, f, indent=2)
  except:
    print('Encountered error attempting to write ' + jsonfile)
    raise


def main():
  args = parse_args()
  jsonfile = os.path.join(args.root, args.json)
  prebuilts = load_prebuilts(jsonfile)
  filter_prebuilts(prebuilts, args.excludes)
  dump_prebuilts(prebuilts, jsonfile)
  return 0


if __name__ == '__main__':
  sys.exit(main())
