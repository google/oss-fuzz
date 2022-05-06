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
"""Script for filter Pigweed's CIPD dependencies for OSS Fuzz conflicts."""

import argparse
import json
import os
import sys


def main():
  """Main entry point of the script."""
  parser = argparse.ArgumentParser()
  parser.add_argument('--root', default=os.path.join(os.getcwd(), 'pigweed'))
  parser.add_argument(
      '--json', default='pw_env_setup/py/pw_env_setup/cipd_setup/pigweed.json')
  parser.add_argument('--excludes', default='clang', nargs='*')
  args = parser.parse_args()

  # Load args.json
  cipd_json = {}
  try:
    with open(args.json, 'r') as json_file:
      cipd_json = json.load(json_file)
  except Exception:
    print('Encountered error attempting to load ' + args.json)
    raise

  packages = cipd_json['packages']

  # Filter out args.excludes
  for exclude in args.excludes:
    packages[:] = [p for p in packages if exclude not in str(p['path'])]

  cipd_json['packages'] = packages

  # Rename original CIPD JSON file
  try:
    os.rename(args.json, args.json + '.orig')
  except Exception:
    print('Encountered error attempting to rename ' + args.json)
    raise

  # Save new CIPD JSON file
  try:
    with open(args.json, 'w') as json_file:
      json.dump(cipd_json, json_file, indent=2)
  except Exception:
    print('Encountered error attempting to write ' + args.json)
    raise

  return 0


if __name__ == '__main__':
  sys.exit(main())
