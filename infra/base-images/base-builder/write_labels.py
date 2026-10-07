#!/usr/bin/env python3
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
"""Script for writing from project.yaml to .labels file."""

import os
import json
import sys


def main():
  """Writes labels."""
  if len(sys.argv) != 3:
    print('Usage: write_labels.py labels_json out_dir', file=sys.stderr)
    sys.exit(1)

  labels_by_target = json.loads(sys.argv[1])
  out = sys.argv[2]

  for target_name, labels in labels_by_target.items():
    # Skip over wildcard value applying to all fuzz targets
    if target_name == '*':
      continue
    with open(os.path.join(out, target_name + '.labels'), 'w') as file_handle:
      file_handle.write('\n'.join(labels))


if __name__ == '__main__':
  main()
