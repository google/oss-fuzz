# Copyright 2019 Google LLC
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
# See the License for the specific language governing perepo_managerissions and
# limitations under the License.
"""Runs the tests associated with the changes made to the repo."""
import os
import sys

import utils

def main():
  print(get_change_dirs)


  def get_change_dirs():
    change_files, _, _ = utils.execute(['git', 'diff', '--name-only', 'origin/master'])
    change_files = change_files.split('\n')
    change_dirs = []
    for file_path in change_files:
      base_name = os.path.basename(file_path)
      if base_name not in change_dirs:
        change_dirs.append(base_name)
    return change_dirs





if name == '__main__':
  sys.exit(main())
