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
"""
Helper to manage coverage.py related operations. Does two main
things: (1) pass commands into the coverage.py library and (2)
translate .coverage created from a pyinstaller executable into
paths that match local files. This is needed for html report creation.
"""
import os
import re
import sys
from coverage.cmdline import main as coverage_main
from coverage.data import CoverageData


def translate_lines(cov_data, new_cov_data, all_file_paths):
  """
  Translate lines in a .coverage file created by coverage.py such that
  the file paths points to local files instead. This is needed when collecting
  coverage from executables created by pyinstaller.
  """
  for pyinstaller_file_path in cov_data.measured_files():
    stripped_py_file_path = pyinstaller_file_path
    if stripped_py_file_path.startswith('/tmp/_MEI'):
      stripped_py_file_path = '/'.join(stripped_py_file_path.split('/')[3:])
    if stripped_py_file_path.startswith('/out/'):
      stripped_py_file_path = stripped_py_file_path.replace('/out/', '')

    # Check if this file exists in our file paths:
    for local_file_path in all_file_paths:
      if local_file_path.endswith(stripped_py_file_path):
        print('Found matching: %s' % (local_file_path))
        new_cov_data.add_lines(
            {local_file_path: cov_data.lines(pyinstaller_file_path)})


def translate_coverage(all_file_paths):
  """
  Translate pyinstaller-generated file paths in .coverage (produced by
  coverage.py) into local file paths. Place result in .new_coverage.
  """
  covdata_pre_translation = CoverageData('.coverage')
  covdata_post_translation = CoverageData('.new_coverage')

  covdata_pre_translation.read()
  translate_lines(covdata_pre_translation, covdata_post_translation,
                  all_file_paths)
  covdata_post_translation.write()


def main():
  """
  Main handler.
  """
  if sys.argv[1] == 'translate':
    print('Translating the coverage')
    files_path = sys.argv[2]
    all_file_paths = list()
    for root, _, files in os.walk(files_path):
      for relative_file_path in files:
        abs_file_path = os.path.abspath(os.path.join(root, relative_file_path))
        all_file_paths.append(abs_file_path)
    print('Done with path walk')
    translate_coverage(all_file_paths)
  else:
    # Pass commands into coverage package
    sys.argv[0] = re.sub(r'(-script\.pyw|\.exe)?$', '', sys.argv[0])
    sys.exit(coverage_main())


if __name__ == '__main__':
  main()
