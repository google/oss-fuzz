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
"""Extracts file paths to copy files from pyinstaller-generated executables"""
import os
import sys
import shutil
import zipfile


# Finds all *.toc files in ./workpath and reads these files in order to
# identify Python files associated with a pyinstaller packaged executable.
# Copies all of the Python files to a temporary directory (/medio) following
# the original directory structure.
def get_all_files_from_toc(toc_file, file_path_set):
  """
  Extract filepaths from a .toc file and add to file_path_set
  """
  with open(toc_file, 'rb') as toc_file_fd:
    for line in toc_file_fd:
      try:
        line = line.decode()
      except:  # pylint:disable=bare-except
        continue
      if '.py' not in line:
        continue

      split_line = line.split(' ')
      for word in split_line:
        word = word.replace('\'', '').replace(',', '').replace('\n', '')
        if '.py' not in word:
          continue
        # Check if .egg is in the path and if so we need to split it
        if os.path.isfile(word):
          file_path_set.add(word)
        elif '.egg' in word:  # check if this is an egg
          egg_path_split = word.split('.egg')
          if len(egg_path_split) != 2:
            continue
          egg_path = egg_path_split[0] + '.egg'
          if not os.path.isfile(egg_path):
            continue

          print('Unzipping contents of %s' % egg_path)

          # We have an egg. This needs to be unzipped and then replaced
          # with the unzipped data.
          tmp_dir_name = 'zipdcontents'
          if os.path.isdir(tmp_dir_name):
            shutil.rmtree(tmp_dir_name)

          # unzip egg and replace path with unzipped content
          with zipfile.ZipFile(egg_path, 'r') as zip_f:
            zip_f.extractall(tmp_dir_name)
          os.remove(egg_path)
          shutil.copytree(tmp_dir_name, egg_path)

          # Now the lines should be accessible, so check again
          if os.path.isfile(word):
            file_path_set.add(word)


def create_file_structure_from_tocs(work_path, out_path):
  """
  Extract the Python files that are added as paths in the output of
  a pyinstaller operation. The files are determined by reading through
  all of the *.toc files in the workpath of pyinstaller.

  The files will be copied into the out_path using a similar file path
  as they originally are. If any archive (.egg) files are present in the
  .toc files, then unzip the archives and substitute the archive for the
  unzipped content, i.e. we will extract the archives and collect the source
  files.
  """
  print('Extracts files from the pyinstaller workpath')
  file_path_set = set()
  for path1 in os.listdir(work_path):
    full_path = os.path.join(work_path, path1)
    if not os.path.isdir(full_path):
      continue

    # We have a directory
    for path2 in os.listdir(full_path):
      if not '.toc' in path2:
        continue
      full_toc_file = os.path.join(full_path, path2)
      get_all_files_from_toc(full_toc_file, file_path_set)

  for file_path in file_path_set:
    relative_src = file_path[1:] if file_path[0] == '/' else file_path
    dst_path = os.path.join(out_path, relative_src)
    os.makedirs(os.path.dirname(dst_path), exist_ok=True)
    shutil.copy(file_path, dst_path)


def main():
  """
  Main handler.
  """
  if len(sys.argv) != 3:
    print('Use: python3 python_coverage_helper.py pyinstaller_workpath '
          'destination_for_output')
    sys.exit(1)
  work_path = sys.argv[1]
  out_path = sys.argv[2]
  create_file_structure_from_tocs(work_path, out_path)


if __name__ == '__main__':
  main()
