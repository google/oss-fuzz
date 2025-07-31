#!/bin/bash -eux
# Copyright 2025 Google LLC.
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
###############################################################################
"""Module for extracting coverage data from a run of run_tests.sh"""

import os
import shutil
import subprocess

COV_WORKDIR = '/tmp/cov-dumps'


def collect_coverage_profraw_files():
  """Finds profraw files in the most likely places in the OSS-Fuzz build
    container and copies them to the COV_WORKDIR."""
  rootdir = '/src/'
  for subdir, _, files in os.walk(rootdir):
    for file in files:
      if file.endswith('.profraw'):
        print(os.path.join(subdir, file))
        dst_name = os.path.join(subdir, file).replace('/', '_')
        shutil.copy(os.path.join(subdir, file), f'{COV_WORKDIR}/{dst_name}')


def find_all_executables():
  """Finds all executables that are likely to be run with coverage
  collection."""
  rootdir = '/src/'
  objects_string = ''
  for subdir, _, files in os.walk(rootdir):
    if any(avoid_dir in subdir for avoid_dir in
           ['aflplusplus', 'fuzztest', 'honggfuzz', 'libfuzzer', '.git']):
      continue
    for file in files:
      abs_file = os.path.join(subdir, file)

      if os.access(abs_file, os.X_OK):

        # Ensure it's an ELF
        with open(abs_file, 'rb') as binf:
          magic_bytes = binf.read(4)
        if len(magic_bytes) != 4:
          continue

        is_elf = True
        if magic_bytes[0] != 0x7f:
          is_elf = False
        if magic_bytes[1] != 0x45:
          is_elf = False
        if magic_bytes[2] != 0x4c:
          is_elf = False
        if magic_bytes[3] != 0x46:
          is_elf = False
        if not is_elf:
          continue

        dst_name = f'{COV_WORKDIR}/{file}'
        if not objects_string:
          objects_string = abs_file + ' '
        else:
          objects_string += f'-object {dst_name} '
        shutil.copy(abs_file, dst_name)
  print('Found the following executables for coverage extraction:')
  print(objects_string)
  return objects_string


def run_llvm_html_generation(objects, out_dir, workdir=COV_WORKDIR):
  """Generates HTML coverage report from profraw files."""
  prof_raws = ''
  instr_profile = os.path.join(workdir, 'merged_profdata.profdata')

  for file in os.listdir(workdir):
    if file.endswith('.profraw'):
      prof_raws += os.path.join(workdir, file) + ' '
  cmd = [
      'llvm-profdata', 'merge', '-j=1', '-sparse', prof_raws, '-o',
      instr_profile
  ]
  subprocess.check_call(' '.join(cmd), shell=True)

  # Extract HTML report
  cmd = [
      'llvm-cov', 'show', '-format=html', f'-output-dir={out_dir}',
      f'-instr-profile={instr_profile}', objects
  ]

  subprocess.check_call(' '.join(cmd), shell=True)

  # Extract json report
  cmd = [
      'llvm-cov',
      'export',
      '-summary-only',
      f'-instr-profile={instr_profile}',
      objects,
  ]
  stdout_fp = open(os.path.join(out_dir, 'summary.json'), 'w')
  subprocess.check_call(' '.join(cmd), shell=True, stdout=stdout_fp)
  stdout_fp.close()


def reset_cov_workdir():
  """Resets the coverage work directory."""
  if os.path.exists(COV_WORKDIR):
    shutil.rmtree(COV_WORKDIR, ignore_errors=True)
  os.mkdir(COV_WORKDIR)


def main():
  """Main function to run the coverage test collection."""
  reset_cov_workdir()
  collect_coverage_profraw_files()
  obj_string = find_all_executables()

  run_llvm_html_generation(obj_string, '/out/test-html-generation')


if __name__ == '__main__':
  main()
