#!/usr/bin/env python3
# Copyright 2020 Google LLC
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
"""Does bad_build_check on all fuzz targets in $OUT."""

import multiprocessing
import os
import re
import shutil
import subprocess
import stat
import sys

TMP_FUZZER_DIR = '/tmp/not-out'

EXECUTABLE = stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH


def recreate_directory(directory):
  """Creates |directory|. If it already exists than deletes it first before
  creating."""
  if os.path.exists(directory):
    shutil.rmtree(directory)
  os.mkdir(directory)


def move_directory_contents(src_directory, dst_directory):
  """Moves contents of |src_directory| to |dst_directory|."""
  src_files = os.listdir(src_directory)
  for filename in src_files:
    src_path = os.path.join(src_directory, filename)
    shutil.move(src_path, dst_directory)


def find_fuzz_targets(directory):
  """Returns paths to fuzz targets in |directory|."""
  fuzzing_language = os.getenv('FUZZING_LANGUAGE')
  fuzz_targets = []
  for filename in os.listdir(directory):
    path = os.path.join(directory, filename)
    if filename.startswith('afl-'):
      continue
    if not os.path.isfile(path):
      continue
    if not os.stat(path).st_mode & EXECUTABLE:
      continue
    with open(path, 'rb') as file_handle:
      binary = file_handle.read()
      if b'LLVMFuzzerTestOneInput' not in binary:
        continue
      if fuzzing_language != 'python' and b'ELF' not in binary:
        continue
    fuzz_targets.append(path)
  return fuzz_targets


def do_bad_build_check(fuzz_target):
  """Runs bad_build_check on |fuzz_target|. Returns a
  Subprocess.ProcessResult."""
  print('INFO: performing bad build checks for', fuzz_target)
  command = ['bad_build_check', fuzz_target]
  return subprocess.run(command,
                        stderr=subprocess.PIPE,
                        stdout=subprocess.PIPE,
                        check=False)


def get_broken_fuzz_targets(bad_build_results, fuzz_targets):
  """Returns a list of broken fuzz targets and their process results in
  |fuzz_targets| where each item in |bad_build_results| is the result of
  bad_build_check on the corresponding element in |fuzz_targets|."""
  broken = []
  for result, fuzz_target in zip(bad_build_results, fuzz_targets):
    if result.returncode != 0:
      broken.append((fuzz_target, result))
  return broken


def has_ignored_targets(out_dir):
  """Returns True if |out_dir| has any fuzz targets we are supposed to ignore
  bad build checks of."""
  out_files = set(os.listdir(out_dir))
  ignored_targets = {
      'do_stuff_fuzzer'
      'checksum_fuzzer', 'fuzz_dump', 'fuzz_keyring', 'xmltest',
      'fuzz_compression_sas_rle'
  }
  if out_files.intersection(ignored_targets):
    return True
  for filename in out_files:
    if re.match(r'ares_*_fuzzer', filename):
      return True
  return False


def test_all(pool, out, initial_out):
  """Do bad_build_check on all fuzz targets."""
  # TODO(metzman): Refactor so that we can conver test_one to python.
  # Use a fake OUT directory to catch path hardcoding that breaks on
  # ClusterFuzz.
  recreate_directory(TMP_FUZZER_DIR)
  try:
    # Set this so that run_fuzzer which is called by bad_build_check works
    # properly.
    move_directory_contents(initial_out, out)
    fuzz_targets = find_fuzz_targets(out)
    bad_build_results = pool.map(do_bad_build_check, fuzz_targets)
  finally:
    move_directory_contents(out, initial_out)
    out = initial_out

  broken_targets = get_broken_fuzz_targets(bad_build_results, fuzz_targets)
  broken_targets_count = len(broken_targets)
  if not broken_targets_count:
    return True

  print('Broken fuzz targets ', broken_targets_count)
  total_targets_count = len(fuzz_targets)
  broken_targets_percentage = 100 * broken_targets_count / total_targets_count
  for broken_target, result in broken_targets:
    print(broken_target)
    sys.stdout.buffer.write(result.stdout + result.stderr + '\n')

  allowed_broken_targets_percentage = int(
      os.getenv('ALLOWED_BROKEN_TARGETS_PERCENTAGE', '10'))
  if broken_targets_percentage > allowed_broken_targets_percentage:
    print('ERROR: {broken_targets_percentage}% of fuzz targets seem to be '
          'broken. See the list above for a detailed information.'.format(
              broken_targets_percentage=broken_targets_percentage))
    if has_ignored_targets(out):
      return True
    return False
  print('{total_targets_count} fuzzers total, {broken_targets_count} '
        'seem to be broken ({broken_targets_percentage}%).'.format(
            total_targets_count=total_targets_count,
            broken_targets_count=broken_targets_count,
            broken_targets_percentage=broken_targets_percentage))
  return True


def change_out_to_tmp_fuzzer_dir():
  """Changes $OUT to TMP_FUZZER_DIR and returns the initial value of $OUT and
  the new value of $OUT."""
  out = os.getenv('OUT')
  initial_out = out
  out = TMP_FUZZER_DIR
  os.environ['OUT'] = TMP_FUZZER_DIR
  return out, initial_out


def main():
  """Does bad_build_check on all fuzz targets in parallel. Returns 0 on success.
  Returns 1 on failure."""
  # Set these environment variables here so that stdout
  out, initial_out = change_out_to_tmp_fuzzer_dir()
  pool = multiprocessing.Pool()
  if not test_all(pool, out, initial_out):
    return 1
  return 0


if __name__ == '__main__':
  sys.exit(main())
