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

import contextlib
import multiprocessing
import os
import re
import subprocess
import stat
import sys
import tempfile

BASE_TMP_FUZZER_DIR = '/tmp/not-out'

EXECUTABLE = stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH

IGNORED_TARGETS = [
    r'do_stuff_fuzzer', r'checksum_fuzzer', r'fuzz_dump', r'fuzz_keyring',
    r'xmltest', r'fuzz_compression_sas_rle', r'ares_*_fuzzer'
]

IGNORED_TARGETS_RE = re.compile('^' + r'$|^'.join(IGNORED_TARGETS) + '$')


def move_directory_contents(src_directory, dst_directory):
  """Moves contents of |src_directory| to |dst_directory|."""
  # Use mv because mv preserves file permissions. If we don't preserve file
  # permissions that can mess up CheckFuzzerBuildTest in cifuzz_test.py and
  # other cases where one is calling test_all on files not in OSS-Fuzz's real
  # out directory.
  src_contents = [
      os.path.join(src_directory, filename)
      for filename in os.listdir(src_directory)
  ]
  command = ['mv'] + src_contents + [dst_directory]
  subprocess.check_call(command)


def is_elf(filepath):
  """Returns True if |filepath| is an ELF file."""
  result = subprocess.run(['file', filepath],
                          stdout=subprocess.PIPE,
                          check=False)
  return b'ELF' in result.stdout


def is_shell_script(filepath):
  """Returns True if |filepath| is a shell script."""
  result = subprocess.run(['file', filepath],
                          stdout=subprocess.PIPE,
                          check=False)
  return b'shell script' in result.stdout


def find_fuzz_targets(directory):
  """Returns paths to fuzz targets in |directory|."""
  # TODO(https://github.com/google/oss-fuzz/issues/4585): Use libClusterFuzz for
  # this.
  fuzz_targets = []
  for filename in os.listdir(directory):
    path = os.path.join(directory, filename)
    if filename == 'llvm-symbolizer':
      continue
    if filename.startswith('afl-'):
      continue
    if filename.startswith('jazzer_'):
      continue
    if not os.path.isfile(path):
      continue
    if not os.stat(path).st_mode & EXECUTABLE:
      continue
    # Fuzz targets can either be ELF binaries or shell scripts (e.g. wrapper
    # scripts for Python and JVM targets or rules_fuzzing builds with runfiles
    # trees).
    if not is_elf(path) and not is_shell_script(path):
      continue
    if os.getenv('FUZZING_ENGINE') not in {'none', 'wycheproof'}:
      with open(path, 'rb') as file_handle:
        binary_contents = file_handle.read()
        if b'LLVMFuzzerTestOneInput' not in binary_contents:
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
  for filename in out_files:
    if re.match(IGNORED_TARGETS_RE, filename):
      return True
  return False


@contextlib.contextmanager
def use_different_out_dir():
  """Context manager that moves OUT to subdirectory of BASE_TMP_FUZZER_DIR. This
  is useful for catching hardcoding. Note that this sets the environment
  variable OUT and therefore must be run before multiprocessing.Pool is created.
  Resets OUT at the end."""
  # Use a fake OUT directory to catch path hardcoding that breaks on
  # ClusterFuzz.
  initial_out = os.getenv('OUT')
  os.makedirs(BASE_TMP_FUZZER_DIR, exist_ok=True)
  # Use a random subdirectory of BASE_TMP_FUZZER_DIR to allow running multiple
  # instances of test_all in parallel (useful for integration testing).
  with tempfile.TemporaryDirectory(dir=BASE_TMP_FUZZER_DIR) as out:
    # Set this so that run_fuzzer which is called by bad_build_check works
    # properly.
    os.environ['OUT'] = out
    # We move the contents of the directory because we can't move the
    # directory itself because it is a mount.
    move_directory_contents(initial_out, out)
    try:
      yield out
    finally:
      move_directory_contents(out, initial_out)
      os.environ['OUT'] = initial_out


def test_all_outside_out(allowed_broken_targets_percentage):
  """Wrapper around test_all that changes OUT and returns the result."""
  with use_different_out_dir() as out:
    return test_all(out, allowed_broken_targets_percentage)


def test_all(out, allowed_broken_targets_percentage):
  """Do bad_build_check on all fuzz targets."""
  # TODO(metzman): Refactor so that we can convert test_one to python.
  fuzz_targets = find_fuzz_targets(out)
  if not fuzz_targets:
    print('ERROR: No fuzz targets found.')
    return False

  pool = multiprocessing.Pool()
  bad_build_results = pool.map(do_bad_build_check, fuzz_targets)
  pool.close()
  pool.join()
  broken_targets = get_broken_fuzz_targets(bad_build_results, fuzz_targets)
  broken_targets_count = len(broken_targets)
  if not broken_targets_count:
    return True

  print('Retrying failed fuzz targets sequentially', broken_targets_count)
  pool = multiprocessing.Pool(1)
  retry_targets = []
  for broken_target, result in broken_targets:
    retry_targets.append(broken_target)
  bad_build_results = pool.map(do_bad_build_check, retry_targets)
  pool.close()
  pool.join()
  broken_targets = get_broken_fuzz_targets(bad_build_results, broken_targets)
  broken_targets_count = len(broken_targets)
  if not broken_targets_count:
    return True

  print('Broken fuzz targets', broken_targets_count)
  total_targets_count = len(fuzz_targets)
  broken_targets_percentage = 100 * broken_targets_count / total_targets_count
  for broken_target, result in broken_targets:
    print(broken_target)
    # Use write because we can't print binary strings.
    sys.stdout.buffer.write(result.stdout + result.stderr + b'\n')

  if broken_targets_percentage > allowed_broken_targets_percentage:
    print('ERROR: {broken_targets_percentage}% of fuzz targets seem to be '
          'broken. See the list above for a detailed information.'.format(
              broken_targets_percentage=broken_targets_percentage))
    if has_ignored_targets(out):
      print('Build check automatically passing because of ignored targets.')
      return True
    return False
  print('{total_targets_count} fuzzers total, {broken_targets_count} '
        'seem to be broken ({broken_targets_percentage}%).'.format(
            total_targets_count=total_targets_count,
            broken_targets_count=broken_targets_count,
            broken_targets_percentage=broken_targets_percentage))
  return True


def get_allowed_broken_targets_percentage():
  """Returns the value of the environment value
  'ALLOWED_BROKEN_TARGETS_PERCENTAGE' as an int or returns a reasonable
  default."""
  return int(os.getenv('ALLOWED_BROKEN_TARGETS_PERCENTAGE') or '10')


def main():
  """Does bad_build_check on all fuzz targets in parallel. Returns 0 on success.
  Returns 1 on failure."""
  allowed_broken_targets_percentage = get_allowed_broken_targets_percentage()
  if not test_all_outside_out(allowed_broken_targets_percentage):
    return 1
  return 0


if __name__ == '__main__':
  sys.exit(main())
