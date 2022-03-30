#!/usr/bin/env python3
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
"""Script for collecting dataflow traces using DFSan compiled binary. The script
imitates `CollectDataFlow` function from libFuzzer but provides some flexibility
for skipping long and/or slow corpus elements.

Follow https://github.com/google/oss-fuzz/issues/1632 for more details."""
import hashlib
import os
import subprocess
import sys

# pylint: skip-file

# See https://github.com/google/oss-fuzz/pull/5024#discussion_r561313003 for why
# we are disabling pylint for this file (we can't do it in .pylintrc, probably
# because of weirdness with this file's package, so we do it here).

# These can be controlled by the runner in order to change the values without
# rebuilding OSS-Fuzz base images.
FILE_SIZE_LIMIT = int(os.getenv('DFT_FILE_SIZE_LIMIT', 32 * 1024))
MIN_TIMEOUT = float(os.getenv('DFT_MIN_TIMEOUT', 1.0))
TIMEOUT_RANGE = float(os.getenv('DFT_TIMEOUT_RANGE', 3.0))

DFSAN_OPTIONS = 'fast16labels=1:warn_unimplemented=0'


def _error(msg):
  sys.stderr.write(msg + '\n')


def _list_dir(dirpath):
  for root, _, files in os.walk(dirpath):
    for f in files:
      yield os.path.join(root, f)


def _sha1(filepath):
  h = hashlib.sha1()
  with open(filepath, 'rb') as f:
    h.update(f.read())
  return h.hexdigest()


def _run(cmd, timeout=None):
  result = None
  try:
    result = subprocess.run(cmd,
                            timeout=timeout,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)
    if result.returncode:
      _error('{command} finished with non-zero code: {code}'.format(
          command=str(cmd), code=result.returncode))

  except subprocess.TimeoutExpired:
    raise
  except Exception as e:
    _error('Exception: ' + str(e))

  return result


def _timeout(size):
  # Dynamic timeout value (proportional to file size) to discard slow units.
  timeout = MIN_TIMEOUT
  timeout += size * TIMEOUT_RANGE / FILE_SIZE_LIMIT
  return timeout


def collect_traces(binary, corpus_dir, dft_dir):
  stats = {
      'total': 0,
      'traced': 0,
      'long': 0,
      'slow': 0,
      'failed': 0,
  }

  files_and_sizes = {}
  for f in _list_dir(corpus_dir):
    stats['total'] += 1
    size = os.path.getsize(f)
    if size > FILE_SIZE_LIMIT:
      stats['long'] += 1
      print('Skipping large file ({size}b): {path}'.format(size=size, path=f))
      continue
    files_and_sizes[f] = size

  for f in sorted(files_and_sizes, key=files_and_sizes.get):
    output_path = os.path.join(dft_dir, _sha1(f))
    try:
      result = _run([binary, f, output_path], timeout=_timeout(size))
      if result.returncode:
        stats['failed'] += 1
      else:
        stats['traced'] += 1

    except subprocess.TimeoutExpired as e:
      _error('Slow input: ' + str(e))
      stats['slow'] += 1

  return stats


def dump_functions(binary, dft_dir):
  result = _run([binary])
  if not result or result.returncode:
    return False

  with open(os.path.join(dft_dir, 'functions.txt'), 'wb') as f:
    f.write(result.stdout)

  return True


def main():
  if len(sys.argv) < 4:
    _error('Usage: {0} <binary> <corpus_dir> <dft_dir>'.format(sys.argv[0]))
    sys.exit(1)

  binary = sys.argv[1]
  corpus_dir = sys.argv[2]
  dft_dir = sys.argv[3]

  os.environ['DFSAN_OPTIONS'] = DFSAN_OPTIONS

  if not dump_functions(binary, dft_dir):
    _error('Failed to dump functions. Something is wrong.')
    sys.exit(1)

  stats = collect_traces(binary, corpus_dir, dft_dir)
  for k, v in stats.items():
    print('{0}: {1}'.format(k, v))

  # Checksum that we didn't lose track of any of the inputs.
  assert stats['total'] * 2 == sum(v for v in stats.values())
  sys.exit(0)


if __name__ == "__main__":
  main()
