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
#
################################################################################
"""Does bad_build_check on a fuzz target in $OUT."""
import os
import sys

import test_all


def test_one(fuzz_target):
  """Does bad_build_check on one fuzz target. Returns True on success."""
  with test_all.use_different_out_dir():
    fuzz_target_path = os.path.join(os.environ['OUT'], fuzz_target)
    result = test_all.do_bad_build_check(fuzz_target_path)
    if result.returncode != 0:
      sys.stdout.buffer.write(result.stdout + result.stderr + b'\n')
      return False
    return True


def main():
  """Does bad_build_check on one fuzz target. Returns 1 on failure, 0 on
  success."""
  if len(sys.argv) != 2:
    print('Usage: %d <fuzz_target>', sys.argv[0])
    return 1

  fuzz_target_binary = sys.argv[1]
  return 0 if test_one(fuzz_target_binary) else 1


if __name__ == '__main__':
  sys.exit(main())
