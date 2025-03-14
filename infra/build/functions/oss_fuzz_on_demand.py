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
#
################################################################################
"""OSS-Fuzz on demand."""

import sys
import logging

import fuzzbench, build_project

FUZZBENCH_BUILD_TYPE = 'coverage'


def get_build_script_args(args):
  if not args:
    return None

  build_script_args = [args[0]]
  for i in range(len(args)):
    if args[i] in ['--branch', '--fuzzing-engine']:
      build_script_args.append(args[i])
      build_script_args.append(args[i + 1])

  return build_script_args


def oss_fuzz_on_demand_main(args=None):
  """Main function for OSS-Fuzz on demand."""
  build_script_args = get_build_script_args(args)
  return build_project.build_script_main('Does a FuzzBench run.',
                                         fuzzbench.get_build_steps,
                                         FUZZBENCH_BUILD_TYPE,
                                         build_script_args)


def main():
  """Build OSS-Fuzz projects with FuzzBench fuzzing engines."""
  logging.basicConfig(level=logging.INFO)
  return 0 if oss_fuzz_on_demand_main() else 1


if __name__ == '__main__':
  sys.exit(main())
