# Copyright 2025 Google LLC
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


def oss_fuzz_on_demand_main(args=None):
  """Main function for OSS-Fuzz on demand."""


def main():
  """Build OSS-Fuzz projects with FuzzBench fuzzing engines."""
  logging.basicConfig(level=logging.INFO)
  return 0 if oss_fuzz_on_demand_main() else 1


if __name__ == '__main__':
  sys.exit(main())
