
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
"""A simple script that configures the environment and runs the build."""
import argparse
import os
import subprocess
import sys

def main():
  parser = argparse.ArgumentParser(sys.argv[0], description='Run a single project build.')
  parser.add_argument('project', help='Project name.')
  parser.add_argument('--sanitizer', required=True, help='Sanitizer.')
  parser.add_argument('--fuzzing-engine', required=True, help='Fuzzing engine.')
  parser.add_argument('--architecture', default='x86_64', help='Architecture.')
  args = parser.parse_args()

  os.environ['PROJECT_NAME'] = args.project
  os.environ['SANITIZER'] = args.sanitizer
  os.environ['FUZZING_ENGINE'] = args.fuzzing_engine
  os.environ['ARCHITECTURE'] = args.architecture
  
  # For now, we are not setting FUZZING_LANGUAGE, as it is set by the base image.
  # We might need to revisit this.

  try:
    subprocess.run(['compile'], check=True)
  except subprocess.CalledProcessError as e:
    sys.exit(e.returncode)

if __name__ == '__main__':
  main()
