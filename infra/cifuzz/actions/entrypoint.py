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
"""Builds and runs specific OSS-Fuzz project's fuzzers for CI tools."""

import os
import subprocess
import sys


def main():
  """Runs OSS-Fuzz project's fuzzers for CI tools."""
  project_name = os.environ['OSS_FUZZ_PROJECT_NAME']
  repo_name = os.environ['GITHUB_REPOSITORY'].rsplit('/', 1)[-1]
  commit_sha = os.environ['GITHUB_SHA']

  # Build the specified project's fuzzers from the current repo state.
  print('Building fuzzers\nproject: {0}\nrepo name: {1}\ncommit: {2}'.format(
      project_name, repo_name, commit_sha))
  command = [
      'python3', '/src/oss-fuzz/infra/cifuzz.py', 'build_fuzzers', project_name,
      repo_name, commit_sha
  ]
  print('Running command: "{0}"'.format(' '.join(command)))
  try:
    subprocess.check_call(command)
  except subprocess.CalledProcessError as err:
    sys.stderr.write('Error building fuzzers: "{0}"'.format(str(err)))
    return err.returncode

  # Run the specified project's fuzzers from the build.
  command = [
      'python3', '/src/oss-fuzz/infra/cifuzz.py', 'run_fuzzers', project_name
  ]
  print('Running command: "{0}"'.format(' '.join(command)))
  try:
    subprocess.check_call(command)
  except subprocess.CalledProcessError as err:
    sys.stderr.write('Error running fuzzers: "{0}"'.format(str(err)))
    return err.returncode
  print('Fuzzers ran successfully.')
  return 0


if __name__ == '__main__':

  sys.exit(main())
