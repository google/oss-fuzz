# Copyright 2019 Google LLC
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
"""Builds a specific OSS-Fuzz project's fuzzers at a specific commit.
"""
import argparse
import os
import subprocess

GITHUB_URL = 'https://github.com/'

def main():
  """Finds the commit SHA where an error was initally introduced."""
  project_name = os.environ['OSS_FUZZ_PROJECT_NAME']
  repo_url = GITHUB_URL + os.environ['GITHUB_REPOSITORY']
  commit_sha = os.environ['GITHUB_SHA']
  branch_name = os.environ['GITHUB_REF']
  print("Building fuzzers\nproject: %s\nrepo url: %s\nbranch: %s\nCOMMIT: %s" % (project_name, repo_url ,branch_name, commit_sha))
  command = ['python3', '/src/oss-fuzz/infra/ci_fuzz.py', 'build_fuzzers', project_name, repo_url , commit_sha]
  print('Running command: %s' % command)
  if subprocess.check_call(command):
    return 1
  command = ['python3', '/src/oss-fuzz/infra/cifuzz.py', 'run_fuzzers', project_name]
  print('Running command: %s' % command)
  print(subprocess.check_output(command))

  return 0


if __name__ == '__main__':
  main()
