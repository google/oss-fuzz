#!/usr/bin/env python3
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
"""Script to unshallow repositories."""
import argparse
import os
import pathlib
import re
import subprocess

SRC = pathlib.Path(os.getenv('SRC', '/src'))


def main():
  parser = argparse.ArgumentParser(description='Unshallows repositores.')
  parser.add_argument('repos', nargs='+', help='Repo URLs')

  args = parser.parse_args()
  repos = set()
  for repo in args.repos:
    repos.add(_normalize_repo(repo))

  for subdir in SRC.iterdir():
    if (subdir / '.git').exists():
      repo = subprocess.check_output(['git', 'remote', 'get-url', 'origin'],
                                     cwd=subdir).decode().strip()
      if _normalize_repo(repo) in repos:
        if not _is_shallow_repo(subdir):
          continue
        print(f'Unshallowing {repo} at {subdir}.')
        subprocess.check_call(['git', 'fetch', '--unshallow'], cwd=subdir)


def _normalize_repo(repo: str) -> str:
  return re.sub(r'(.git)?/?$', '', repo)


def _is_shallow_repo(directory: pathlib.Path):
  return subprocess.check_output(
      ['git', 'rev-parse', '--is-shallow-repository'],
      cwd=directory).decode().strip() == 'true'


if __name__ == '__main__':
  main()
