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
"""Helper to check if run_tests.sh alter files in WORKDIR after execution."""

import hashlib
import os
import pathlib
import subprocess
import sys

EXCLUDE_DIRS = ['.git']


def _is_git_ignored(file_path: str) -> bool:
  """Helper to check if the current file path is git ignored."""
  # Check if the file_path in a git work tree. Always treat
  # it as not ignoored if it located outside of the git work tree
  try:
    result = subprocess.run(
        ["git", "rev-parse", "--is-inside-work-tree"],
        cwd=os.path.dirname(file_path),
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        check=False,
    )
    if result.returncode != 0 or result.stdout.strip() != "true":
      return False
  except:
    return False

  # Check if the file_path is git ignored
  try:
    result = subprocess.run(
        ["git", "check-ignore", "-q", "--",
         os.path.basename(file_path)],
        cwd=os.path.dirname(file_path),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return res.returncode == 0
  except:
    return False


def run_test_script():
  """Helper to execute the run_tests.sh"""
  cmd = ['chmod +x /src/run_tests.sh', '/src/run_tests.sh']
  subprocess.run(' && '.join(cmd), shell=True)


def build_snapshot(root: pathlib.Path) -> dict[str, str]:
  """Helper to record the snapshot of files in recursively in the current directory."""
  snapshot = {}
  for dirpath, dirs, files in os.walk(root, followlinks=False):
    dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]
    for file in files:
      file_path = os.path.abspath(os.path.join(dirpath, file))
      if _is_git_ignored(file_path):
        continue

      file_path_obj = pathlib.Path(file_path)
      try:
        if file_path_obj.is_symlink():
          # If the target is a symlink, record its link
          snapshot[file_path] = os.readlink(file_path_obj)
        elif file_path_obj.is_file():
          # If the target is a normal file, record its content hash
          hash = hashlib.sha256()
          with file_path_obj.open('rb') as f:
            while True:
              b = f.read(1024 * 1024)
              if not b:
                break
              hash.update(b)
          snapshot[file_path] = hash.hexdigest()
      except:
        pass

  return snapshot


def compare_snapshots(
    before: dict[str, str],
    after: dict[str, str]) -> tuple[set[str], set[str], set[str]]:
  """Helpers to discover deleted or modified files from the two snapshot."""
  before_keys = set(before.keys())
  after_keys = set(after.keys())

  deleted = before_keys - after_keys
  created = after_keys - before_keys
  common = before_keys & after_keys

  modified = set()
  for key in common:
    if before[key] != after[key]:
      modified.add(key)

  return modified, deleted, created


def main() -> bool:
  # Get current directory
  root = pathlib.Path.cwd()

  # Build snapshot before and after run_tests.sh
  before = build_snapshot(root)
  run_test_script()
  after = build_snapshot(root)

  # Compare the snapshots
  modified, deleted, created = compare_snapshots(before, after)
  if len(sys.argv) == 2 and sys.argv[1] == '--ignore-new-files':
    created = set()

  # Print results
  for file in modified:
    print('Modified file: ', file)
  for file in deleted:
    print('Deleted file: ', file)
  for file in created:
    print('New file: ', file)

  return modified or deleted or created


if __name__ == "__main__":
  has_changed = main()
  raise SystemExit(1 if has_changed else 0)
