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
"""
A CI script to ensure that the base OS version specified in a project's
project.yaml file matches the FROM line in its Dockerfile.
"""

import os
import sys
import yaml

# Defines the base OS versions that are currently supported for use in project.yaml.
# For now, only 'legacy' is permitted. This list will be expanded as new
# base images are rolled out.
SUPPORTED_VERSIONS = [
    'legacy',
    # 'ubuntu-20-04',
    'ubuntu-24-04',
]

# A map from the base_os_version in project.yaml to the expected Dockerfile
# FROM tag.
BASE_OS_TO_DOCKER_TAG = {
    'legacy': 'latest',
    'ubuntu-20-04': 'ubuntu-20-04',
    'ubuntu-24-04': 'ubuntu-24-04',
}


def main():
  """Checks the Dockerfile FROM tag against the project's base_os_version."""
  if len(sys.argv) < 2:
    print(f'Usage: {sys.argv[0]} <project_path>', file=sys.stderr)
    return 1

  project_path = sys.argv[1]
  project_yaml_path = os.path.join(project_path, 'project.yaml')
  dockerfile_path = os.path.join(project_path, 'Dockerfile')

  # 1. Get the base_os_version from project.yaml, defaulting to 'legacy'.
  base_os_version = 'legacy'
  if os.path.exists(project_yaml_path):
    with open(project_yaml_path) as f:
      config = yaml.safe_load(f)
      if config and 'base_os_version' in config:
        base_os_version = config['base_os_version']

  # 2. Validate that the version is currently supported.
  if base_os_version not in SUPPORTED_VERSIONS:
    print(
        f'Error: base_os_version "{base_os_version}" is not yet supported. '
        f'The currently supported versions are: "{", ".join(SUPPORTED_VERSIONS)}"',
        file=sys.stderr)
    return 1

  # 3. Get the expected Dockerfile tag from our mapping.
  expected_tag = BASE_OS_TO_DOCKER_TAG[base_os_version]

  # 4. Read the Dockerfile and find the tag in the FROM line.
  if not os.path.exists(dockerfile_path):
    print(f'Error: Dockerfile not found at {dockerfile_path}', file=sys.stderr)
    return 1

  dockerfile_tag = ''
  with open(dockerfile_path) as f:
    for line in f:
      if line.strip().startswith('FROM'):
        try:
          if ':' not in line:
            print(
                f'Error: Malformed FROM line in Dockerfile (missing tag): {line.strip()}',
                file=sys.stderr)
            return 1
          dockerfile_tag = line.split(':')[1].strip()
        except IndexError:
          print(f'Error: Could not parse tag from Dockerfile FROM line: {line}',
                file=sys.stderr)
          return 1
        break

  # 5. Compare and report.
  if dockerfile_tag != expected_tag:
    print(
        f'Error: Mismatch found in {project_path}.\n'
        f'  - project.yaml (base_os_version): "{base_os_version}" (expects Dockerfile tag "{expected_tag}")\n'
        f'  - Dockerfile FROM tag: "{dockerfile_tag}"\n'
        f'Please align the Dockerfile\'s FROM line to use the tag "{expected_tag}".',
        file=sys.stderr)
    return 1

  print(
      f'Success: {project_path} is consistent (base_os_version: "{base_os_version}", Dockerfile tag: "{dockerfile_tag}").'
  )
  return 0


if __name__ == '__main__':
  sys.exit(main())
