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
"""CI check ensuring project.yaml base_os_version matches Dockerfile tags."""

import os
import sys
import yaml

SUPPORTED_VERSIONS = [
    'legacy',
    'ubuntu-24-04',
]

BASE_OS_TO_DOCKER_TAG = {
    'legacy': 'latest',
    'ubuntu-20-04': 'ubuntu-20-04',
    'ubuntu-24-04': 'ubuntu-24-04',
}

OSS_FUZZ_BASE_PREFIX = 'gcr.io/oss-fuzz-base/'


def parse_oss_fuzz_base_tags(dockerfile_content):
  """Extracts (line, image_repo, tag) tuples for gcr.io/oss-fuzz-base stages."""
  stages = []
  for raw_line in dockerfile_content.splitlines():
    stripped = raw_line.split('#', 1)[0].strip()
    if not stripped.upper().startswith('FROM '):
      continue
    tokens = stripped.split()[1:]
    tokens = [tok for tok in tokens if not tok.startswith('--')]
    if not tokens:
      continue
    image_spec = tokens[0]
    if not image_spec.startswith(OSS_FUZZ_BASE_PREFIX):
      continue
    if ':' in image_spec:
      repo, tag = image_spec.rsplit(':', 1)
    else:
      repo, tag = image_spec, 'latest'
    stages.append((stripped, repo, tag))
  return stages


def check_project_base_os(project_path):
  """Validates that OSS-Fuzz base stages in Dockerfile match project.yaml."""
  project_yaml_path = os.path.join(project_path, 'project.yaml')
  dockerfile_path = os.path.join(project_path, 'Dockerfile')

  base_os_version = 'legacy'
  if os.path.exists(project_yaml_path):
    with open(project_yaml_path, encoding='utf-8') as handle:
      config = yaml.safe_load(handle)
      if config and 'base_os_version' in config:
        base_os_version = config['base_os_version']

  if base_os_version not in SUPPORTED_VERSIONS:
    print(
        f'Error: base_os_version "{base_os_version}" is not yet supported. '
        f'Supported versions: "{", ".join(SUPPORTED_VERSIONS)}"',
        file=sys.stderr)
    return 1

  expected_tag = BASE_OS_TO_DOCKER_TAG[base_os_version]

  if not os.path.exists(dockerfile_path):
    print(f'Error: Dockerfile not found at {dockerfile_path}', file=sys.stderr)
    return 1

  with open(dockerfile_path, encoding='utf-8') as handle:
    stages = parse_oss_fuzz_base_tags(handle.read())

  if not stages:
    print(f'Success: {project_path} uses no {OSS_FUZZ_BASE_PREFIX} stages '
          f'(base_os_version: "{base_os_version}").')
    return 0

  mismatches = [(line, tag) for line, _, tag in stages if tag != expected_tag]
  if mismatches:
    details = '\n'.join(
        f'  - "{line}" (parsed tag: "{tag}")' for line, tag in mismatches)
    print(
        f'Error: Mismatch found in {project_path}.\n'
        f'  - project.yaml (base_os_version): "{base_os_version}" '
        f'(expects Dockerfile tag "{expected_tag}")\n'
        f'{details}\n'
        f'Please align all {OSS_FUZZ_BASE_PREFIX}* FROM lines to use '
        f'":{expected_tag}".',
        file=sys.stderr)
    return 1

  print(f'Success: {project_path} is consistent '
        f'(base_os_version: "{base_os_version}", tag: "{expected_tag}").')
  return 0


def main():
  """CLI entrypoint."""
  if len(sys.argv) < 2:
    print(f'Usage: {sys.argv[0]} <project_path>', file=sys.stderr)
    return 1
  return check_project_base_os(sys.argv[1])


if __name__ == '__main__':
  sys.exit(main())
