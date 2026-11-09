# Copyright 2026 Google LLC
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
"""Unit tests for infra/ci/check_base_os.py."""

import os
import tempfile
import unittest

from infra.ci import check_base_os


class CheckBaseOsTest(unittest.TestCase):
  """Tests multi-stage and alias handling in check_base_os."""

  def _write_project(self, root, yaml_text, dockerfile_text):
    with open(os.path.join(root, 'project.yaml'), 'w', encoding='utf-8') as yf:
      yf.write(yaml_text)
    with open(os.path.join(root, 'Dockerfile'), 'w', encoding='utf-8') as df:
      df.write(dockerfile_text)

  def test_legacy_implicit_latest_passes(self):
    """Implicit :latest tag passes when base_os_version is omitted (legacy)."""
    with tempfile.TemporaryDirectory() as tmp:
      self._write_project(
          tmp,
          'language: c++\n',
          'FROM gcr.io/oss-fuzz-base/base-builder\n',
      )
      self.assertEqual(check_base_os.check_project_base_os(tmp), 0)

  def test_ubuntu24_with_stage_alias_passes(self):
    """Multi-stage Dockerfile with AS alias and matching ubuntu-24-04 passes."""
    with tempfile.TemporaryDirectory() as tmp:
      self._write_project(
          tmp,
          'language: c++\nbase_os_version: ubuntu-24-04\n',
          'FROM gcr.io/oss-fuzz-base/base-builder:ubuntu-24-04 AS builder\n'
          'FROM gcr.io/oss-fuzz-base/base-runner:ubuntu-24-04\n',
      )
      self.assertEqual(check_base_os.check_project_base_os(tmp), 0)

  def test_multistage_unpinned_second_stage_fails(self):
    """Unpinned second OSS-Fuzz stage is caught when ubuntu-24-04 is set."""
    with tempfile.TemporaryDirectory() as tmp:
      self._write_project(
          tmp,
          'language: c++\nbase_os_version: ubuntu-24-04\n',
          'FROM ubuntu:24.04 AS prep\n'
          'FROM gcr.io/oss-fuzz-base/base-builder\n',
      )
      self.assertEqual(check_base_os.check_project_base_os(tmp), 1)


if __name__ == '__main__':
  unittest.main()
