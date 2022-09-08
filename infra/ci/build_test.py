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
#
################################################################################
"""Tests for build.py"""

import os
import sys
import unittest
from unittest import mock

# pylint: disable=wrong-import-position
INFRA_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(INFRA_DIR)

from ci import build


def patch_environ(testcase_obj):
  """Patch environment."""
  env = {}
  patcher = mock.patch.dict(os.environ, env)
  testcase_obj.addCleanup(patcher.stop)
  patcher.start()


def _set_coverage_build():
  """Set the right environment variables for a coverage build."""
  os.environ['SANITIZER'] = 'coverage'
  os.environ['ENGINE'] = 'libfuzzer'
  os.environ['ARCHITECTURE'] = 'x86_64'


class TestShouldBuild(unittest.TestCase):
  """Tests that should_build() works as intended."""

  def setUp(self):
    patch_environ(self)

  def test_none_engine_coverage_build(self):
    """Tests that should_build returns False for a coverage build of a
    project that specifies 'none' for fuzzing_engines."""
    _set_coverage_build()
    project_yaml = {
        'language': 'c++',
        'fuzzing_engines': ['none'],
        'sanitizers': ['address']
    }
    self.assertFalse(build.should_build(project_yaml))

  def test_unspecified_engines_coverage_build(self):
    """Tests that should_build returns True for a coverage build of a
    project that doesn't specify fuzzing_engines."""
    _set_coverage_build()
    project_yaml = {'language': 'c++'}
    self.assertTrue(build.should_build(project_yaml))

  def test_libfuzzer_coverage_build(self):
    """Tests that should_build returns True for coverage build of a project
    specifying 'libfuzzer' for fuzzing_engines."""
    _set_coverage_build()
    project_yaml = {
        'language': 'c++',
        'fuzzing_engines': ['libfuzzer'],
        'sanitizers': ['address']
    }
    self.assertTrue(build.should_build(project_yaml))

  def test_go_coverage_build(self):
    """Tests that should_build returns True for coverage build of a project
    specifying 'libfuzzer' for fuzzing_engines."""
    _set_coverage_build()
    project_yaml = {'language': 'go'}
    self.assertTrue(build.should_build(project_yaml))

  def test_engine_project_none_build(self):
    """Tests that should_build returns False for an engine: 'none' build when
    the project doesn't specify engines."""
    os.environ['SANITIZER'] = 'address'
    os.environ['ENGINE'] = 'none'
    os.environ['ARCHITECTURE'] = 'x86_64'
    project_yaml = {
        'language': 'c++',
        'fuzzing_engines': ['libfuzzer'],
        'sanitizers': ['address']
    }
    self.assertFalse(build.should_build(project_yaml))

  def test_centipede_none_build(self):
    """Tests that should_build returns True for none sanitizer build of a
    project specifying 'centipede' for fuzzing_engines."""
    os.environ['SANITIZER'] = 'none'
    os.environ['ENGINE'] = 'centipede'
    os.environ['ARCHITECTURE'] = 'x86_64'
    project_yaml = {
        'language': 'c++',
        'fuzzing_engines': ['centipede'],
        'sanitizers': ['none']
    }
    self.assertTrue(build.should_build(project_yaml))

  def test_centipede_address_build(self):
    """Tests that should_build returns True for address sanitizer build of a
    project specifying 'centipede' for fuzzing_engines."""
    os.environ['SANITIZER'] = 'address'
    os.environ['ENGINE'] = 'centipede'
    os.environ['ARCHITECTURE'] = 'x86_64'
    project_yaml = {
        'language': 'c++',
        'fuzzing_engines': ['centipede'],
        'sanitizers': ['address']
    }
    self.assertTrue(build.should_build(project_yaml))
