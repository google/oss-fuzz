#!/usr/bin/env python3
# Copyright 2020 Google LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################
"""Tests for compiler_wrapper."""

from __future__ import print_function

import unittest

import compiler_wrapper


class CompilerWrapperTest(unittest.TestCase):
  """Tests for compiler_wrapper."""

  def test_filter_z_defs(self):
    """Reference tests for remove_z_defs."""
    self.assertListEqual(['arg'],
                         compiler_wrapper.remove_z_defs(['arg', '-Wl,-z,defs']))

    self.assertListEqual(['arg'],
                         compiler_wrapper.remove_z_defs(
                             ['arg', '-Wl,--no-undefined']))

    self.assertListEqual(['arg', '-Wl,-z,relro'],
                         compiler_wrapper.remove_z_defs(['arg',
                                                         '-Wl,-z,relro']))

    self.assertListEqual(['arg', '-Wl,-soname,lib.so.1,-z,relro'],
                         compiler_wrapper.remove_z_defs(
                             ['arg', '-Wl,-soname,lib.so.1,-z,defs,-z,relro']))

    self.assertListEqual(['arg', '-Wl,-z,relro'],
                         compiler_wrapper.remove_z_defs(
                             ['arg', '-Wl,-z,relro,-z,defs']))

    self.assertListEqual(['arg'],
                         compiler_wrapper.remove_z_defs(
                             ['arg', '-Wl,-z', '-Wl,defs']))

    self.assertListEqual(['arg', 'arg2'],
                         compiler_wrapper.remove_z_defs(
                             ['arg', 'arg2', '-Wl,--no-undefined']))

    self.assertListEqual(['arg', 'arg2'],
                         compiler_wrapper.remove_z_defs(
                             ['arg', '-Wl,-z', 'arg2', '-Wl,defs']))


if __name__ == '__main__':
  unittest.main()
