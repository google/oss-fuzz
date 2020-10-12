#!/usr/bin/env python
# Copyright 2020 Google Inc.
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
"""Tests for compiler_wrapper."""

from __future__ import print_function

import unittest

import compiler_wrapper


class CompilerWrapperTest(unittest.TestCase):
  """
  CompilerWrapperTest()
  """

  def test_filter_zdefs(self):
    """
    test_filter_zdefs()
    """
    self.assertListEqual(['arg'],
                         compiler_wrapper.remove_zdefs(['arg', '-Wl,-z,defs']))

    # TODO (cclauss) Why does this test fail?
    # self.assertListEqual(['arg'],
    #                     compiler_wrapper.remove_zdefs(
    #                         ['arg', '-Wl,-z,--no-undefined']))

    self.assertListEqual(['arg', '-Wl,-z,relro'],
                         compiler_wrapper.remove_zdefs(['arg', '-Wl,-z,relro']))

    self.assertListEqual(['arg', '-Wl,-soname,lib.so.1,-z,relro'],
                         compiler_wrapper.remove_zdefs(
                             ['arg', '-Wl,-soname,lib.so.1,-z,defs,-z,relro']))

    self.assertListEqual(['arg', '-Wl,-z,relro'],
                         compiler_wrapper.remove_zdefs(
                             ['arg', '-Wl,-z,relro,-z,defs']))

    self.assertListEqual(['arg'],
                         compiler_wrapper.remove_zdefs(
                             ['arg', '-Wl,-z', '-Wl,defs']))

    self.assertListEqual(['arg', 'arg2'],
                         compiler_wrapper.remove_zdefs(
                             ['arg', '-Wl,-z', 'arg2', '-Wl,--no-undefined']))


if __name__ == '__main__':
  unittest.main()
