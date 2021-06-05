"""Tests for compiler_wrapper."""

from __future__ import print_function

import unittest

import compiler_wrapper


class CompilerWrapperTest(unittest.TestCase):

  def testFilterZDefs(self):
    self.assertListEqual(
        ['arg'],
        compiler_wrapper.RemoveZDefs(['arg', '-Wl,-z,defs']))

    self.assertListEqual(
        ['arg'],
        compiler_wrapper.RemoveZDefs(['arg', '-Wl,-z,--no-undefined']))

    self.assertListEqual(
        ['arg', '-Wl,-z,relro'],
        compiler_wrapper.RemoveZDefs(['arg', '-Wl,-z,relro']))

    self.assertListEqual(
        ['arg', '-Wl,-soname,lib.so.1,-z,relro'],
        compiler_wrapper.RemoveZDefs(['arg', '-Wl,-soname,lib.so.1,-z,defs,-z,relro']))

    self.assertListEqual(
        ['arg', '-Wl,-z,relro'],
        compiler_wrapper.RemoveZDefs(['arg', '-Wl,-z,relro,-z,defs']))

    self.assertListEqual(
        ['arg'],
        compiler_wrapper.RemoveZDefs(['arg', '-Wl,-z', '-Wl,defs']))

    self.assertListEqual(
        ['arg', 'arg2'],
        compiler_wrapper.RemoveZDefs(['arg', '-Wl,-z', 'arg2', '-Wl,--no-undefined']))

if __name__ == '__main__':
  unittest.main()
