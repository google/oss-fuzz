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
"""Tests for ood_upload_testcase_test.py."""

import os
import shutil
import tempfile
import unittest
from unittest import mock

import ood_upload_testcase


class GetFilePath(unittest.TestCase):
  """Tests for get_file_path."""

  def setUp(self):
    """Set tem_dir attribute"""
    self.temp_dir = tempfile.mkdtemp()

  def tearDown(self):
    """Remove temp_dir after tests"""
    shutil.rmtree(self.temp_dir)

  def test_no_files(self):
    """Test for empty directory"""
    self.assertIsNone(ood_upload_testcase.get_file_path(self.temp_dir))

  def test_single_file(self):
    """Test for single file"""
    file_name = 'test_file.txt'
    file_path = os.path.join(self.temp_dir, file_name)
    open(file_path, 'w').close()
    self.assertEqual(ood_upload_testcase.get_file_path(self.temp_dir),
                     file_path)

  def test_multiple_files(self):
    """Test for multiple files"""
    file_names = ['file1.txt', 'file2.csv', 'data.json']
    file_paths = []
    for name in file_names:
      file_path = os.path.join(self.temp_dir, name)
      file_paths.append(file_path)
      open(file_path, 'w').close()
    self.assertIn(ood_upload_testcase.get_file_path(self.temp_dir), file_paths)

  def test_with_subdirectory(self):
    """Test for directory with subdirectory"""
    os.makedirs(os.path.join(self.temp_dir, 'subdir'))
    self.assertIsNone(ood_upload_testcase.get_file_path(self.temp_dir))

    file_name = 'test_file.txt'
    file_path = os.path.join(self.temp_dir, file_name)
    open(file_path, 'w').close()
    self.assertEqual(ood_upload_testcase.get_file_path(self.temp_dir),
                     file_path)
