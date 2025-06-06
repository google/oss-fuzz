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
"""Tests for ood_upload_corpus_test.py."""

import json
import os
import shutil
import tempfile
import unittest
from unittest.mock import patch, MagicMock, call

import build_lib
import ood_upload_corpus


class GetFilePathTest(unittest.TestCase):
  """Tests for get_files_path function."""

  def setUp(self):
    """Set tem_dir attribute"""
    self.temp_dir = tempfile.mkdtemp()

  def tearDown(self):
    """Remove temp_dir after tests"""
    shutil.rmtree(self.temp_dir)

  def test_no_files(self):
    """Test for empty directory"""
    self.assertEqual(ood_upload_corpus.get_files_path(self.temp_dir, 10), [])

  def test_single_file(self):
    """Test for single file"""
    file_name = 'test_file.txt'
    file_path = os.path.join(self.temp_dir, file_name)
    open(file_path, 'w').close()
    self.assertEqual(ood_upload_corpus.get_files_path(self.temp_dir, 10),
                     [file_path])

  def test_multiple_files(self):
    """Test for multiple files"""
    file_names = ['file1.txt', 'file2.csv', 'data.json']
    for name in file_names:
      file_path = os.path.join(self.temp_dir, name)
      open(file_path, 'w').close()
    files_path_set = set(ood_upload_corpus.get_files_path(self.temp_dir, 2))
    self.assertTrue(len(files_path_set) == 2)
    self.assertTrue(
        files_path_set.issubset(
            set([
                f'{self.temp_dir}/file1.txt', f'{self.temp_dir}/file2.csv',
                f'{self.temp_dir}/data.json'
            ])))

  def test_with_subdirectory(self):
    """Test for directory with subdirectory"""
    os.makedirs(os.path.join(self.temp_dir, 'subdir'))
    self.assertEqual(ood_upload_corpus.get_files_path(self.temp_dir, 10), [])

    file_name = 'test_file.txt'
    file_path = os.path.join(self.temp_dir, file_name)
    open(file_path, 'w').close()
    self.assertEqual(ood_upload_corpus.get_files_path(self.temp_dir, 10),
                     [file_path])


class TestUploadCorpus(unittest.TestCase):
  """Tests for upload_corpus function."""

  @patch('uuid.uuid4')
  @patch('ood_upload_corpus.upload_corpus_file')
  @patch('ood_upload_corpus.get_files_path')
  def test_upload_multiple_files(self, mock_get_files_path,
                                 mock_upload_corpus_file, mock_uuid):
    """Tests uploading multiple corpus files with the given document policy."""
    output_dir = 'test_corpus_dir'
    path_prefix = 'gs://test_bucket/corpus/'
    num_uploads = 3
    doc = build_lib.SignedPolicyDocument(bucket='bucket',
                                         policy='test_policy',
                                         x_goog_algorithm='x',
                                         x_goog_credential='x',
                                         x_goog_date='00000000',
                                         x_goog_signature='x')
    doc_str = json.dumps(doc.__dict__)
    mock_get_files_path.return_value = [
        os.path.join(output_dir, 'file_0.txt'),
        os.path.join(output_dir, 'file_1.txt'),
        os.path.join(output_dir, 'file_2.txt'),
    ]
    mock_uuid.side_effect = [
        MagicMock(hex='suffix1'),
        MagicMock(hex='suffix2'),
        MagicMock(hex='suffix3')
    ]

    ood_upload_corpus.upload_corpus(doc_str, path_prefix, output_dir,
                                    num_uploads)

    mock_get_files_path.assert_called_once_with(output_dir, num_uploads)
    mock_upload_corpus_file.assert_has_calls([
        call(os.path.join(output_dir, 'file_0.txt'),
             'gs://test_bucket/corpus/suffix1', doc),
        call(os.path.join(output_dir, 'file_1.txt'),
             'gs://test_bucket/corpus/suffix2', doc),
        call(os.path.join(output_dir, 'file_2.txt'),
             'gs://test_bucket/corpus/suffix3', doc),
    ])
    self.assertEqual(mock_uuid.call_count, num_uploads)


if __name__ == '__main__':
  unittest.main()
