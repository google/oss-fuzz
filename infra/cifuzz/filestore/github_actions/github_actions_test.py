# Copyright 2021 Google LLC
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
"""Tests for github_actions."""
import io
import os
import shutil
import stat
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

# pylint: disable=wrong-import-position
INFRA_DIR = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.append(INFRA_DIR)

from filestore import github_actions
import test_helpers

# pylint: disable=protected-access,no-self-use


class GithubActionsFilestoreTest(unittest.TestCase):
  """Tests for GithubActionsFilestore."""

  @mock.patch('platform_config.github._get_event_data', return_value={})
  def setUp(self, _):  # pylint: disable=arguments-differ
    test_helpers.patch_environ(self)
    self.token = 'example githubtoken'
    self.owner = 'exampleowner'
    self.repo = 'examplerepo'
    os.environ['GITHUB_REPOSITORY'] = f'{self.owner}/{self.repo}'
    os.environ['GITHUB_EVENT_PATH'] = '/fake'
    os.environ['CFL_PLATFORM'] = 'github'
    os.environ['GITHUB_WORKSPACE'] = '/workspace'
    self.config = test_helpers.create_run_config(token=self.token)
    self.local_dir = tempfile.mkdtemp()
    self.testcase = os.path.join(self.local_dir, 'testcase')

  def tearDown(self):
    shutil.rmtree(self.local_dir)

  def _get_expected_http_headers(self):
    return {
        'Authorization': f'token {self.token}',
        'Accept': 'application/vnd.github.v3+json',
    }

  @mock.patch('filestore.github_actions.github_api.list_artifacts')
  def test_list_artifacts(self, mock_list_artifacts):
    """Tests that _list_artifacts works as intended."""
    filestore = github_actions.GithubActionsFilestore(self.config)
    filestore._list_artifacts()
    mock_list_artifacts.assert_called_with(self.owner, self.repo,
                                           self._get_expected_http_headers())

  @mock.patch('logging.warning')
  @mock.patch('filestore.github_actions.GithubActionsFilestore._list_artifacts',
              return_value=None)
  @mock.patch('filestore.github_actions.github_api.find_artifact',
              return_value=None)
  def test_download_build_no_artifact(self, _, __, mock_warning):
    """Tests that download_build returns None and doesn't exception when
    find_artifact can't find an artifact."""
    filestore = github_actions.GithubActionsFilestore(self.config)
    name = 'name'
    build_dir = 'build-dir'
    self.assertFalse(filestore.download_build(name, build_dir))
    mock_warning.assert_called_with('Could not download artifact: %s.',
                                    'cifuzz-build-' + name)

  @mock.patch('logging.warning')
  @mock.patch('filestore.github_actions.GithubActionsFilestore._list_artifacts',
              return_value=None)
  @mock.patch('filestore.github_actions.github_api.find_artifact',
              return_value=None)
  def test_download_corpus_no_artifact(self, _, __, mock_warning):
    """Tests that download_corpus_build returns None and doesn't exception when
    find_artifact can't find an artifact."""
    filestore = github_actions.GithubActionsFilestore(self.config)
    name = 'name'
    dst_dir = self.local_dir
    self.assertFalse(filestore.download_corpus(name, dst_dir))
    mock_warning.assert_called_with('Could not download artifact: %s.',
                                    'cifuzz-corpus-' + name)

  @mock.patch('filestore.github_actions.tar_directory')
  @mock.patch('filestore.github_actions._upload_artifact_with_upload_js')
  def test_upload_corpus(self, mock_upload_artifact, mock_tar_directory):
    """Test uploading corpus."""
    self._create_local_dir()

    def mock_tar_directory_impl(_, archive_path):
      with open(archive_path, 'w') as f:
        pass

    mock_tar_directory.side_effect = mock_tar_directory_impl

    filestore = github_actions.GithubActionsFilestore(self.config)
    filestore.upload_corpus('target', self.local_dir)
    self.assert_upload(mock_upload_artifact, mock_tar_directory,
                       'corpus-target')

  @mock.patch('filestore.github_actions._upload_artifact_with_upload_js')
  def test_upload_crashes(self, mock_upload_artifact):
    """Test uploading crashes."""
    self._create_local_dir()

    filestore = github_actions.GithubActionsFilestore(self.config)
    filestore.upload_crashes('current', self.local_dir)
    mock_upload_artifact.assert_has_calls([
        mock.call('crashes-current', [f'{self.local_dir}/testcase'],
                  self.local_dir)
    ])

  @mock.patch('filestore.github_actions.tar_directory')
  @mock.patch('filestore.github_actions._upload_artifact_with_upload_js')
  def test_upload_build(self, mock_upload_artifact, mock_tar_directory):
    """Test uploading build."""
    self._create_local_dir()

    def mock_tar_directory_impl(_, archive_path):
      with open(archive_path, 'w') as f:
        pass

    mock_tar_directory.side_effect = mock_tar_directory_impl

    filestore = github_actions.GithubActionsFilestore(self.config)
    filestore.upload_build('sanitizer', self.local_dir)
    self.assert_upload(mock_upload_artifact, mock_tar_directory,
                       'build-sanitizer')

  @mock.patch('filestore.github_actions.tar_directory')
  @mock.patch('filestore.github_actions._upload_artifact_with_upload_js')
  def test_upload_coverage(self, mock_upload_artifact, mock_tar_directory):
    """Test uploading coverage."""
    self._create_local_dir()

    def mock_tar_directory_impl(_, archive_path):
      with open(archive_path, 'w') as f:
        pass

    mock_tar_directory.side_effect = mock_tar_directory_impl

    filestore = github_actions.GithubActionsFilestore(self.config)
    filestore.upload_coverage('latest', self.local_dir)
    self.assert_upload(mock_upload_artifact, mock_tar_directory,
                       'coverage-latest')

  @mock.patch('filestore.github_actions.UPLOAD_JS', shutil.which('false'))
  def test_upload_failure_raises(self):
    """Tests that a failed artifact upload raises."""
    self._create_local_dir()
    filestore = github_actions.GithubActionsFilestore(self.config)
    with self.assertRaises(RuntimeError):
      filestore.upload_corpus('target', self.local_dir)

  def assert_upload(self, mock_upload_artifact, mock_tar_directory,
                    expected_artifact_name):
    """Tests that upload_directory invokes tar_directory and
    artifact_client.upload_artifact properly."""
    # Don't assert what second argument will be since it's a temporary
    # directory.
    self.assertEqual(mock_tar_directory.call_args_list[0][0][0], self.local_dir)

    # Don't assert what second and third arguments will be since they are
    # temporary directories.
    expected_artifact_name = 'cifuzz-' + expected_artifact_name
    self.assertEqual(mock_upload_artifact.call_args_list[0][0][0],
                     expected_artifact_name)

    # Assert artifacts list contains one tarfile.
    artifacts_list = mock_upload_artifact.call_args_list[0][0][1]
    self.assertEqual(len(artifacts_list), 1)
    self.assertEqual(os.path.basename(artifacts_list[0]),
                     expected_artifact_name + '.tar')

  def _create_local_dir(self):
    """Create fake testcase."""
    with open(self.testcase, 'w') as f:
      f.write('hi')

  @mock.patch('filestore.github_actions.GithubActionsFilestore._find_artifact')
  @mock.patch('http_utils.download_and_unpack_zip')
  def test_download_artifact(self, mock_download_and_unpack_zip,
                             mock_find_artifact):
    """Tests that _download_artifact works as intended."""
    artifact_download_url = 'http://example.com/download'
    artifact_listing = {
        'expired': False,
        'name': 'corpus',
        'archive_download_url': artifact_download_url
    }
    mock_find_artifact.return_value = artifact_listing

    self._create_local_dir()
    with tempfile.TemporaryDirectory() as temp_dir:
      # Create a tarball.
      archive_path = os.path.join(temp_dir, 'cifuzz-corpus.tar')
      github_actions.tar_directory(self.local_dir, archive_path)

      artifact_download_dst_dir = os.path.join(temp_dir, 'dst')
      os.mkdir(artifact_download_dst_dir)

      def mock_download_and_unpack_zip_impl(url, download_artifact_temp_dir,
                                            headers):
        self.assertEqual(url, artifact_download_url)
        self.assertEqual(headers, self._get_expected_http_headers())
        shutil.copy(
            archive_path,
            os.path.join(download_artifact_temp_dir,
                         os.path.basename(archive_path)))
        return True

      mock_download_and_unpack_zip.side_effect = (
          mock_download_and_unpack_zip_impl)
      filestore = github_actions.GithubActionsFilestore(self.config)
      self.assertTrue(
          filestore._download_artifact('corpus', artifact_download_dst_dir))
      mock_find_artifact.assert_called_with('cifuzz-corpus')
      self.assertTrue(
          os.path.exists(
              os.path.join(artifact_download_dst_dir,
                           os.path.basename(self.testcase))))

  def _mock_zip_unpack_from_tar(self, mock_unpack, archive_path):
    """Configures |mock_unpack| to copy |archive_path| into temp dir."""

    def copy_tar(_, download_temp_dir, headers=None):
      del headers
      shutil.copy(
          archive_path,
          os.path.join(download_temp_dir, os.path.basename(archive_path)))
      return True

    mock_unpack.side_effect = copy_tar

  @mock.patch('filestore.github_actions.GithubActionsFilestore._find_artifact')
  @mock.patch('http_utils.download_and_unpack_zip')
  def test_download_build_preserves_executables_and_relative_symlinks(
      self, mock_download_and_unpack_zip, mock_find_artifact):
    """Tests that download_build preserves executable bits and safe internal
    relative symlinks produced by tar_directory."""
    mock_find_artifact.return_value = {
        'expired': False,
        'name': 'cifuzz-build-address',
        'archive_download_url': 'http://example.com/build',
    }

    with tempfile.TemporaryDirectory() as temp_dir:
      build_src = os.path.join(temp_dir, 'out_src')
      lib_dir = os.path.join(build_src, 'lib')
      os.makedirs(lib_dir)

      fuzzer_bin = os.path.join(build_src, 'example_fuzzer')
      with open(fuzzer_bin, 'wb') as handle:
        handle.write(b'\x7fELF-fuzzer-binary')
      os.chmod(fuzzer_bin, 0o755)

      options_file = os.path.join(build_src, 'example_fuzzer.options')
      with open(options_file, 'w') as handle:
        handle.write('[libfuzzer]\nmax_len = 1024\n')

      real_so = os.path.join(lib_dir, 'libhelper.so.1.0')
      with open(real_so, 'wb') as handle:
        handle.write(b'\x7fELF-shared-object')
      os.chmod(real_so, 0o755)
      os.symlink('libhelper.so.1.0', os.path.join(lib_dir, 'libhelper.so.1'))
      os.symlink('../example_fuzzer', os.path.join(lib_dir, 'fuzzer_alias'))

      archive_path = os.path.join(temp_dir, 'cifuzz-build-address.tar')
      github_actions.tar_directory(build_src, archive_path)
      self._mock_zip_unpack_from_tar(mock_download_and_unpack_zip, archive_path)

      dst_dir = os.path.join(temp_dir, 'out_dst')
      os.mkdir(dst_dir)
      store = github_actions.GithubActionsFilestore(self.config)
      self.assertTrue(store.download_build('address', dst_dir))

      extracted_bin = os.path.join(dst_dir, 'example_fuzzer')
      self.assertTrue(os.path.isfile(extracted_bin))
      self.assertEqual(0o755, stat.S_IMODE(os.stat(extracted_bin).st_mode))
      self.assertTrue(
          os.path.isfile(os.path.join(dst_dir, 'example_fuzzer.options')))
      extracted_so_link = os.path.join(dst_dir, 'lib', 'libhelper.so.1')
      self.assertTrue(os.path.islink(extracted_so_link))
      self.assertEqual('libhelper.so.1.0', os.readlink(extracted_so_link))
      extracted_alias = os.path.join(dst_dir, 'lib', 'fuzzer_alias')
      self.assertTrue(os.path.islink(extracted_alias))
      self.assertEqual('../example_fuzzer', os.readlink(extracted_alias))

  @mock.patch('filestore.github_actions.GithubActionsFilestore._find_artifact')
  @mock.patch('http_utils.download_and_unpack_zip')
  def test_download_coverage_extracts_nested_reports(
      self, mock_download_and_unpack_zip, mock_find_artifact):
    """Tests that download_coverage extracts nested JSON and HTML reports."""
    mock_find_artifact.return_value = {
        'expired': False,
        'name': 'cifuzz-coverage-latest',
        'archive_download_url': 'http://example.com/coverage',
    }

    with tempfile.TemporaryDirectory() as temp_dir:
      cov_src = os.path.join(temp_dir, 'cov_src')
      nested_dir = os.path.join(cov_src, 'report', 'linux')
      os.makedirs(nested_dir)
      with open(os.path.join(nested_dir, 'summary.json'), 'w') as handle:
        handle.write('{"data": []}')

      archive_path = os.path.join(temp_dir, 'cifuzz-coverage-latest.tar')
      github_actions.tar_directory(cov_src, archive_path)
      self._mock_zip_unpack_from_tar(mock_download_and_unpack_zip, archive_path)

      dst_dir = os.path.join(temp_dir, 'cov_dst')
      os.mkdir(dst_dir)
      store = github_actions.GithubActionsFilestore(self.config)
      self.assertTrue(store.download_coverage('latest', dst_dir))
      self.assertTrue(
          os.path.isfile(
              os.path.join(dst_dir, 'report', 'linux', 'summary.json')))

  @mock.patch('filestore.github_actions.GithubActionsFilestore._find_artifact')
  @mock.patch('http_utils.download_and_unpack_zip', return_value=True)
  def test_download_artifact_missing_inner_tarfile(self,
                                                   mock_download_and_unpack_zip,
                                                   mock_find_artifact):
    """Tests that _download_artifact returns False if zip lacks tar."""
    del mock_download_and_unpack_zip
    mock_find_artifact.return_value = {
        'expired': False,
        'name': 'cifuzz-corpus',
        'archive_download_url': 'http://example.com/download',
    }
    with tempfile.TemporaryDirectory() as dst_dir:
      store = github_actions.GithubActionsFilestore(self.config)
      self.assertFalse(store._download_artifact('corpus', dst_dir))

  def _write_tar_entries(self, archive_path, entries):
    """Writes (name, entry_type, target_or_bytes) entries to |archive_path|."""
    with tarfile.open(archive_path, 'w') as tar_handle:
      for member_name, entry_type, value in entries:
        member = tarfile.TarInfo(name=member_name)
        member.type = entry_type
        if entry_type in (tarfile.SYMTYPE, tarfile.LNKTYPE):
          member.linkname = value
          tar_handle.addfile(member)
        elif entry_type == tarfile.FIFOTYPE:
          tar_handle.addfile(member)
        else:
          member.size = len(value)
          tar_handle.addfile(member, io.BytesIO(value))

  @mock.patch('filestore.github_actions.GithubActionsFilestore._find_artifact')
  @mock.patch('http_utils.download_and_unpack_zip')
  def test_download_artifact_rejects_unsafe_tar_members(
      self, mock_download_and_unpack_zip, mock_find_artifact):
    """Tests that _download_artifact rejects path traversal, absolute paths,
    external symlinks/hardlinks, special files, and corrupted archives."""
    mock_find_artifact.return_value = {
        'expired': False,
        'name': 'corpus',
        'archive_download_url': 'http://example.com/download',
    }

    with tempfile.TemporaryDirectory() as temp_dir:
      outside_canary = os.path.join(temp_dir, 'escaped.txt')
      unsafe_cases = [
          ('relative_traversal', [
              ('../escaped.txt', tarfile.REGTYPE, b'escape'),
          ]),
          ('nested_relative_traversal', [
              ('corpus/sub/../../../escaped.txt', tarfile.REGTYPE, b'escape'),
          ]),
          ('absolute_member', [
              (outside_canary, tarfile.REGTYPE, b'escape'),
          ]),
          ('external_absolute_symlink', [
              ('escape_link', tarfile.SYMTYPE, outside_canary),
          ]),
          ('external_relative_symlink_chain', [
              ('sub/escape_dir', tarfile.SYMTYPE, '../..'),
              ('sub/escape_dir/escaped.txt', tarfile.REGTYPE, b'escape'),
          ]),
          ('external_hardlink', [
              ('hard_escape', tarfile.LNKTYPE, outside_canary),
          ]),
          ('special_fifo_member', [
              ('named_pipe', tarfile.FIFOTYPE, b''),
          ]),
      ]
      for case_name, entries in unsafe_cases:
        with self.subTest(case=case_name):
          archive_path = os.path.join(temp_dir, 'cifuzz-corpus.tar')
          self._write_tar_entries(archive_path, entries)
          self._mock_zip_unpack_from_tar(mock_download_and_unpack_zip,
                                         archive_path)
          dst_dir = os.path.join(temp_dir, f'dst_{case_name}')
          os.mkdir(dst_dir)
          store = github_actions.GithubActionsFilestore(self.config)
          self.assertFalse(store._download_artifact('corpus', dst_dir))
          self.assertFalse(os.path.exists(outside_canary))

      with self.subTest(case='corrupted_tar_stream'):
        corrupt_archive = os.path.join(temp_dir, 'cifuzz-corpus.tar')
        with open(corrupt_archive, 'wb') as handle:
          handle.write(b'not-a-valid-tar-header')
        self._mock_zip_unpack_from_tar(mock_download_and_unpack_zip,
                                       corrupt_archive)
        corrupt_dst = os.path.join(temp_dir, 'dst_corrupt')
        os.mkdir(corrupt_dst)
        store = github_actions.GithubActionsFilestore(self.config)
        self.assertFalse(store._download_artifact('corpus', corrupt_dst))

  @mock.patch('filestore.github_actions.github_api.list_artifacts')
  def test_find_artifact(self, mock_list_artifacts):
    """Tests that _find_artifact works as intended."""
    artifact_listing_1 = {
        'expired': False,
        'name': 'other',
        'archive_download_url': 'http://download1'
    }
    artifact_listing_2 = {
        'expired': False,
        'name': 'artifact',
        'archive_download_url': 'http://download2'
    }
    artifact_listing_3 = {
        'expired': True,
        'name': 'artifact',
        'archive_download_url': 'http://download3'
    }
    artifact_listing_4 = {
        'expired': False,
        'name': 'artifact',
        'archive_download_url': 'http://download4'
    }
    artifacts = [
        artifact_listing_1, artifact_listing_2, artifact_listing_3,
        artifact_listing_4
    ]
    mock_list_artifacts.return_value = artifacts
    filestore = github_actions.GithubActionsFilestore(self.config)
    # Test that find_artifact will return the most recent unexpired artifact
    # with the correct name.
    self.assertEqual(filestore._find_artifact('artifact'), artifact_listing_2)
    mock_list_artifacts.assert_called_with(self.owner, self.repo,
                                           self._get_expected_http_headers())


class TarDirectoryTest(unittest.TestCase):
  """Tests for tar_directory."""

  def test_tar_directory(self):
    """Tests that tar_directory writes the archive to the correct location and
    archives properly."""
    with tempfile.TemporaryDirectory() as temp_dir:
      archive_path = os.path.join(temp_dir, 'myarchive.tar')
      archived_dir = os.path.join(temp_dir, 'toarchive')
      os.mkdir(archived_dir)
      archived_filename = 'file1'
      archived_file_path = os.path.join(archived_dir, archived_filename)
      with open(archived_file_path, 'w') as file_handle:
        file_handle.write('hi')
      github_actions.tar_directory(archived_dir, archive_path)
      self.assertTrue(os.path.exists(archive_path))

      # Now check it archives correctly.
      unpacked_directory = os.path.join(temp_dir, 'unpacked')
      with tarfile.TarFile(archive_path) as artifact_tarfile:
        artifact_tarfile.extractall(unpacked_directory)
      unpacked_archived_file_path = os.path.join(unpacked_directory,
                                                 archived_filename)
      self.assertTrue(os.path.exists(unpacked_archived_file_path))
