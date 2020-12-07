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
"""Tests the functionality of the fuzz_target module."""

import os
import sys
import tempfile
import unittest
import unittest.mock
import urllib.error

import parameterized
from pyfakefs import fake_filesystem_unittest

# Pylint has an issue importing utils which is why error suppression is needed.
# pylint: disable=wrong-import-position,import-error
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import fuzz_target

# NOTE: This integration test relies on
# https://github.com/google/oss-fuzz/tree/master/projects/example project.
EXAMPLE_PROJECT = 'example'

# An example fuzzer that triggers an error.
EXAMPLE_FUZZER = 'example_crash_fuzzer'

# The return value of a successful call to utils.execute.
EXECUTE_SUCCESS_RETVAL = ('', '', 0)

# The return value of a failed call to utils.execute.
EXECUTE_FAILURE_RETVAL = ('', '', 1)


# TODO(metzman): Use patch from test_libs/helpers.py in clusterfuzz so that we
# don't need to accept this as an argument in every test method.
@unittest.mock.patch('utils.get_container_name', return_value='container')
class IsReproducibleTest(fake_filesystem_unittest.TestCase):
  """Tests the is_reproducible method in the fuzz_target.FuzzTarget class."""

  def setUp(self):
    """Sets up dummy fuzz target to test is_reproducible method."""
    self.fuzz_target_path = '/example/path'
    self.testcase_path = '/testcase'
    self.test_target = fuzz_target.FuzzTarget(self.fuzz_target_path,
                                              fuzz_target.REPRODUCE_ATTEMPTS,
                                              '/example/outdir')

  def test_reproducible(self, _):
    """Tests that is_reproducible returns True if crash is detected and that
    is_reproducible uses the correct command to reproduce a crash."""
    self._set_up_fakefs()
    all_repro = [EXECUTE_FAILURE_RETVAL] * fuzz_target.REPRODUCE_ATTEMPTS
    with unittest.mock.patch('utils.execute',
                             side_effect=all_repro) as mocked_execute:
      result = self.test_target.is_reproducible(self.testcase_path,
                                                self.fuzz_target_path)
      mocked_execute.assert_called_once_with([
          'docker', 'run', '--rm', '--privileged', '--volumes-from',
          'container', '-e', 'OUT=/example', '-e',
          'TESTCASE=' + self.testcase_path, '-t',
          'gcr.io/oss-fuzz-base/base-runner', 'reproduce', 'path', '-runs=100'
      ])
      self.assertTrue(result)
      self.assertEqual(1, mocked_execute.call_count)

  def _set_up_fakefs(self):
    """Helper to setup pyfakefs and add important files to the fake
    filesystem."""
    self.setUpPyfakefs()
    self.fs.create_file(self.fuzz_target_path)
    self.fs.create_file(self.testcase_path)

  def test_flaky(self, _):
    """Tests that is_reproducible returns True if crash is detected on the last
    attempt."""
    self._set_up_fakefs()
    last_time_repro = [EXECUTE_SUCCESS_RETVAL] * 9 + [EXECUTE_FAILURE_RETVAL]
    with unittest.mock.patch('utils.execute',
                             side_effect=last_time_repro) as mocked_execute:
      self.assertTrue(
          self.test_target.is_reproducible(self.testcase_path,
                                           self.fuzz_target_path))
      self.assertEqual(fuzz_target.REPRODUCE_ATTEMPTS,
                       mocked_execute.call_count)

  def test_nonexistent_fuzzer(self, _):
    """Tests that is_reproducible raises an error if it could not attempt
    reproduction because the fuzzer doesn't exist."""
    with self.assertRaises(fuzz_target.ReproduceError):
      self.test_target.is_reproducible(self.testcase_path, '/non-existent-path')

  def test_unreproducible(self, _):
    """Tests that is_reproducible returns False for a crash that did not
    reproduce."""
    all_unrepro = [EXECUTE_SUCCESS_RETVAL] * fuzz_target.REPRODUCE_ATTEMPTS
    self._set_up_fakefs()
    with unittest.mock.patch('utils.execute', side_effect=all_unrepro):
      result = self.test_target.is_reproducible(self.testcase_path,
                                                self.fuzz_target_path)
      self.assertFalse(result)


class GetTestCaseTest(unittest.TestCase):
  """Tests get_testcase."""

  def setUp(self):
    """Sets up dummy fuzz target to test get_testcase method."""
    self.test_target = fuzz_target.FuzzTarget('/example/path', 10,
                                              '/example/outdir')

  def test_valid_error_string(self):
    """Tests that get_testcase returns the correct testcase give an error."""
    testcase_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                 'test_files',
                                 'example_crash_fuzzer_output.txt')
    with open(testcase_path, 'rb') as test_fuzz_output:
      parsed_testcase = self.test_target.get_testcase(test_fuzz_output.read())
    self.assertEqual(
        parsed_testcase,
        '/example/outdir/crash-ad6700613693ef977ff3a8c8f4dae239c3dde6f5')

  def test_invalid_error_string(self):
    """Tests that get_testcase returns None with a bad error string."""
    self.assertIsNone(self.test_target.get_testcase(b''))
    self.assertIsNone(self.test_target.get_testcase(b' Example crash string.'))

  def test_encoding(self):
    """Tests that get_testcase accepts bytes and returns a string."""
    fuzzer_output = b'\x8fTest unit written to ./crash-1'
    result = self.test_target.get_testcase(fuzzer_output)
    self.assertTrue(isinstance(result, str))


class DownloadLatestCorpusTest(unittest.TestCase):
  """Tests parse_fuzzer_output."""

  def test_download_valid_projects_corpus(self):
    """Tests that a valid fuzz target returns a corpus directory."""
    with tempfile.TemporaryDirectory() as tmp_dir:
      test_target = fuzz_target.FuzzTarget('testfuzzer', 3, 'test_out')
      test_target.project_name = EXAMPLE_PROJECT
      test_target.target_name = EXAMPLE_FUZZER
      test_target.out_dir = tmp_dir
      with unittest.mock.patch(
          'fuzz_target.download_and_unpack_zip',
          return_value=tmp_dir) as mocked_download_and_unpack_zip:
        test_target.download_latest_corpus()
        (url, out_dir), _ = mocked_download_and_unpack_zip.call_args
        self.assertEqual(
            url, 'https://storage.googleapis.com/example-backup.'
            'clusterfuzz-external.appspot.com/corpus/libFuzzer/'
            'example_crash_fuzzer/public.zip')
        self.assertEqual(out_dir,
                         os.path.join(tmp_dir, 'backup_corpus', EXAMPLE_FUZZER))

  def test_download_invalid_projects_corpus(self):
    """Tests that a invade fuzz target does not return None."""
    with tempfile.TemporaryDirectory() as tmp_dir:
      test_target = fuzz_target.FuzzTarget('test fuzzer', 3, tmp_dir)
      corpus_path = test_target.download_latest_corpus()
      self.assertIsNone(corpus_path)
      test_target = fuzz_target.FuzzTarget('not_a_fuzzer', 3, tmp_dir,
                                           'not_a_project')
      corpus_path = test_target.download_latest_corpus()
      self.assertIsNone(corpus_path)


class IsCrashReportableTest(fake_filesystem_unittest.TestCase):
  """Tests the is_crash_reportable method of FuzzTarget."""

  def setUp(self):
    """Sets up dummy fuzz target to test is_crash_reportable method."""
    self.fuzz_target_path = '/example/do_stuff_fuzzer'
    self.test_target = fuzz_target.FuzzTarget(self.fuzz_target_path, 100,
                                              '/example/outdir', 'example')
    self.oss_fuzz_build_path = '/oss-fuzz-build'
    self.setUpPyfakefs()
    self.fs.create_file(self.fuzz_target_path)
    self.oss_fuzz_target_path = os.path.join(
        self.oss_fuzz_build_path, os.path.basename(self.fuzz_target_path))
    self.fs.create_file(self.oss_fuzz_target_path)
    self.testcase_path = '/testcase'
    self.fs.create_file(self.testcase_path, contents='')

  @unittest.mock.patch('logging.info')
  def test_new_reproducible_crash(self, mocked_info):
    """Tests that a new reproducible crash returns True."""

    with unittest.mock.patch('fuzz_target.FuzzTarget.is_reproducible',
                             side_effect=[True, False]):
      with tempfile.TemporaryDirectory() as tmp_dir:
        self.test_target.out_dir = tmp_dir
        self.assertTrue(self.test_target.is_crash_reportable(
            self.testcase_path))
    mocked_info.assert_called_with(
        'The crash is reproducible. The crash doesn\'t reproduce '
        'on old builds. This pull request probably introduced the '
        'crash.')

  # yapf: disable
  @parameterized.parameterized.expand([
      # Reproducible on PR build, but also reproducible on OSS-Fuzz.
      ([True, True],),

      # Not reproducible on PR build, but somehow reproducible on OSS-Fuzz.
      # Unlikely to happen in real world except if test is flaky.
      ([False, True],),

      # Not reproducible on PR build, and not reproducible on OSS-Fuzz.
      ([False, False],),
  ])
  # yapf: enable
  def test_invalid_crash(self, is_reproducible_retvals):
    """Tests that a nonreportable crash causes the method to return False."""
    with unittest.mock.patch('fuzz_target.FuzzTarget.is_reproducible',
                             side_effect=is_reproducible_retvals):

      with unittest.mock.patch('fuzz_target.FuzzTarget.download_oss_fuzz_build',
                               return_value=self.oss_fuzz_build_path):
        self.assertFalse(
            self.test_target.is_crash_reportable(self.testcase_path))

  @unittest.mock.patch('logging.info')
  @unittest.mock.patch('fuzz_target.FuzzTarget.is_reproducible',
                       return_value=[True])
  def test_reproducible_no_oss_fuzz_target(self, _, mocked_info):
    """Tests that is_crash_reportable returns True when a crash reproduces on
    the PR build but the target is not in the OSS-Fuzz build (usually because it
    is new)."""
    os.remove(self.oss_fuzz_target_path)

    def is_reproducible_side_effect(_, target_path):
      if os.path.dirname(target_path) == self.oss_fuzz_build_path:
        raise fuzz_target.ReproduceError()
      return True

    with unittest.mock.patch(
        'fuzz_target.FuzzTarget.is_reproducible',
        side_effect=is_reproducible_side_effect) as mocked_is_reproducible:
      with unittest.mock.patch('fuzz_target.FuzzTarget.download_oss_fuzz_build',
                               return_value=self.oss_fuzz_build_path):
        self.assertTrue(self.test_target.is_crash_reportable(
            self.testcase_path))
    mocked_is_reproducible.assert_any_call(self.testcase_path,
                                           self.oss_fuzz_target_path)
    mocked_info.assert_called_with(
        'Crash is reproducible. Could not run OSS-Fuzz build of '
        'target to determine if this pull request introduced crash. '
        'Assuming this pull request introduced crash.')


class GetLatestBuildVersionTest(unittest.TestCase):
  """Tests the get_latest_build_version function."""

  def test_get_valid_project(self):
    """Tests that the latest build can be retrieved from GCS."""
    test_target = fuzz_target.FuzzTarget('/example/path', 10, '/example/outdir',
                                         'example')
    latest_build = test_target.get_latest_build_version()
    self.assertIsNotNone(latest_build)
    self.assertTrue(latest_build.endswith('.zip'))
    self.assertTrue('address' in latest_build)

  def test_get_invalid_project(self):
    """Tests that the latest build returns None when project doesn't exist."""
    test_target = fuzz_target.FuzzTarget('/example/path', 10, '/example/outdir',
                                         'not-a-proj')
    self.assertIsNone(test_target.get_latest_build_version())
    test_target = fuzz_target.FuzzTarget('/example/path', 10, '/example/outdir')
    self.assertIsNone(test_target.get_latest_build_version())


class DownloadOSSFuzzBuildDirIntegrationTest(unittest.TestCase):
  """Tests download_oss_fuzz_build."""

  def test_single_download(self):
    """Tests that the build directory was only downloaded once."""
    with tempfile.TemporaryDirectory() as tmp_dir:
      test_target = fuzz_target.FuzzTarget('/example/do_stuff_fuzzer', 10,
                                           tmp_dir, 'example')
      latest_version = test_target.get_latest_build_version()
      with unittest.mock.patch(
          'fuzz_target.FuzzTarget.get_latest_build_version',
          return_value=latest_version) as mocked_get_latest_build_version:
        for _ in range(5):
          oss_fuzz_build_path = test_target.download_oss_fuzz_build()
        self.assertEqual(1, mocked_get_latest_build_version.call_count)
        self.assertIsNotNone(oss_fuzz_build_path)
        self.assertTrue(os.listdir(oss_fuzz_build_path))

  def test_get_valid_project(self):
    """Tests the latest build can be retrieved from GCS."""
    with tempfile.TemporaryDirectory() as tmp_dir:
      test_target = fuzz_target.FuzzTarget('/example/do_stuff_fuzzer', 10,
                                           tmp_dir, 'example')
      oss_fuzz_build_path = test_target.download_oss_fuzz_build()
      self.assertIsNotNone(oss_fuzz_build_path)
      self.assertTrue(os.listdir(oss_fuzz_build_path))

  def test_get_invalid_project(self):
    """Tests the latest build returns None when project doesn't exist."""
    with tempfile.TemporaryDirectory() as tmp_dir:
      test_target = fuzz_target.FuzzTarget('/example/do_stuff_fuzzer', 10,
                                           tmp_dir)
      self.assertIsNone(test_target.download_oss_fuzz_build())
      test_target = fuzz_target.FuzzTarget('/example/do_stuff_fuzzer', 10,
                                           tmp_dir, 'not-a-proj')
      self.assertIsNone(test_target.download_oss_fuzz_build())

  def test_invalid_build_dir(self):
    """Tests the download returns None when out_dir doesn't exist."""
    with tempfile.TemporaryDirectory() as tmp_dir:
      invalid_dir = os.path.join(tmp_dir, 'not/a/dir')
      test_target = fuzz_target.FuzzTarget('/example/do_stuff_fuzzer', 10,
                                           invalid_dir, 'example')
      self.assertIsNone(test_target.download_oss_fuzz_build())


class DownloadUrlTest(unittest.TestCase):
  """Tests that download_url works."""
  URL = 'example.com/file'
  FILE_PATH = '/tmp/file'

  @unittest.mock.patch('time.sleep')
  @unittest.mock.patch('urllib.request.urlretrieve', return_value=True)
  def test_download_url_no_error(self, mocked_urlretrieve, _):
    """Tests that download_url works when there is no error."""
    self.assertTrue(fuzz_target.download_url(self.URL, self.FILE_PATH))
    self.assertEqual(1, mocked_urlretrieve.call_count)

  @unittest.mock.patch('time.sleep')
  @unittest.mock.patch('logging.error')
  @unittest.mock.patch('urllib.request.urlretrieve',
                       side_effect=urllib.error.HTTPError(
                           None, None, None, None, None))
  def test_download_url_http_error(self, mocked_urlretrieve, mocked_error, _):
    """Tests that download_url doesn't retry when there is an HTTP error."""
    self.assertFalse(fuzz_target.download_url(self.URL, self.FILE_PATH))
    mocked_error.assert_called_with('Unable to download from: %s.', self.URL)
    self.assertEqual(1, mocked_urlretrieve.call_count)

  @unittest.mock.patch('time.sleep')
  @unittest.mock.patch('logging.error')
  @unittest.mock.patch('urllib.request.urlretrieve',
                       side_effect=ConnectionResetError)
  def test_download_url_connection_error(self, mocked_urlretrieve, mocked_error,
                                         mocked_sleep):
    """Tests that download_url doesn't retry when there is an HTTP error."""
    self.assertFalse(fuzz_target.download_url(self.URL, self.FILE_PATH))
    self.assertEqual(3, mocked_urlretrieve.call_count)
    self.assertEqual(3, mocked_sleep.call_count)
    mocked_error.assert_called_with('Failed to download %s, %d times.',
                                    self.URL, 3)


class DownloadAndUnpackZipTest(unittest.TestCase):
  """Tests download_and_unpack_zip."""

  def test_bad_zip_download(self):
    """Tests download_and_unpack_zip returns none when a bad zip is passed."""
    with tempfile.TemporaryDirectory() as tmp_dir, unittest.mock.patch(
        'urllib.request.urlretrieve', return_value=True):
      file_handle = open(os.path.join(tmp_dir, 'url_tmp.zip'), 'w')
      file_handle.write('Test file.')
      file_handle.close()
      self.assertIsNone(
          fuzz_target.download_and_unpack_zip('/not/a/real/url', tmp_dir))


if __name__ == '__main__':
  unittest.main()
