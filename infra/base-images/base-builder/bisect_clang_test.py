# Copyright 2019 Google Inc.
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
"""Tests for bisect_clang.py"""
import os
from unittest import mock
import unittest

import bisect_clang

FILE_DIRECTORY = os.path.dirname(__file__)
LLVM_REPO_PATH = '/llvm-project'


def get_git_command(*args):
  """Returns a git command for the LLVM repo with |args| as arguments."""
  return ['git', '-C', LLVM_REPO_PATH] + list(args)


def patch_environ(testcase_obj):
  """Patch environment."""
  env = {}
  patcher = mock.patch.dict(os.environ, env)
  testcase_obj.addCleanup(patcher.stop)
  patcher.start()


class BisectClangTestMixin:  # pylint: disable=too-few-public-methods
  """Useful mixin for bisect_clang unittests."""

  def setUp(self):  # pylint: disable=invalid-name
    """Initialization method for unittests."""
    patch_environ(self)
    os.environ['SRC'] = '/src'
    os.environ['WORK'] = '/work'


class GetClangBuildEnvTest(BisectClangTestMixin, unittest.TestCase):
  """Tests for get_clang_build_env."""

  def test_cflags(self):
    """Test that CFLAGS are not used compiling clang."""
    os.environ['CFLAGS'] = 'blah'
    self.assertNotIn('CFLAGS', bisect_clang.get_clang_build_env())

  def test_cxxflags(self):
    """Test that CXXFLAGS are not used compiling clang."""
    os.environ['CXXFLAGS'] = 'blah'
    self.assertNotIn('CXXFLAGS', bisect_clang.get_clang_build_env())

  def test_other_variables(self):
    """Test that other env vars are used when compiling clang."""
    key = 'other'
    value = 'blah'
    os.environ[key] = value
    self.assertEqual(value, bisect_clang.get_clang_build_env()[key])


def read_test_data(filename):
  """Returns data from |filename| in the test_data directory."""
  with open(os.path.join(FILE_DIRECTORY, 'test_data', filename)) as file_handle:
    return file_handle.read()


class SearchBisectOutputTest(BisectClangTestMixin, unittest.TestCase):
  """Tests for search_bisect_output."""

  def test_search_bisect_output(self):
    """Test that search_bisect_output finds the responsible commit when one
    exists."""
    test_data = read_test_data('culprit-commit.txt')
    self.assertEqual('ac9ee01fcbfac745aaedca0393a8e1c8a33acd8d',
                     bisect_clang.search_bisect_output(test_data))

  def test_search_bisect_output_none(self):
    """Test that search_bisect_output doesnt find a non-existent culprit
    commit."""
    self.assertIsNone(bisect_clang.search_bisect_output('hello'))


def create_mock_popen(
    output=bytes('', 'utf-8'), err=bytes('', 'utf-8'), returncode=0):
  """Creates a mock subprocess.Popen."""

  class MockPopen:
    """Mock subprocess.Popen."""
    commands = []
    testcases_written = []

    def __init__(self, command, *args, **kwargs):  # pylint: disable=unused-argument
      """Inits the MockPopen."""
      stdout = kwargs.pop('stdout', None)
      self.command = command
      self.commands.append(command)
      self.stdout = None
      self.stderr = None
      self.returncode = returncode
      if hasattr(stdout, 'write'):
        self.stdout = stdout

    def communicate(self, input_data=None):  # pylint: disable=unused-argument
      """Mock subprocess.Popen.communicate."""
      if self.stdout:
        self.stdout.write(output)

      if self.stderr:
        self.stderr.write(err)

      return output, err

    def poll(self, input_data=None):  # pylint: disable=unused-argument
      """Mock subprocess.Popen.poll."""
      return self.returncode

  return MockPopen


def mock_prepare_build_impl(llvm_project_path):  # pylint: disable=unused-argument
  """Mocked prepare_build function."""
  return '/work/llvm-build'


class BuildClangTest(BisectClangTestMixin, unittest.TestCase):
  """Tests for build_clang."""

  def test_build_clang_test(self):
    """Tests that build_clang works as intended."""
    with mock.patch('subprocess.Popen', create_mock_popen()) as mock_popen:
      with mock.patch('bisect_clang.prepare_build', mock_prepare_build_impl):
        llvm_src_dir = '/src/llvm-project'
        bisect_clang.build_clang(llvm_src_dir)
        self.assertEqual([['ninja', '-C', '/work/llvm-build', 'install']],
                         mock_popen.commands)


class GitRepoTest(BisectClangTestMixin, unittest.TestCase):
  """Tests for GitRepo."""

  # TODO(metzman): Mock filesystem. Until then, use a real directory.

  def setUp(self):
    super().setUp()
    self.git = bisect_clang.GitRepo(LLVM_REPO_PATH)
    self.good_commit = 'good_commit'
    self.bad_commit = 'bad_commit'
    self.test_command = 'testcommand'

  def test_do_command(self):
    """Test do_command creates a new process as intended."""
    # TODO(metzman): Test directory changing behavior.
    command = ['subcommand', '--option']
    with mock.patch('subprocess.Popen', create_mock_popen()) as mock_popen:
      self.git.do_command(command)
      self.assertEqual([get_git_command('subcommand', '--option')],
                       mock_popen.commands)

  def _test_test_start_commit_unexpected(self, label, commit, returncode):
    """Tests test_start_commit works as intended when the test returns an
    unexpected value."""

    def mock_execute_impl(command, *args, **kwargs):  # pylint: disable=unused-argument
      if command == self.test_command:
        return returncode, '', ''
      return 0, '', ''

    with mock.patch('bisect_clang.execute', mock_execute_impl):
      with mock.patch('bisect_clang.prepare_build', mock_prepare_build_impl):
        with self.assertRaises(bisect_clang.BisectError):
          self.git.test_start_commit(commit, label, self.test_command)

  def test_test_start_commit_bad_zero(self):
    """Tests test_start_commit works as intended when the test on the first bad
    commit returns 0."""
    self._test_test_start_commit_unexpected('bad', self.bad_commit, 0)

  def test_test_start_commit_good_nonzero(self):
    """Tests test_start_commit works as intended when the test on the first good
    commit returns nonzero."""
    self._test_test_start_commit_unexpected('good', self.good_commit, 1)

  def test_test_start_commit_good_zero(self):
    """Tests test_start_commit works as intended when the test on the first good
    commit returns 0."""
    self._test_test_start_commit_expected('good', self.good_commit, 0)  # pylint: disable=no-value-for-parameter

  @mock.patch('bisect_clang.build_clang')
  def _test_test_start_commit_expected(self, label, commit, returncode,
                                       mock_build_clang):
    """Tests test_start_commit works as intended when the test returns an
    expected value."""
    command_args = []

    def mock_execute_impl(command, *args, **kwargs):  # pylint: disable=unused-argument
      command_args.append(command)
      if command == self.test_command:
        return returncode, '', ''
      return 0, '', ''

    with mock.patch('bisect_clang.execute', mock_execute_impl):
      self.git.test_start_commit(commit, label, self.test_command)
      self.assertEqual([
          get_git_command('checkout', commit), self.test_command,
          get_git_command('bisect', label)
      ], command_args)
      mock_build_clang.assert_called_once_with(LLVM_REPO_PATH)

  def test_test_start_commit_bad_nonzero(self):
    """Tests test_start_commit works as intended when the test on the first bad
    commit returns nonzero."""
    self._test_test_start_commit_expected('bad', self.bad_commit, 1)  # pylint: disable=no-value-for-parameter

  @mock.patch('bisect_clang.GitRepo.test_start_commit')
  def test_bisect_start(self, mock_test_start_commit):
    """Tests bisect_start works as intended."""
    with mock.patch('subprocess.Popen', create_mock_popen()) as mock_popen:
      self.git.bisect_start(self.good_commit, self.bad_commit,
                            self.test_command)
      self.assertEqual(get_git_command('bisect', 'start'),
                       mock_popen.commands[0])
      mock_test_start_commit.assert_has_calls([
          mock.call('bad_commit', 'bad', 'testcommand'),
          mock.call('good_commit', 'good', 'testcommand')
      ])

  def test_do_bisect_command(self):
    """Test do_bisect_command executes a git bisect subcommand as intended."""
    subcommand = 'subcommand'
    with mock.patch('subprocess.Popen', create_mock_popen()) as mock_popen:
      self.git.do_bisect_command(subcommand)
      self.assertEqual([get_git_command('bisect', subcommand)],
                       mock_popen.commands)

  @mock.patch('bisect_clang.build_clang')
  def _test_test_commit(self, label, output, returncode, mock_build_clang):
    """Test test_commit works as intended."""
    command_args = []

    def mock_execute_impl(command, *args, **kwargs):  # pylint: disable=unused-argument
      command_args.append(command)
      if command == self.test_command:
        return returncode, output, ''
      return 0, output, ''

    with mock.patch('bisect_clang.execute', mock_execute_impl):
      result = self.git.test_commit(self.test_command)
      self.assertEqual([self.test_command,
                        get_git_command('bisect', label)], command_args)
    mock_build_clang.assert_called_once_with(LLVM_REPO_PATH)
    return result

  def test_test_commit_good(self):
    """Test test_commit labels a good commit as good."""
    self.assertIsNone(self._test_test_commit('good', '', 0))  # pylint: disable=no-value-for-parameter

  def test_test_commit_bad(self):
    """Test test_commit labels a bad commit as bad."""
    self.assertIsNone(self._test_test_commit('bad', '', 1))  # pylint: disable=no-value-for-parameter

  def test_test_commit_culprit(self):
    """Test test_commit returns the culprit"""
    test_data = read_test_data('culprit-commit.txt')
    self.assertEqual('ac9ee01fcbfac745aaedca0393a8e1c8a33acd8d',
                     self._test_test_commit('good', test_data, 0))  # pylint: disable=no-value-for-parameter


class GetTargetArchToBuildTest(unittest.TestCase):
  """Tests for get_target_arch_to_build."""

  def test_unrecognized(self):
    """Test that an unrecognized architecture raises an exception."""
    with mock.patch('bisect_clang.execute') as mock_execute:
      mock_execute.return_value = (None, 'mips', None)
      with self.assertRaises(Exception):
        bisect_clang.get_clang_target_arch()

  def test_recognized(self):
    """Test that a recognized architecture returns the expected value."""
    arch_pairs = {'x86_64': 'X86', 'aarch64': 'AArch64'}
    for uname_result, clang_target in arch_pairs.items():
      with mock.patch('bisect_clang.execute') as mock_execute:
        mock_execute.return_value = (None, uname_result, None)
        self.assertEqual(clang_target, bisect_clang.get_clang_target_arch())
