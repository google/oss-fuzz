#!/usr/bin/env python3
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
"""Use git bisect to find the Clang/LLVM commit causing a regression."""

import logging
import os
import re
import shutil
import subprocess
import sys


def execute(command, *args, expect_zero=True, **kwargs):
  """Execute |command| and return the returncode, stdout and stderr."""
  kwargs['stdout'] = subprocess.PIPE
  kwargs['stderr'] = subprocess.PIPE
  logging.debug('Running command: "%s"', str(command))
  process = subprocess.Popen(command, *args, **kwargs)
  stdout, stderr = process.communicate()
  stdout = stdout.decode('utf-8')
  stderr = stderr.decode('utf-8')
  retcode = process.returncode
  logging.info('Command: "%s" returned: %d.\nStdout: %s.\nStderr: %s',
               str(command), retcode, stdout, stderr)
  if expect_zero and retcode != 0:
    raise subprocess.CalledProcessError(retcode, command)
  return retcode, stdout, stderr


def search_bisect_output(output):
  """Search |output| for a message indicating the culprit commit has been
  found."""
  # TODO(metzman): Is it necessary to look for "good"?
  culprit_regex = re.compile('([a-z0-9]{40}) is the first (good|bad) commit')
  match = re.match(culprit_regex, output)
  return match.group(1) if match is not None else None


class GitRepo:
  """Class for executing commmands on a git repo."""

  def __init__(self, repo_dir):
    self.repo_dir = repo_dir

  def do_command(self, git_subcommand):
    """Execute a |git_subcommand| (a list of strings)."""
    command = ['git', '-C', self.repo_dir] + git_subcommand
    return execute(command)

  def test_commit(self, test_command):
    """Build LLVM at the currently checkedout commit, then run |test_command|.
    If returncode is 0 run 'git bisect good' otherwise return 'git bisect bad'.
    Return None if bisect didn't finish yet. Return the culprit commit if it
    does."""
    build_clang(self.repo_dir)
    retcode, _, _ = execute(test_command, shell=True, expect_zero=False)
    if retcode == 0:
      retcode, stdout, _ = self.do_bisect_command('good')
    else:
      retcode, stdout, _ = self.do_bisect_command('bad')
    return search_bisect_output(stdout)

  def bisect(self, good_commit, bad_commit, test_command):
    """Do git bisect assuming |good_commit| is good, |bad_commit| is bad and
    |test_command| is an oracle. Return the culprit commit."""
    self.bisect_start(good_commit, bad_commit, test_command)
    result = self.test_commit(test_command)
    while result is None:
      result = self.test_commit(test_command)
    return result

  def bisect_start(self, good_commit, bad_commit, test_command):
    """Start doing git bisect."""
    self.do_bisect_command('start')
    # Do bad commit first since it is more likely to be recent.
    self.test_start_commit(bad_commit, 'bad', test_command)
    self.test_start_commit(good_commit, 'good', test_command)

  def do_bisect_command(self, subcommand):
    """Execute a git bisect |subcommand| (string) and return the result."""
    return self.do_command(['bisect', subcommand])

  def test_start_commit(self, commit, label, test_command):
    """Use |test_command| to test the first good or bad |commit| (depending on
    |label|)."""
    assert label in ('good', 'bad'), label
    self.do_command(['checkout', commit])
    build_clang(self.repo_dir)
    retcode, _, _ = execute(test_command, shell=True, expect_zero=False)
    if label == 'good' and retcode != 0:
      raise BisectError('Test command "%s" returns %d on first good commit %s' %
                        (test_command, retcode, commit))
    if label == 'bad' and retcode == 0:
      raise BisectError('Test command "%s" returns %d on first bad commit %s' %
                        (test_command, retcode, commit))

    self.do_bisect_command(label)


class BisectError(Exception):
  """Error that was encountered during bisection."""


def get_clang_build_env():
  """Get an environment for building Clang."""
  env = os.environ.copy()
  for variable in ['CXXFLAGS', 'CFLAGS']:
    if variable in env:
      del env[variable]
  return env


def install_clang_build_deps():
  """Instal dependencies necessary to build clang."""
  execute([
      'apt-get', 'install', '-y', 'build-essential', 'make', 'cmake',
      'ninja-build', 'git', 'subversion', 'g++-multilib'
  ])


def clone_with_retries(repo, local_path, num_retries=10):
  """Clone |repo| to |local_path| if it doesn't exist already. Try up to
  |num_retries| times. Return False if unable to checkout."""
  if os.path.isdir(local_path):
    return
  for _ in range(num_retries):
    if os.path.isdir(local_path):
      shutil.rmtree(local_path)
    retcode, _, _ = execute(['git', 'clone', repo, local_path],
                            expect_zero=False)
    if retcode == 0:
      return
  raise Exception('Could not checkout %s.' % repo)


def get_clang_target_arch():
  """Get target architecture we want clang to target when we build it."""
  _, arch, _ = execute(['uname', '-m'])
  if 'x86_64' in arch:
    return 'X86'
  if 'aarch64' in arch:
    return 'AArch64'
  raise Exception('Unsupported target: %s.' % arch)


def prepare_build(llvm_project_path):
  """Prepare to build clang."""
  llvm_build_dir = os.path.join(os.getenv('WORK'), 'llvm-build')
  if not os.path.exists(llvm_build_dir):
    os.mkdir(llvm_build_dir)
  execute([
      'cmake', '-G', 'Ninja', '-DLIBCXX_ENABLE_SHARED=OFF',
      '-DLIBCXX_ENABLE_STATIC_ABI_LIBRARY=ON', '-DLIBCXXABI_ENABLE_SHARED=OFF',
      '-DCMAKE_BUILD_TYPE=Release',
      '-DLLVM_ENABLE_PROJECTS=libcxx;libcxxabi;compiler-rt;clang',
      '-DLLVM_TARGETS_TO_BUILD=' + get_clang_target_arch(),
      os.path.join(llvm_project_path, 'llvm')
  ],
          env=get_clang_build_env(),
          cwd=llvm_build_dir)
  return llvm_build_dir


def build_clang(llvm_project_path):
  """Checkout, build and install Clang."""
  # TODO(metzman): Merge Python checkout and build code with
  # checkout_build_install_llvm.sh.
  # TODO(metzman): Look into speeding this process using ccache.
  # TODO(metzman): Make this program capable of handling MSAN and i386 Clang
  # regressions.
  llvm_build_dir = prepare_build(llvm_project_path)
  execute(['ninja', '-C', llvm_build_dir, 'install'], env=get_clang_build_env())


def find_culprit_commit(test_command, good_commit, bad_commit):
  """Returns the culprit LLVM commit that introduced a bug revealed by running
  |test_command|. Uses git bisect and treats |good_commit| as the first latest
   known good commit and |bad_commit| as the first known bad commit."""
  llvm_project_path = os.path.join(os.getenv('SRC'), 'llvm-project')
  clone_with_retries('https://github.com/llvm/llvm-project.git',
                     llvm_project_path)
  git_repo = GitRepo(llvm_project_path)
  result = git_repo.bisect(good_commit, bad_commit, test_command)
  print('Culprit commit', result)
  return result


def main():
  # pylint: disable=line-too-long
  """Finds the culprit LLVM commit that introduced a clang regression.
  Can be tested using this command in a libsodium shell:
  python3 bisect_clang.py "cd /src/libsodium; make clean; cd -; compile && /out/secret_key_auth_fuzzer -runs=100" \
                          f7e52fbdb5a7af8ea0808e98458b497125a5eca1 \
                          8288453f6aac05080b751b680455349e09d49825
  """
  # pylint: enable=line-too-long
  # TODO(metzman): Check CFLAGS for things like -fsanitize=fuzzer-no-link.
  # TODO(metzman): Allow test_command to be optional and for just build.sh to be
  # used instead.
  test_command = sys.argv[1]
  # TODO(metzman): Add in more automation so that the script can automatically
  # determine the commits used in last Clang roll.
  good_commit = sys.argv[2]
  bad_commit = sys.argv[3]
  # TODO(metzman): Make verbosity configurable.
  logging.getLogger().setLevel(logging.DEBUG)
  install_clang_build_deps()
  find_culprit_commit(test_command, good_commit, bad_commit)
  return 0


if __name__ == '__main__':
  sys.exit(main())
