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
"""Module used by CI tools in order to interact with fuzzers.
This module helps CI tools do the following:
  1. Build fuzzers.
  2. Run fuzzers.
Eventually it will be used to help CI tools determine which fuzzers to run.
"""

import logging
import os
import shutil
import sys
import time

import affected_fuzz_targets
import fuzz_target

# pylint: disable=wrong-import-position,import-error
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import build_specified_commit
import helper
import repo_manager
import retry
import utils

# From clusterfuzz: src/python/crash_analysis/crash_analyzer.py
# Used to get the beginning of the stacktrace.
STACKTRACE_TOOL_MARKERS = [
    b'AddressSanitizer',
    b'ASAN:',
    b'CFI: Most likely a control flow integrity violation;',
    b'ERROR: libFuzzer',
    b'KASAN:',
    b'LeakSanitizer',
    b'MemorySanitizer',
    b'ThreadSanitizer',
    b'UndefinedBehaviorSanitizer',
    b'UndefinedSanitizer',
]

# From clusterfuzz: src/python/crash_analysis/crash_analyzer.py
# Used to get the end of the stacktrace.
STACKTRACE_END_MARKERS = [
    b'ABORTING',
    b'END MEMORY TOOL REPORT',
    b'End of process memory map.',
    b'END_KASAN_OUTPUT',
    b'SUMMARY:',
    b'Shadow byte and word',
    b'[end of stack trace]',
    b'\nExiting',
    b'minidump has been written',
]

# Default fuzz configuration.
DEFAULT_ENGINE = 'libfuzzer'
DEFAULT_ARCHITECTURE = 'x86_64'

# TODO(metzman): Turn default logging to WARNING when CIFuzz is stable.
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.DEBUG)

_IMAGE_BUILD_TRIES = 3
_IMAGE_BUILD_BACKOFF = 2


def checkout_specified_commit(repo_manager_obj, pr_ref, commit_sha):
  """Checks out the specified commit or pull request using
  |repo_manager_obj|."""
  try:
    if pr_ref:
      repo_manager_obj.checkout_pr(pr_ref)
    else:
      repo_manager_obj.checkout_commit(commit_sha)
  except (RuntimeError, ValueError):
    logging.error(
        'Can not check out requested state %s. '
        'Using current repo state', pr_ref or commit_sha)


@retry.wrap(_IMAGE_BUILD_TRIES, _IMAGE_BUILD_BACKOFF)
def build_external_project_docker_image(project_name, project_src,
                                        build_integration_path):
  """Builds the project builder image for an external (non-OSS-Fuzz) project.
  Returns True on success."""
  dockerfile_path = os.path.join(build_integration_path, 'Dockerfile')
  tag = 'gcr.io/oss-fuzz/{project_name}'.format(project_name=project_name)
  command = ['-t', tag, '-f', dockerfile_path, project_src]
  return helper.docker_build(command)


def fix_git_repo_for_diff(repo_dir):
  """Fixes git repos cloned by the "checkout" action so that diffing works on
  them."""
  command = [
      'git', 'symbolic-ref', 'refs/remotes/origin/HEAD',
      'refs/remotes/origin/master'
  ]
  return utils.execute(command, location=repo_dir)


def check_project_src_path(project_src_path):
  """Returns True if |project_src_path| exists."""
  if not os.path.exists(project_src_path):
    logging.error(
        'PROJECT_SRC_PATH: %s does not exist. '
        'Are you mounting it correctly?', project_src_path)
    return False
  return True


# pylint: disable=too-many-arguments


class BaseBuilder:  # pylint: disable=too-many-instance-attributes
  """Base class for fuzzer builders."""

  def __init__(self,
               project_name,
               project_repo_name,
               workspace,
               sanitizer,
               host_repo_path=None):
    self.project_name = project_name
    self.project_repo_name = project_repo_name
    self.workspace = workspace
    self.out_dir = os.path.join(workspace, 'out')
    os.makedirs(self.out_dir, exist_ok=True)
    self.work_dir = os.path.join(workspace, 'work')
    os.makedirs(self.work_dir, exist_ok=True)
    self.sanitizer = sanitizer
    self.host_repo_path = host_repo_path
    self.image_repo_path = None
    self.repo_manager = None

  def build_image_and_checkout_src(self):
    """Builds the project builder image and checkout source code for the patch
    we want to fuzz (if necessary). Returns True on success.
    Must be implemented by child classes."""
    raise NotImplementedError('Child class must implement method')

  def build_fuzzers(self):
    """Moves the source code we want to fuzz into the project builder and builds
    the fuzzers from that source code. Returns True on success."""
    image_src_path = os.path.dirname(self.image_repo_path)
    command = get_common_docker_args(self.sanitizer)
    container = utils.get_container_name()

    if container:
      command.extend(['-e', 'OUT=' + self.out_dir, '--volumes-from', container])
      rm_path = os.path.join(self.image_repo_path, '*')

      bash_command = 'rm -rf {0} && cp -r {1} {2} && compile'.format(
          rm_path, self.host_repo_path, image_src_path)
    else:
      # TODO(metzman): Figure out if we can eliminate this branch.
      command.extend([
          '-e', 'OUT=' + '/out', '-v',
          '%s:%s' % (self.host_repo_path, self.image_repo_path), '-v',
          '%s:%s' % (self.out_dir, '/out')
      ])
      bash_command = 'compile'

    if self.sanitizer == 'memory':
      command.extend(self.handle_msan_prebuild(container))

    command.extend([
        'gcr.io/oss-fuzz/' + self.project_name,
        '/bin/bash',
        '-c',
    ])
    command.append(bash_command)
    logging.info('Building with %s sanitizer.', self.sanitizer)
    if helper.docker_run(command):
      # docker_run returns nonzero on failure.
      logging.error('Building fuzzers failed.')
      return False

    if self.sanitizer == 'memory':
      self.handle_msan_postbuild(container)
    return True

  def handle_msan_postbuild(self, container):
    """Post-build step for MSAN builds. Patches the build to use MSAN
    libraries."""
    helper.docker_run([
        '--volumes-from', container, '-e',
        'WORK={work_dir}'.format(work_dir=self.work_dir),
        'gcr.io/oss-fuzz-base/base-sanitizer-libs-builder', 'patch_build.py',
        '/out'
    ])

  def handle_msan_prebuild(self, container):
    """Pre-build step for MSAN builds. Copies MSAN libs to |msan_libs_dir| and
    returns docker arguments to use that directory for MSAN libs."""
    logging.info('Copying MSAN libs.')
    helper.docker_run([
        '--volumes-from', container, 'gcr.io/oss-fuzz-base/msan-libs-builder',
        'bash', '-c', 'cp -r /msan {work_dir}'.format(work_dir=self.work_dir)
    ])
    return [
        '-e', 'MSAN_LIBS_PATH={msan_libs_path}'.format(
            msan_libs_path=os.path.join(self.work_dir, 'msan'))
    ]

  def build(self):
    """Builds the image, checkouts the source (if needed), builds the fuzzers
    and then removes the unaffectted fuzzers. Returns True on success."""
    methods = [
        self.build_image_and_checkout_src, self.build_fuzzers,
        self.remove_unaffected_fuzz_targets
    ]
    for method in methods:
      if not method():
        return False
    return True

  def remove_unaffected_fuzz_targets(self):
    """Removes the fuzzers unaffected by the patch."""
    fix_git_repo_for_diff(self.host_repo_path)
    changed_files = self.repo_manager.get_git_diff()
    affected_fuzz_targets.remove_unaffected_fuzz_targets(
        self.project_name, self.out_dir, changed_files, self.image_repo_path)
    return True


class ExternalGithubBuilder(BaseBuilder):
  """Class for building non-OSS-Fuzz projects on GitHub Actions."""

  def __init__(self, project_name, project_repo_name, workspace, sanitizer,
               project_src_path, build_integration_path):

    super().__init__(project_name,
                     project_repo_name,
                     workspace,
                     sanitizer,
                     host_repo_path=project_src_path)
    self.build_integration_path = os.path.join(self.host_repo_path,
                                               build_integration_path)
    logging.info('build_integration_path %s, project_src_path %s.',
                 self.build_integration_path, self.host_repo_path)
    self.image_repo_path = os.path.join('/src', project_repo_name)

  def build_image_and_checkout_src(self):
    """Builds the project builder image for a non-OSS-Fuzz project. Sets the
    repo manager. Does not checkout source code since external projects are
    expected to bring their own source code to CIFuzz. Returns True on
    success."""
    logging.info('Building external project.')
    if not build_external_project_docker_image(
        self.project_name, self.host_repo_path, self.build_integration_path):
      logging.error('Failed to build external project.')
      return False
    self.repo_manager = repo_manager.RepoManager(self.host_repo_path)
    return True


class InternalGithubBuilder(BaseBuilder):
  """Class for building OSS-Fuzz projects on GitHub actions."""

  def __init__(self, project_name, project_repo_name, workspace, sanitizer,
               commit_sha, pr_ref):
    # Validate inputs.
    assert pr_ref or commit_sha

    super().__init__(project_name, project_repo_name, workspace, sanitizer)

    self.commit_sha = commit_sha
    self.pr_ref = pr_ref

  def build_image_and_checkout_src(self):
    """Builds the project builder image for a non-OSS-Fuzz project. Sets the
    repo manager and host_repo_path. Checks out source code of project with
    patch under test. Returns True on success."""
    logging.info('Building OSS-Fuzz project on Github Actions.')
    # detect_main_repo builds the image as a side effect.
    inferred_url, self.image_repo_path = (
        build_specified_commit.detect_main_repo(
            self.project_name, repo_name=self.project_repo_name))

    if not inferred_url or not self.image_repo_path:
      logging.error('Could not detect repo from project %s.', self.project_name)
      return False

    git_workspace = os.path.join(self.workspace, 'storage')
    os.makedirs(git_workspace, exist_ok=True)

    # Use the same name used in the docker image so we can overwrite it.
    image_repo_name = os.path.basename(self.image_repo_path)

    # Checkout project's repo in the shared volume.
    self.repo_manager = repo_manager.clone_repo_and_get_manager(
        inferred_url, git_workspace, repo_name=image_repo_name)

    self.host_repo_path = self.repo_manager.repo_dir

    checkout_specified_commit(self.repo_manager, self.pr_ref, self.commit_sha)
    return True


class InternalGenericCiBuilder(BaseBuilder):
  """Class for building fuzzers for an OSS-Fuzz project using on a platform
  other than GitHub actions."""

  def __init__(self, project_name, project_repo_name, workspace, sanitizer,
               project_src_path):
    super().__init__(project_name,
                     project_repo_name,
                     workspace,
                     sanitizer,
                     host_repo_path=project_src_path)

  def build_image_and_checkout_src(self):
    """Builds the project builder image for a non-OSS-Fuzz project. Sets the
    repo manager. Does not checkout source code since external projects are
    expected to bring their own source code to CIFuzz. Returns True on
    success."""
    logging.info('Building OSS-Fuzz project.')
    # detect_main_repo builds the image as a side effect.
    _, self.image_repo_path = (build_specified_commit.detect_main_repo(
        self.project_name, repo_name=self.project_repo_name))

    if not self.image_repo_path:
      logging.error('Could not detect repo from project %s.', self.project_name)
      return False

    # Checkout project's repo in the shared volume.
    self.repo_manager = repo_manager.RepoManager(self.host_repo_path)
    return True


def get_builder(project_name, project_repo_name, workspace, pr_ref, commit_sha,
                sanitizer, project_src_path, build_integration_path):
  """Determines what kind of build is being requested using the arguments
  provided and instantiates and returns the correct builder object."""
  if build_integration_path and project_src_path:
    # Non-OSS-Fuzz projects must bring their own source and their own build
    # integration (which is relative to that source).
    return ExternalGithubBuilder(project_name, project_repo_name, workspace,
                                 sanitizer, project_src_path,
                                 build_integration_path)

  if project_src_path:
    # Builds of OSS-Fuzz projects not hosted on Github must bring their own
    # source since the checkout logic CIFuzz implements is github-specific.
    # TODO(metzman): Consider moving Github-actions builds of OSS-Fuzz projects
    # to this system to reduce implementation complexity.
    return InternalGenericCiBuilder(project_name, project_repo_name, workspace,
                                    sanitizer, project_src_path)

  return InternalGithubBuilder(project_name, project_repo_name, workspace,
                               sanitizer, commit_sha, pr_ref)


def build_fuzzers(  # pylint: disable=too-many-arguments,too-many-locals
    project_name,
    project_repo_name,
    workspace,
    pr_ref=None,
    commit_sha=None,
    sanitizer='address',
    project_src_path=None,
    build_integration_path=None):
  """Builds all of the fuzzers for a specific OSS-Fuzz project.

  Args:
    project_name: The name of the OSS-Fuzz project being built.
    project_repo_name: The name of the project's repo.
    workspace: The location in a shared volume to store a git repo and build
      artifacts.
    pr_ref: The pull request reference to be built.
    commit_sha: The commit sha for the project to be built at.
    sanitizer: The sanitizer the fuzzers should be built with.

  Returns:
    True if build succeeded or False on failure.
  """
  # Do some quick validation.
  if project_src_path and not check_project_src_path(project_src_path):
    return False

  # Get the builder and then build the fuzzers.
  builder = get_builder(project_name, project_repo_name, workspace, pr_ref,
                        commit_sha, sanitizer, project_src_path,
                        build_integration_path)
  return builder.build()


def run_fuzzers(  # pylint: disable=too-many-arguments,too-many-locals
    fuzz_seconds,
    workspace,
    project_name,
    sanitizer='address'):
  """Runs all fuzzers for a specific OSS-Fuzz project.

  Args:
    fuzz_seconds: The total time allotted for fuzzing.
    workspace: The location in a shared volume to store a git repo and build
      artifacts.
    project_name: The name of the relevant OSS-Fuzz project.
    sanitizer: The sanitizer the fuzzers should be run with.

  Returns:
    (True if run was successful, True if bug was found).
  """
  # Validate inputs.
  if not os.path.exists(workspace):
    logging.error('Invalid workspace: %s.', workspace)
    return False, False

  logging.info('Using %s sanitizer.', sanitizer)

  out_dir = os.path.join(workspace, 'out')
  artifacts_dir = os.path.join(out_dir, 'artifacts')
  os.makedirs(artifacts_dir, exist_ok=True)
  if not fuzz_seconds or fuzz_seconds < 1:
    logging.error('Fuzz_seconds argument must be greater than 1, but was: %s.',
                  fuzz_seconds)
    return False, False

  # Get fuzzer information.
  fuzzer_paths = utils.get_fuzz_targets(out_dir)
  if not fuzzer_paths:
    logging.error('No fuzzers were found in out directory: %s.', out_dir)
    return False, False

  # Run fuzzers for allotted time.
  total_num_fuzzers = len(fuzzer_paths)
  fuzzers_left_to_run = total_num_fuzzers
  min_seconds_per_fuzzer = fuzz_seconds // total_num_fuzzers
  for fuzzer_path in fuzzer_paths:
    run_seconds = max(fuzz_seconds // fuzzers_left_to_run,
                      min_seconds_per_fuzzer)

    target = fuzz_target.FuzzTarget(fuzzer_path,
                                    run_seconds,
                                    out_dir,
                                    project_name,
                                    sanitizer=sanitizer)
    start_time = time.time()
    testcase, stacktrace = target.fuzz()
    fuzz_seconds -= (time.time() - start_time)
    if not testcase or not stacktrace:
      logging.info('Fuzzer %s, finished running.', target.target_name)
    else:
      utils.binary_print(b'Fuzzer %s, detected error:\n%s' %
                         (target.target_name.encode(), stacktrace))
      shutil.move(testcase, os.path.join(artifacts_dir, 'test_case'))
      parse_fuzzer_output(stacktrace, artifacts_dir)
      return True, True
    fuzzers_left_to_run -= 1

  return True, False


def get_common_docker_args(sanitizer):
  """Returns a list of common docker arguments."""
  return [
      '--cap-add',
      'SYS_PTRACE',
      '-e',
      'FUZZING_ENGINE=' + DEFAULT_ENGINE,
      '-e',
      'SANITIZER=' + sanitizer,
      '-e',
      'ARCHITECTURE=' + DEFAULT_ARCHITECTURE,
      '-e',
      'CIFUZZ=True',
      '-e',
      'FUZZING_LANGUAGE=c++',  # FIXME: Add proper support.
  ]


def check_fuzzer_build(out_dir,
                       sanitizer='address',
                       allowed_broken_targets_percentage=None):
  """Checks the integrity of the built fuzzers.

  Args:
    out_dir: The directory containing the fuzzer binaries.
    sanitizer: The sanitizer the fuzzers are built with.

  Returns:
    True if fuzzers are correct.
  """
  if not os.path.exists(out_dir):
    logging.error('Invalid out directory: %s.', out_dir)
    return False
  if not os.listdir(out_dir):
    logging.error('No fuzzers found in out directory: %s.', out_dir)
    return False

  command = get_common_docker_args(sanitizer)

  if allowed_broken_targets_percentage is not None:
    command += [
        '-e',
        ('ALLOWED_BROKEN_TARGETS_PERCENTAGE=' +
         allowed_broken_targets_percentage)
    ]

  container = utils.get_container_name()
  if container:
    command += ['-e', 'OUT=' + out_dir, '--volumes-from', container]
  else:
    command += ['-v', '%s:/out' % out_dir]
  command.extend(['-t', 'gcr.io/oss-fuzz-base/base-runner', 'test_all.py'])
  exit_code = helper.docker_run(command)
  logging.info('check fuzzer build exit code: %d', exit_code)
  if exit_code:
    logging.error('Check fuzzer build failed.')
    return False
  return True


def parse_fuzzer_output(fuzzer_output, out_dir):
  """Parses the fuzzer output from a fuzz target binary.

  Args:
    fuzzer_output: A fuzz target binary output string to be parsed.
    out_dir: The location to store the parsed output files.
  """
  # Get index of key file points.
  for marker in STACKTRACE_TOOL_MARKERS:
    marker_index = fuzzer_output.find(marker)
    if marker_index:
      begin_summary = marker_index
      break

  end_summary = -1
  for marker in STACKTRACE_END_MARKERS:
    marker_index = fuzzer_output.find(marker)
    if marker_index:
      end_summary = marker_index + len(marker)
      break

  if begin_summary is None or end_summary is None:
    return

  summary_str = fuzzer_output[begin_summary:end_summary]
  if not summary_str:
    return

  # Write sections of fuzzer output to specific files.
  summary_file_path = os.path.join(out_dir, 'bug_summary.txt')
  with open(summary_file_path, 'ab') as summary_handle:
    summary_handle.write(summary_str)
