# Copyright 2019 Google LLC
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
"""Module to build a image from a specific commit, branch or pull request.

This module is allows each of the OSS Fuzz projects fuzzers to be built
from a specific point in time. This feature can be used for implementations
like continuious integration fuzzing and bisection to find errors
"""
import argparse
import bisect
import datetime
from distutils import spawn
import os
import collections
import json
import logging
import re
import shutil
import tempfile

import helper
import repo_manager
import retry
import utils

BuildData = collections.namedtuple(
    'BuildData', ['project_name', 'engine', 'sanitizer', 'architecture'])

_GIT_DIR_MARKER = 'gitdir: '
_IMAGE_BUILD_TRIES = 3


class BaseBuilderRepo:
  """Repo of base-builder images."""

  def __init__(self):
    self.timestamps = []
    self.digests = []

  def add_digest(self, timestamp, digest):
    """Add a digest."""
    self.timestamps.append(timestamp)
    self.digests.append(digest)

  def find_digest(self, timestamp):
    """Find the latest image before the given timestamp."""
    index = bisect.bisect_right(self.timestamps, timestamp)
    if index > 0:
      return self.digests[index - 1]

    logging.error('Failed to find suitable base-builder.')
    return None


def _replace_gitdir(src_dir, file_path):
  """Replace gitdir with a relative path."""
  with open(file_path) as handle:
    lines = handle.readlines()

  new_lines = []
  for line in lines:
    if line.startswith(_GIT_DIR_MARKER):
      absolute_path = line[len(_GIT_DIR_MARKER):].strip()
      if not os.path.isabs(absolute_path):
        # Already relative.
        return

      current_dir = os.path.dirname(file_path)
      # Rebase to /src rather than the host src dir.
      base_dir = current_dir.replace(src_dir, '/src')
      relative_path = os.path.relpath(absolute_path, base_dir)
      logging.info('Replacing absolute submodule gitdir from %s to %s',
                   absolute_path, relative_path)

      line = _GIT_DIR_MARKER + relative_path

    new_lines.append(line)

  with open(file_path, 'w') as handle:
    handle.write(''.join(new_lines))


def _make_gitdirs_relative(src_dir):
  """Make gitdirs relative."""
  for root_dir, _, files in os.walk(src_dir):
    for filename in files:
      if filename != '.git':
        continue

      file_path = os.path.join(root_dir, filename)
      _replace_gitdir(src_dir, file_path)


def _replace_base_builder_digest(dockerfile_path, digest):
  """Replace the base-builder digest in a Dockerfile."""
  with open(dockerfile_path) as handle:
    lines = handle.readlines()

  new_lines = []
  for line in lines:
    if line.strip().startswith('FROM'):
      line = 'FROM gcr.io/oss-fuzz-base/base-builder@' + digest + '\n'

    new_lines.append(line)

  with open(dockerfile_path, 'w') as handle:
    handle.write(''.join(new_lines))


def copy_src_from_docker(project_name, host_dir):
  """Copy /src from docker to the host."""
  # Copy /src to host.
  image_name = 'gcr.io/oss-fuzz/' + project_name
  src_dir = os.path.join(host_dir, 'src')
  if os.path.exists(src_dir):
    shutil.rmtree(src_dir, ignore_errors=True)

  docker_args = [
      '-v',
      host_dir + ':/out',
      image_name,
      'cp',
      '-r',
      '-p',
      '/src',
      '/out',
  ]
  helper.docker_run(docker_args)

  # Submodules can have gitdir entries which point to absolute paths. Make them
  # relative, as otherwise we can't do operations on the checkout on the host.
  _make_gitdirs_relative(src_dir)
  return src_dir


@retry.wrap(_IMAGE_BUILD_TRIES, 2)
def _build_image_with_retries(project_name):
  """Build image with retries."""
  return helper.build_image_impl(helper.Project(project_name))


def get_required_post_checkout_steps(dockerfile_path):
  """Get required post checkout steps (best effort)."""

  checkout_pattern = re.compile(r'\s*RUN\s*(git|svn|hg)')

  # If the build.sh is copied from upstream, we need to copy it again after
  # changing the revision to ensure correct building.
  post_run_pattern = re.compile(r'\s*RUN\s*(.*build\.sh.*(\$SRC|/src).*)')

  with open(dockerfile_path) as handle:
    lines = handle.readlines()

  subsequent_run_cmds = []
  for i, line in enumerate(lines):
    if checkout_pattern.match(line):
      subsequent_run_cmds = []
      continue

    match = post_run_pattern.match(line)
    if match:
      workdir = helper.workdir_from_lines(lines[:i])
      command = match.group(1)
      subsequent_run_cmds.append((workdir, command))

  return subsequent_run_cmds


# pylint: disable=too-many-locals
def build_fuzzers_from_commit(commit,
                              build_repo_manager,
                              host_src_path,
                              build_data,
                              base_builder_repo=None):
  """Builds a OSS-Fuzz fuzzer at a specific commit SHA.

  Args:
    commit: The commit SHA to build the fuzzers at.
    build_repo_manager: The OSS-Fuzz project's repo manager to be built at.
    build_data: A struct containing project build information.
    base_builder_repo: A BaseBuilderRepo.
  Returns:
    0 on successful build or error code on failure.
  """
  oss_fuzz_repo_manager = repo_manager.RepoManager(helper.OSS_FUZZ_DIR)
  num_retry = 1

  def cleanup():
    # Re-copy /src for a clean checkout every time.
    copy_src_from_docker(build_data.project_name,
                         os.path.dirname(host_src_path))
    build_repo_manager.fetch_all_remotes()

  projects_dir = os.path.join('projects', build_data.project_name)
  dockerfile_path = os.path.join(projects_dir, 'Dockerfile')

  for i in range(num_retry + 1):
    build_repo_manager.checkout_commit(commit, clean=False)

    post_checkout_steps = get_required_post_checkout_steps(dockerfile_path)
    for workdir, post_checkout_step in post_checkout_steps:
      logging.info('Running post-checkout step `%s` in %s.', post_checkout_step,
                   workdir)
      helper.docker_run([
          '-w',
          workdir,
          '-v',
          host_src_path + ':' + '/src',
          'gcr.io/oss-fuzz/' + build_data.project_name,
          '/bin/bash',
          '-c',
          post_checkout_step,
      ])

    project = helper.Project(build_data.project_name)
    result = helper.build_fuzzers_impl(project=project,
                                       clean=True,
                                       engine=build_data.engine,
                                       sanitizer=build_data.sanitizer,
                                       architecture=build_data.architecture,
                                       env_to_add=None,
                                       source_path=host_src_path,
                                       mount_path='/src')
    if result or i == num_retry:
      break

    # Retry with an OSS-Fuzz builder container that's closer to the project
    # commit date.
    commit_date = build_repo_manager.commit_date(commit)

    # Find first change in the projects/<PROJECT> directory before the project
    # commit date.
    oss_fuzz_commit, _, _ = oss_fuzz_repo_manager.git([
        'log', '--before=' + commit_date.isoformat(), '-n1', '--format=%H',
        projects_dir
    ],
                                                      check_result=True)
    oss_fuzz_commit = oss_fuzz_commit.strip()
    if not oss_fuzz_commit:
      logging.info(
          'Could not find first OSS-Fuzz commit prior to upstream commit. '
          'Falling back to oldest integration commit.')

      # Find the oldest commit.
      oss_fuzz_commit, _, _ = oss_fuzz_repo_manager.git(
          ['log', '--reverse', '--format=%H', projects_dir], check_result=True)

      oss_fuzz_commit = oss_fuzz_commit.splitlines()[0].strip()

    if not oss_fuzz_commit:
      logging.error('Failed to get oldest integration commit.')
      break

    logging.info('Build failed. Retrying on earlier OSS-Fuzz commit %s.',
                 oss_fuzz_commit)

    # Check out projects/<PROJECT> dir to the commit that was found.
    oss_fuzz_repo_manager.git(['checkout', oss_fuzz_commit, projects_dir],
                              check_result=True)

    # Also use the closest base-builder we can find.
    if base_builder_repo:
      base_builder_digest = base_builder_repo.find_digest(commit_date)
      if not base_builder_digest:
        return False

      logging.info('Using base-builder with digest %s.', base_builder_digest)
      _replace_base_builder_digest(dockerfile_path, base_builder_digest)

    # Rebuild image and re-copy src dir since things in /src could have changed.
    if not _build_image_with_retries(build_data.project_name):
      logging.error('Failed to rebuild image.')
      return False

    cleanup()

  cleanup()
  return result


def detect_main_repo(project_name, repo_name=None, commit=None):
  """Checks a docker image for the main repo of an OSS-Fuzz project.

  Note: The default is to use the repo name to detect the main repo.

  Args:
    project_name: The name of the oss-fuzz project.
    repo_name: The name of the main repo in an OSS-Fuzz project.
    commit: A commit SHA that is associated with the main repo.

  Returns:
    A tuple containing (the repo's origin, the repo's path).
  """

  if not repo_name and not commit:
    logging.error(
        'Error: can not detect main repo without a repo_name or a commit.')
    return None, None
  if repo_name and commit:
    logging.info(
        'Both repo name and commit specific. Using repo name for detection.')

  # Change to oss-fuzz main directory so helper.py runs correctly.
  utils.chdir_to_root()
  if not _build_image_with_retries(project_name):
    logging.error('Error: building %s image failed.', project_name)
    return None, None
  docker_image_name = 'gcr.io/oss-fuzz/' + project_name
  command_to_run = [
      'docker', 'run', '--rm', '-t', docker_image_name, 'python3',
      os.path.join('/opt', 'cifuzz', 'detect_repo.py')
  ]
  if repo_name:
    command_to_run.extend(['--repo_name', repo_name])
  else:
    command_to_run.extend(['--example_commit', commit])
  out, _, _ = utils.execute(command_to_run)
  match = re.search(r'\bDetected repo: ([^ ]+) ([^ ]+)', out.rstrip())
  if match and match.group(1) and match.group(2):
    return match.group(1), match.group(2)

  logging.error('Failed to detect repo:\n%s', out)
  return None, None


def load_base_builder_repo():
  """Get base-image digests."""
  gcloud_path = spawn.find_executable('gcloud')
  if not gcloud_path:
    logging.warning('gcloud not found in PATH.')
    return None

  result, _, _ = utils.execute([
      gcloud_path,
      'container',
      'images',
      'list-tags',
      'gcr.io/oss-fuzz-base/base-builder',
      '--format=json',
      '--sort-by=timestamp',
  ],
                               check_result=True)
  result = json.loads(result)

  repo = BaseBuilderRepo()
  for image in result:
    timestamp = datetime.datetime.fromisoformat(
        image['timestamp']['datetime']).astimezone(datetime.timezone.utc)
    repo.add_digest(timestamp, image['digest'])

  return repo


def main():
  """Main function."""
  logging.getLogger().setLevel(logging.INFO)

  parser = argparse.ArgumentParser(
      description='Build fuzzers at a specific commit')
  parser.add_argument('--project_name',
                      help='The name of the project where the bug occurred.',
                      required=True)
  parser.add_argument('--commit',
                      help='The newest commit SHA to be bisected.',
                      required=True)
  parser.add_argument('--engine',
                      help='The default is "libfuzzer".',
                      default='libfuzzer')
  parser.add_argument('--sanitizer',
                      default='address',
                      help='The default is "address".')
  parser.add_argument('--architecture', default='x86_64')

  args = parser.parse_args()

  repo_url, repo_path = detect_main_repo(args.project_name, commit=args.commit)

  if not repo_url or not repo_path:
    raise ValueError('Main git repo can not be determined.')

  with tempfile.TemporaryDirectory() as tmp_dir:
    host_src_dir = copy_src_from_docker(args.project_name, tmp_dir)
    build_repo_manager = repo_manager.RepoManager(
        os.path.join(host_src_dir, os.path.basename(repo_path)))
    base_builder_repo = load_base_builder_repo()

    build_data = BuildData(project_name=args.project_name,
                           engine=args.engine,
                           sanitizer=args.sanitizer,
                           architecture=args.architecture)
    if not build_fuzzers_from_commit(args.commit,
                                     build_repo_manager,
                                     host_src_dir,
                                     build_data,
                                     base_builder_repo=base_builder_repo):
      raise RuntimeError('Failed to build.')


if __name__ == '__main__':
  main()
