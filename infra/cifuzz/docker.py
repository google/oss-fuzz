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
"""Module for dealing with docker."""
import logging
import os
import subprocess
import sys
import tempfile

import process_utils

# pylint: disable=wrong-import-position,import-error
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import utils

BASE_BUILDER_TAG = 'gcr.io/oss-fuzz-base/base-builder'
BASE_RUNNER_TAG = 'gcr.io/oss-fuzz-base/base-runner'
MSAN_LIBS_BUILDER_TAG = 'gcr.io/oss-fuzz-base/msan-libs-builder'
PROJECT_TAG_PREFIX = 'gcr.io/oss-fuzz/'


def get_project_image_name(project):
  """Returns the name of the project builder image for |project_name|."""
  return PROJECT_TAG_PREFIX + project


def delete_images(images):
  """Deletes |images|."""
  command = ['docker', 'rmi', '-f'] + images
  utils.execute(command)
  utils.execute(['docker', 'builder', 'prune', '-f'])


def stop_docker_container(container_id, wait_time=1):
  """Stops the docker container, |container_id|. Returns True on success."""
  result = subprocess.run(
      ['docker', 'stop', container_id, '-t',
       str(wait_time)], check=False)
  return result.returncode == 0


def _handle_timed_out_container_process(process, cid_filename):
  """Stops the docker container |process| (and child processes) that has a
  container id in |cid_filename|. Returns stdout and stderr of |process|. This
  function is a helper for run_container_command and should only be invoked by
  it. Returns None for each if we can't get stdout and stderr."""
  # Be cautious here. We probably aren't doing anything essential for CIFuzz to
  # function. So try extra hard not to throw uncaught exceptions.
  try:
    with open(cid_filename, 'r') as cid_file_handle:
      container_id = cid_file_handle.read()
  except FileNotFoundError:
    logging.error('cid_file not found.')
    return None, None

  if not stop_docker_container(container_id):
    logging.error('Failed to stop docker container: %s', container_id)
    return None, None

  # Use a timeout so we don't wait forever.
  return process.communicate(timeout=1)


def run_container_command(command_arguments, timeout=None):
  """Runs |command_arguments| as a "docker run" command. Returns ProcessResult.
  Stops the command if timeout is reached."""
  command = ['docker', 'run', '--rm', '--privileged']
  timed_out = False
  with tempfile.TemporaryDirectory() as temp_dir:
    # Use temp dir instead of file because docker complains if file exists
    # already.
    cid_file_path = os.path.join(temp_dir, 'cidfile')
    command.extend(['--cidfile', cid_file_path])
    command.extend(command_arguments)
    logging.info('Running command: %s', ' '.join(command))
    process = subprocess.Popen(command,
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
    try:
      stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
      logging.warning('Command timed out: %s', ' '.join(command))
      stdout, stderr = _handle_timed_out_container_process(
          process, cid_file_path)
      timed_out = True

    return process_utils.ProcessResult(process, stdout, stderr, timed_out)
