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
"""Does fuzzbench runs locally."""
# TODO It is worth checking https://github.com/google/oss-fuzz/pull/12833 for
# insights on making this code less specific for OSS-Fuzz on Demand.

import os
import re
import shutil
import subprocess
import sys
import tempfile
import time

import build_lib
import build_project
import fuzzbench

GCB_WORKSPACE_DIR = fuzzbench.GCB_WORKSPACE_DIR
FUZZBENCH_PATH = fuzzbench.FUZZBENCH_PATH
DOCKER_BUILDER_IMAGE = 'gcr.io/cloud-builders/docker'
LOG_FILE_PATH = os.path.join(os.path.dirname(__file__),
                             'fuzzbench_local_run_log.txt')


def run_step_locally(temp_dir, local_fuzzbench_path, step, i, log_file):
  """Run a build step locally."""
  log_file.write(f'--- Step {i}: ---\n')
  log_file.write(f'Step_details:\n{step}\n')
  log_file.write('------\n')

  image_name = step.get('name')
  args = step.get('args', [])
  env_list = step.get('env', [])
  volumes = step.get('volumes', [])

  if not image_name:
    raise Exception(f'Error: Step {i} has no "name" field.\n')
  if not args:
    raise Exception(f'Error: Step {i} has no "args" field.\n')
  if args[0] == 'push':
    log_file.write(f'Skipping step {i} because it is a push step.\n')
    return

  step_container_work_dir = os.path.join(GCB_WORKSPACE_DIR, step.get('dir', ''))

  # This is needed because when running a container inside of a container, the
  # mount point of the second container is also in the host machine and not in
  # the first container
  if args[0] == 'run' and args[1] == '-v' and GCB_WORKSPACE_DIR in args[2]:
    args[2] = args[2].replace(GCB_WORKSPACE_DIR, temp_dir, 1)

  docker_command = ['docker', 'run', '--rm', '--cpus=0.5']
  docker_command.extend(['-w', step_container_work_dir])
  docker_command.extend(['-v', f'{temp_dir}:{GCB_WORKSPACE_DIR}'])

  mount_fuzzbench = any(vol.get('path') == FUZZBENCH_PATH for vol in volumes)
  if mount_fuzzbench:
    docker_command.extend(['-v', f'{local_fuzzbench_path}:{FUZZBENCH_PATH}'])

  if image_name == DOCKER_BUILDER_IMAGE:
    docker_command.extend(['-v', '/var/run/docker.sock:/var/run/docker.sock'])

  for env_var in env_list:
    docker_command.extend(['-e', env_var])

  docker_command.append(image_name)
  docker_command.extend(args)

  # Local runs use local changes
  if 'https://github.com/google/oss-fuzz.git' in docker_command:
    oss_fuzz_dir = os.path.dirname(
        os.path.dirname(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
    docker_command = ['cp', '-r', f'{oss_fuzz_dir}', f'{temp_dir}']

  if '$$' in docker_command[-1]:
    docker_command[-1] = re.sub(r'\$\$([a-zA-Z0-9_]+)', r'"$\1"',
                                docker_command[-1])

  log_file.write(f'Executing Docker Command:\n')
  log_file.write(
      ' '.join(map(lambda x: f'"{x}"' if ' ' in x else x, docker_command)) +
      '\n')
  log_file.flush()

  try:
    start_time = time.time()
    result = subprocess.run(docker_command,
                            check=True,
                            capture_output=True,
                            text=True)
    end_time = time.time()
    log_file.write(
        f'--- Container STDOUT ---\n'
        f'{result.stdout}'
        f'--- Container STDERR ---\n'
        f'{result.stderr}'
        f'--- Step {i} completed successfully --- Took {end_time - start_time}s\n\n'
    )
  except subprocess.CalledProcessError as e:
    if e.returncode == 124:
      end_time = time.time()
      log_file.write(
          f'Caught timeout: {e}\n'
          f'--- Step {i} completed with a timeout --- Took {end_time - start_time}s\n\n'
      )
    else:
      log_file.write('--- DOCKER RUN ERROR ---\n'
                     f'Docker command failed with exit code {e.returncode}\n'
                     '--- Container STDOUT ---\n'
                     f'{e.stdout}'
                     '--- Container STDERR ---\n'
                     f'{e.stderr}'
                     f'Failed Step Details: {step}\n'
                     f'Failed Docker Command: {" ".join(docker_command)}\n'
                     f'Execution failed at step {i}\n')
      sys.exit()
  except Exception as e:
    log_file.write('--- UNEXPECTED ERROR ---\n'
                   f'An unexpected error occurred during step {i}: {e}\n'
                   f'Failed Step Details: {step}\n'
                   f'Failed Docker Command: {" ".join(docker_command)}\n'
                   f'Execution failed at step {i}\n')
    sys.exit()


def remove_temp_dir_content(temp_dir, i, log_file):
  """Remove temporary directory using Docker to avoid permission issues."""
  remove_temp_dir_step = {
      'name': 'bash',
      'args': ['sh', '-c', f'rm -rf {GCB_WORKSPACE_DIR}/*']
  }
  run_step_locally(temp_dir, '', remove_temp_dir_step, i, log_file)


def run_steps_locally(steps,
                      temp_dir=None,
                      log_file_path=LOG_FILE_PATH,
                      testing=False):
  """Executes Cloud Build steps locally by running each step's command
  inside the specified container using 'docker run'. Log is written in
  to |log_file_path|"""
  with open(log_file_path, 'w') as log_file:
    if not steps:
      log_file.write('No steps provided to run.\n')
      return

    log_file.write(f'--- Starting Local Execution with Docker ---\n')
    log_file.flush()

    if not temp_dir:
      temp_dir = tempfile.mkdtemp()
    local_fuzzbench_path = os.path.join(temp_dir, 'fuzzbench_vol')
    os.makedirs(local_fuzzbench_path, exist_ok=True)

    for i, step in enumerate(steps):
      run_step_locally(temp_dir, local_fuzzbench_path, step, i, log_file)
      log_file.flush()
    log_file.write(f'--- Local Execution Finished ---\n')
    if not testing:
      log_file.write(f'--- Starting temporary directory removal ---\n')
      remove_temp_dir_content(temp_dir, i + 1, log_file)
      shutil.rmtree(temp_dir)
      log_file.write(f'--- Removed temporary directory ---\n')


def main():
  """Local fuzzbench build and run for OSS-Fuzz projects. Excludes steps on
  which non local storage is written."""
  args = build_project.parse_args('local_fuzzbench_run', None)
  project_name = args.projects[0]
  project_yaml, dockerfile_lines = build_project.get_project_data(project_name)
  config = build_project.create_config(args, fuzzbench.FUZZBENCH_BUILD_TYPE)
  project = build_project.Project(project_name, project_yaml, dockerfile_lines)
  fuzz_target_name = config.fuzz_target
  if not fuzz_target_name:
    fuzz_target_name = fuzzbench.get_fuzz_target_name(project.name)
    if not fuzz_target_name:
      raise Exception(
          'Fuzz Introspector Web API did not find a fuzz target. Provide one')
  steps = fuzzbench.get_fuzzbench_setup_steps()
  steps += build_lib.get_project_image_steps(project.name,
                                             project.image,
                                             project.fuzzing_language,
                                             config=config)
  build = build_project.Build(config.fuzzing_engine, 'address', 'x86_64')
  env = fuzzbench.get_env(project, build, fuzz_target_name)
  steps += fuzzbench.get_build_fuzzers_steps(config.fuzzing_engine, project,
                                             env)
  env_dict = {string.split('=')[0]: string.split('=')[1] for string in env}
  steps += fuzzbench.get_gcs_corpus_steps(config.fuzzing_engine, project,
                                          env_dict)
  steps += fuzzbench.get_build_ood_image_steps(config.fuzzing_engine, project,
                                               env_dict)
  steps += fuzzbench.get_push_and_run_ood_image_steps(config.fuzzing_engine,
                                                      project, env_dict)
  steps += fuzzbench.get_extract_crashes_steps(config.fuzzing_engine, project,
                                               env_dict)

  run_steps_locally(steps)
  return 0


if __name__ == '__main__':
  sys.exit(main())
