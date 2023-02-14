#!/usr/bin/env python3
#
# Copyright 2023 Google LLC
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
"""Does fuzzbench runs on Google Cloud Build."""

import logging
import os
import sys

import build_lib
import build_project

FUZZBENCH_BUILD_TYPE = 'coverage'
FUZZBENCH_PATH = '/fuzzbench'


def get_build_steps(  # pylint: disable=too-many-locals, too-many-arguments
    project_name, project_yaml, dockerfile_lines, image_project,
    base_images_project, config):
  """Returns build steps for project."""
  del base_images_project
  project = build_project.Project(project_name, project_yaml, dockerfile_lines,
                                  image_project)
  if project.disabled:
    logging.info('Project "%s" is disabled.', project.name)
    return []

  config = build_project.Config(config.testing, None, config.repo,
                                config.branch, config.parallel, config.upload)

  # TODO(metzman): Make this a command line argument
  fuzzing_engine = 'libafl'

  steps = [
      {
          'args': [
              'clone', 'https://github.com/google/fuzzbench', '--depth', '1',
              FUZZBENCH_PATH
          ],
          'name': 'gcr.io/cloud-builders/git',
          'volumes': [{
              'name': 'fuzzbench_path',
              'path': FUZZBENCH_PATH,
          }],
      },
      {
          'name': 'gcr.io/cloud-builders/docker',
          'args': ['pull', 'gcr.io/oss-fuzz-base/base-builder-fuzzbench']
      },
      {  # TODO(metzman): Don't overwrite base-builder
          'name':
              'gcr.io/cloud-builders/docker',
          'args': [
              'tag', 'gcr.io/oss-fuzz-base/base-builder-fuzzbench',
              'gcr.io/oss-fuzz-base/base-builder'
          ]
      },
  ]

  steps += build_lib.get_project_image_steps(project.name,
                                             project.image,
                                             project.fuzzing_language,
                                             config=config)

  engine_dockerfile_path = os.path.join(FUZZBENCH_PATH, 'fuzzers',
                                        fuzzing_engine, 'builder.Dockerfile')
  build_args = [
      'build', '--build-arg', f'parent_image=gcr.io/oss-fuzz/{project.name}',
      '--tag', project.image, '--file', engine_dockerfile_path,
      os.path.join(FUZZBENCH_PATH, 'fuzzers')
  ]
  engine_step = [
      {
          'name': 'gcr.io/cloud-builders/docker',
          'args': build_args,
          'volumes': [{
              'name': 'fuzzbench_path',
              'path': FUZZBENCH_PATH,
          }],
      },
  ]
  steps += engine_step
  build = build_project.Build(fuzzing_engine, 'address', 'x86_64')
  env = build_project.get_env(project.fuzzing_language, build)
  env.append(f'FUZZBENCH_PATH={FUZZBENCH_PATH}')
  env.append(f'PROJECT={project.name}')
  env.append('OSS_FUZZ_ON_DEMAND=1')
  compile_project_step = {
      'name':
          project.image,
      'env':
          env,
      'volumes': [{
          'name': 'fuzzbench_path',
          'path': FUZZBENCH_PATH,
      }],
      'args': [
          'bash',
          '-c',
          # Remove /out to make sure there are non instrumented binaries.
          # `cd /src && cd {workdir}` (where {workdir} is parsed from the
          # Dockerfile). Container Builder overrides our workdir so we need
          # to add this step to set it back.
          (f'ls /fuzzbench && rm -r /out && cd /src && cd {project.workdir} && '
           f'mkdir -p {build.out} && compile'),
      ],
  }
  steps.append(compile_project_step)
  env.extend(['FUZZ_TARGET=iccprofile_atf', f'BENCHMARK={project.name}'])
  run_fuzzer_step = {
      'name':
          project.image,
      'env':
          env,
      'volumes': [{
          'name': 'fuzzbench_path',
          'path': FUZZBENCH_PATH,
      }],
      'args': [
          'bash',
          '-c',
          (f'ls /fuzzbench && cd {build.out} && ls {build.out} && '
           f'fuzzbench_run_fuzzer'),
      ],
  }
  steps.append(run_fuzzer_step)

  return steps


def main():
  """Build and run fuzzbench for OSS-Fuzz projects."""
  return build_project.build_script_main('Does a FuzzBench run.',
                                         get_build_steps, FUZZBENCH_BUILD_TYPE)


if __name__ == '__main__':
  sys.exit(main())
