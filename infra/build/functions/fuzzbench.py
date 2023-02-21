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


def get_engine_project_image(fuzzing_engine, project):
  """Returns the name of an image used to build |project| with
  |fuzzing_engine|."""
  return f'gcr.io/oss-fuzz-base/{fuzzing_engine}/{project.name}'


def get_env(project, build):
  """Gets the environment for fuzzbench/oss-fuzz-on-demand."""
  env = build_project.get_env(project.fuzzing_language, build)
  env.append(f'FUZZBENCH_PATH={FUZZBENCH_PATH}')
  env.append('FORCE_LOCAL=1')
  env.append(f'PROJECT={project.name}')
  env.append('OSS_FUZZ_ON_DEMAND=1')
  env.append('OUT=/workspace/out')
  env.extend([
      'FUZZ_TARGET=vulnerable', f'BENCHMARK={project.name}',
      'EXPERIMENT_TYPE=bug'
  ])
  return env


def get_build_fuzzers_step(fuzzing_engine, project, env, build):
  """Returns the build_fuzzers step to build |project| with |fuzzing_engine|,
  for fuzzbench/oss-fuzz-on-demand."""
  steps = []
  engine_dockerfile_path = os.path.join(FUZZBENCH_PATH, 'fuzzers',
                                        fuzzing_engine, 'builder.Dockerfile')
  build_args = [
      'build', '--build-arg', f'parent_image=gcr.io/oss-fuzz/{project.name}',
      '--tag',
      get_engine_project_image(fuzzing_engine,
                               project), '--file', engine_dockerfile_path,
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
  steps.append(engine_step)
  compile_project_step = {
      'name':
          get_engine_project_image(fuzzing_engine, project),
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
  return steps


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
  fuzzing_engine = 'libfuzzer'

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

  build = build_project.Build(fuzzing_engine, 'address', 'x86_64')
  env = get_env(project, build)

  steps += get_build_fuzzers_step(fuzzing_engine, project, env, build)
  run_fuzzer_step = {
      'name':
          get_engine_project_image(fuzzing_engine, project),
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
           'fuzzbench_run_fuzzer'),
      ],
  }
  steps.append(run_fuzzer_step)

  build = build_project.Build('coverage', 'address', 'x86_64')
  env = get_env(project, build)
  env.append(f'FUZZER={fuzzing_engine}')
  steps += get_build_fuzzers_step('coverage', project, env, build)
  steps += [{
      'args': ['fuzzbench_measure'],
      'env': env,
      'name': get_engine_project_image('coverage', project),
      'volumes': [{
          'name': 'fuzzbench_path',
          'path': FUZZBENCH_PATH,
      }],
  }]
  return steps


def main():
  """Build and run fuzzbench for OSS-Fuzz projects."""
  return build_project.build_script_main('Does a FuzzBench run.',
                                         get_build_steps, FUZZBENCH_BUILD_TYPE)


if __name__ == '__main__':
  sys.exit(main())
