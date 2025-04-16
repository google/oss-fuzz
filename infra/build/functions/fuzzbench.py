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


def get_gcs_public_corpus_url(project, fuzz_target_name):
  """Returns the url of a public gcs seed corpus."""
  return (
      f'https://storage.googleapis.com/{project.name}-backup.clusterfuzz-'
      f'external.appspot.com/corpus/libFuzzer/{project.name}_{fuzz_target_name}'
      f'/public.zip')


def get_env(project, build, config):
  """Gets the environment for fuzzbench/oss-fuzz-on-demand."""
  env = build_project.get_env(project.fuzzing_language, build)
  env.append(f'FUZZBENCH_PATH={FUZZBENCH_PATH}')
  env.append('FORCE_LOCAL=1')
  env.append(f'PROJECT={project.name}')
  env.append('OSS_FUZZ_ON_DEMAND=1')
  env.extend([
      f'FUZZ_TARGET={config.fuzz_target}', f'BENCHMARK={project.name}',
      'EXPERIMENT_TYPE=bug'
  ])
  return env


def get_fuzzbench_setup_steps():
  """Returns the build steps required to set up fuzzbench on oss-fuzz-on-demand
  build."""
  fuzzbench_setup_steps = [
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
  return fuzzbench_setup_steps


def get_build_fuzzers_steps(fuzzing_engine, project, env, build):
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
          (f'rm -r /out && cd /src && cd {project.workdir} && '
           f'mkdir -p {build.out} && compile'),
      ],
  }
  steps.append(compile_project_step)

  return steps


def get_gcs_corpus_steps(fuzzing_engine, project, build, env_dict):
  """Returns the build steps to download corpus from GCS (if it exists) and
  use it on OSS-fuzz on Demand."""
  steps = []

  corpus_path = '/workspace/gcs_corpus'
  corpus_filename = 'public.zip'
  fuzz_target_name = env_dict["FUZZ_TARGET"]
  corpus_url = get_gcs_public_corpus_url(project, fuzz_target_name)
  download_and_use_corpus_step = {
      'name':
          get_engine_project_image(fuzzing_engine, project),
      'args': [
          'bash', '-c', f'if wget --spider --quiet {corpus_url}; then '
          f'  echo "URL exists. Downloading..." && mkdir -p {corpus_path} && '
          f'  cd {corpus_path} && wget -O {corpus_filename} {corpus_url};'
          f'else '
          f'  echo "URL does not exist. Skipping download."; '
          f'fi'
      ],
  }
  steps.append(download_and_use_corpus_step)

  seed_corpus_path = f'{build.out}/{fuzz_target_name}_seed_corpus.zip'
  gcs_corpus_path = f'{corpus_path}/{corpus_filename}'
  update_corpus_step = {
      'name':
          get_engine_project_image(fuzzing_engine, project),
      'args': [
          'bash', '-c', f'if test -f "{gcs_corpus_path}"; then '
          f'  mv {gcs_corpus_path} {seed_corpus_path} && '
          f'  rm -r {corpus_path};'
          f'else '
          f'  echo "There is no corpus to update."; '
          f'fi'
      ],
  }
  steps.append(update_corpus_step)

  return steps


def get_build_and_push_ood_image_steps(fuzzing_engine, project, env_dict,
                                       build):
  """Returns the build steps to create and push the oss-fuzz-on-demand
  self-contained image."""
  steps = []

  copy_runtime_essential_files_step = {
      'name':
          get_engine_project_image(fuzzing_engine, project),
      'volumes': [{
          'name': 'fuzzbench_path',
          'path': FUZZBENCH_PATH,
      }],
      'args': [
          'bash', '-c', 'cp /usr/local/bin/fuzzbench_run_fuzzer '
          '/workspace/fuzzbench_run_fuzzer.sh  && '
          f'cp -r {FUZZBENCH_PATH} /workspace && ls /workspace'
      ],
  }
  steps.append(copy_runtime_essential_files_step)

  runtime_image_tag = f'us-central1-docker.pkg.dev/oss-fuzz/unsafe/ood/{fuzzing_engine}/{project.name}'
  fuzzer_runtime_dockerfile_path = os.path.join('/workspace' + FUZZBENCH_PATH,
                                                'fuzzers', fuzzing_engine,
                                                'runner.Dockerfile')
  build_runtime_step = {
      'name':
          'gcr.io/cloud-builders/docker',
      'args': [
          'build', '--tag', runtime_image_tag, '--file',
          fuzzer_runtime_dockerfile_path,
          os.path.join('/workspace' + FUZZBENCH_PATH, 'fuzzers')
      ]
  },
  steps.append(build_runtime_step)

  oss_fuzz_on_demand_dockerfile_path = "/workspace/oss-fuzz/infra/build/functions/ood.Dockerfile"
  build_out_path_without_workspace = build.out[10:]
  build_ood_image_step = {
      'name':
          'gcr.io/cloud-builders/docker',
      'args': [
          'build', '--tag', runtime_image_tag, '--file',
          oss_fuzz_on_demand_dockerfile_path, '--build-arg',
          f'runtime_image={runtime_image_tag}', '--build-arg',
          f'BUILD_OUT_PATH={build_out_path_without_workspace}', '--build-arg',
          f'FUZZING_ENGINE={env_dict["FUZZING_ENGINE"]}', '--build-arg',
          f'FUZZ_TARGET={env_dict["FUZZ_TARGET"]}', '--build-arg',
          f'FUZZBENCH_PATH={FUZZBENCH_PATH}', '--build-arg',
          f'BENCHMARK={env_dict["BENCHMARK"]}', '/workspace'
      ]
  }
  steps.append(build_ood_image_step)

  push_ood_image_step = {
      'name': 'gcr.io/cloud-builders/docker',
      'args': ['push', runtime_image_tag]
  }
  steps.append(push_ood_image_step)

  return steps


def get_build_steps(  # pylint: disable=too-many-locals, too-many-arguments
    project_name, project_yaml, dockerfile_lines, config):
  """Returns build steps for project."""
  project = build_project.Project(project_name, project_yaml, dockerfile_lines)
  if project.disabled:
    logging.info('Project "%s" is disabled.', project.name)
    return []

  steps = get_fuzzbench_setup_steps()

  steps += build_lib.get_project_image_steps(project.name,
                                             project.image,
                                             project.fuzzing_language,
                                             config=config)

  build = build_project.Build(config.fuzzing_engine, 'address', 'x86_64')
  env = get_env(project, build, config)

  steps += get_build_fuzzers_steps(config.fuzzing_engine, project, env, build)

  env_dict = {string.split("=")[0]: string.split("=")[1] for string in env}

  steps += get_gcs_corpus_steps(config.fuzzing_engine, project, build, env_dict)

  steps += get_build_and_push_ood_image_steps(config.fuzzing_engine, project,
                                              env_dict, build)

  return steps


def main():
  """Build and run fuzzbench for OSS-Fuzz projects."""
  return build_project.build_script_main('Does a FuzzBench run.',
                                         get_build_steps, FUZZBENCH_BUILD_TYPE)


if __name__ == '__main__':
  sys.exit(main())