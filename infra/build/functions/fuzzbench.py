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

INFRA_DIR = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.append(os.path.join(INFRA_DIR, 'cifuzz'))
import clusterfuzz_deployment
import config_utils

FUZZBENCH_BUILD_TYPE = 'coverage'
FUZZBENCH_PATH = '/fuzzbench'
GCB_WORKSPACE_DIR = '/workspace'
OOD_OUTPUT_CORPUS_DIR = f'{GCB_WORKSPACE_DIR}/ood_output_corpus'
OOD_CRASHES_DIR = f'{GCB_WORKSPACE_DIR}/crashes'


def get_engine_project_image_name(fuzzing_engine, project):
  """Returns the name of an image used to build |project| with
  |fuzzing_engine|."""
  return f'gcr.io/oss-fuzz-base/{fuzzing_engine}/{project.name}'


def get_ood_image_name(fuzzing_engine, project):
  """Returns the name of an OSS-Fuzz on Demand image."""
  # TODO(andrenribeiro): Abstract the OOD image name generation to a separate
  # location.
  return f'us-central1-docker.pkg.dev/oss-fuzz/unsafe/ood/{fuzzing_engine}/{project.name}'


def get_gcs_public_corpus_url(project, fuzz_target_name):
  """Returns the url of a public gcs seed corpus."""
  return (
      f'https://storage.googleapis.com/{project.name}-backup.clusterfuzz-'
      f'external.appspot.com/corpus/libFuzzer/{project.name}_{fuzz_target_name}'
      f'/public.zip')


def get_latest_libfuzzer_build(project_name):
  """Returns the latest LibFuzzer build gsutil URI and the build file name."""
  # Mandatory environment variables required to obtain the latest build name
  os.environ['CIFUZZ_TEST'] = 'True'
  os.environ['OSS_FUZZ_PROJECT_NAME'] = project_name

  config = config_utils.RunFuzzersConfig()
  deployment = clusterfuzz_deployment.OSSFuzz(config, None)
  latest_build_filename = deployment.get_latest_build_name()
  build_uri = f'gs://clusterfuzz-builds/{project_name}/{latest_build_filename}'

  return build_uri, latest_build_filename


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


def get_build_fuzzers_steps(fuzzing_engine, project, env):
  """Returns the build_fuzzers step to build |project| with |fuzzing_engine|,
  for fuzzbench/oss-fuzz-on-demand."""
  steps = []
  engine_dockerfile_path = os.path.join(FUZZBENCH_PATH, 'fuzzers',
                                        fuzzing_engine, 'builder.Dockerfile')
  build_args = [
      'build', '--build-arg', f'parent_image=gcr.io/oss-fuzz/{project.name}',
      '--tag',
      get_engine_project_image_name(fuzzing_engine,
                                    project), '--file', engine_dockerfile_path,
      os.path.join(FUZZBENCH_PATH, 'fuzzers')
  ]
  engine_step = {
      'name': 'gcr.io/cloud-builders/docker',
      'args': build_args,
      'volumes': [{
          'name': 'fuzzbench_path',
          'path': FUZZBENCH_PATH,
      }],
  }
  steps.append(engine_step)

  compile_project_step = {
      'name':
          get_engine_project_image_name(fuzzing_engine, project),
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
           'mkdir -p $${OUT} && compile'),
      ],
  }
  steps.append(compile_project_step)

  return steps


def get_gcs_corpus_steps(fuzzing_engine, project, env_dict):
  """Returns the build steps to download corpus from GCS (if it exists) and
  use it on oss-fuzz-on-demand."""
  steps = []

  corpus_path = f'{GCB_WORKSPACE_DIR}/gcs_corpus'
  corpus_filename = 'public.zip'
  fuzz_target_name = env_dict["FUZZ_TARGET"]
  corpus_url = get_gcs_public_corpus_url(project, fuzz_target_name)
  download_and_use_corpus_step = {
      'name':
          get_engine_project_image_name(fuzzing_engine, project),
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

  seed_corpus_path = f'{env_dict["OUT"]}/{fuzz_target_name}_seed_corpus.zip'
  gcs_corpus_path = f'{corpus_path}/{corpus_filename}'
  update_corpus_step = {
      'name':
          get_engine_project_image_name(fuzzing_engine, project),
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


def get_build_ood_image_steps(fuzzing_engine, project, env_dict):
  """Returns the build steps to create the oss-fuzz-on-demand self-contained
  image. Executing docker run on this image starts the fuzzing process."""
  steps = []

  copy_runtime_essential_files_step = {
      'name':
          get_engine_project_image_name(fuzzing_engine, project),
      'volumes': [{
          'name': 'fuzzbench_path',
          'path': FUZZBENCH_PATH,
      }],
      'args': [
          'bash', '-c', 'cp /usr/local/bin/fuzzbench_run_fuzzer '
          f'{GCB_WORKSPACE_DIR}/fuzzbench_run_fuzzer.sh  && '
          f'cp -r {FUZZBENCH_PATH} {GCB_WORKSPACE_DIR} && '
          f'ls {GCB_WORKSPACE_DIR}'
      ],
  }
  steps.append(copy_runtime_essential_files_step)

  ood_image = get_ood_image_name(fuzzing_engine, project)
  fuzzer_runtime_dockerfile_path = os.path.join(
      GCB_WORKSPACE_DIR + FUZZBENCH_PATH, 'fuzzers', fuzzing_engine,
      'runner.Dockerfile')
  build_runtime_step = {
      'name':
          'gcr.io/cloud-builders/docker',
      'args': [
          'build', '--tag', ood_image, '--file', fuzzer_runtime_dockerfile_path,
          os.path.join(GCB_WORKSPACE_DIR + FUZZBENCH_PATH, 'fuzzers')
      ]
  }
  steps.append(build_runtime_step)

  oss_fuzz_on_demand_dockerfile_path = f'{GCB_WORKSPACE_DIR}/oss-fuzz/infra/build/functions/ood.Dockerfile'
  build_out_path_without_workspace = env_dict["OUT"][10:]
  build_ood_image_step = {
      'name':
          'gcr.io/cloud-builders/docker',
      'args': [
          'build', '--tag', ood_image, '--file',
          oss_fuzz_on_demand_dockerfile_path, '--build-arg',
          f'BENCHMARK={env_dict["BENCHMARK"]}', '--build-arg',
          f'BUILD_OUT_PATH={build_out_path_without_workspace}', '--build-arg',
          f'FUZZBENCH_PATH={FUZZBENCH_PATH}', '--build-arg',
          f'FUZZING_ENGINE={env_dict["FUZZING_ENGINE"]}', '--build-arg',
          f'FUZZ_TARGET={env_dict["FUZZ_TARGET"]}', '--build-arg',
          f'OOD_OUTPUT_CORPUS_DIR={OOD_OUTPUT_CORPUS_DIR}', '--build-arg',
          f'runtime_image={ood_image}', GCB_WORKSPACE_DIR
      ]
  }
  steps.append(build_ood_image_step)

  return steps


def get_push_and_run_ood_image_steps(fuzzing_engine, project, env_dict):
  """Returns the build steps to push and run the oss-fuzz-on-demand
  self-contained image."""
  steps = []

  ood_image = get_ood_image_name(fuzzing_engine, project)

  push_ood_image_step = {
      'name': 'gcr.io/cloud-builders/docker',
      'args': ['push', ood_image]
  }
  steps.append(push_ood_image_step)

  # This step also copies fuzzing output corpus to $OOD_OUTPUT_CORPUS_DIR
  run_ood_image_step = {
      'name':
          'gcr.io/cloud-builders/docker',
      'args': [
          'run', '-v', f'{GCB_WORKSPACE_DIR}:{GCB_WORKSPACE_DIR}', ood_image
      ]
  }
  steps.append(run_ood_image_step)

  return steps


def get_extract_crashes_steps(fuzzing_engine, project, env_dict):
  """Returns the build steps to download a LibFuzzer build and use it to extract
  crashes from the fuzzing output."""
  steps = []

  libfuzzer_build_dir = f'{GCB_WORKSPACE_DIR}/libfuzzer_build/'
  create_libfuzzer_build_dir_step = {
      'name': get_engine_project_image_name(fuzzing_engine, project),
      'args': ['bash', '-c', f'mkdir -p {libfuzzer_build_dir}']
  }
  steps.append(create_libfuzzer_build_dir_step)

  build_uri, build_filename = get_latest_libfuzzer_build(project.name)
  download_libfuzzer_build_step = {
      'name': 'gcr.io/cloud-builders/gsutil',
      'args': ['-m', 'cp', '-r', build_uri, libfuzzer_build_dir]
  }
  steps.append(download_libfuzzer_build_step)

  extract_crashes_step = {
      'name':
          get_engine_project_image_name(fuzzing_engine, project),
      'args': [
          'bash', '-c', f'unzip {libfuzzer_build_dir}{build_filename} '
          f'-d {libfuzzer_build_dir} && mkdir -p {OOD_CRASHES_DIR} && '
          f'{libfuzzer_build_dir}{env_dict["FUZZ_TARGET"]} {OOD_OUTPUT_CORPUS_DIR} '
          f'-runs=0 -artifact_prefix={OOD_CRASHES_DIR}/; '
          f'echo "\nCrashes found by OOD:" && ls {OOD_CRASHES_DIR} '
      ],
  }
  steps.append(extract_crashes_step)

  return steps


def get_upload_testcase_steps(project, env_dict):
  """Returns the build steps to upload a testcase in the ClusterFuzz External
  upload testcase endpoint."""
  steps = []

  access_token_file_path = f'{GCB_WORKSPACE_DIR}/at.txt'
  get_access_token_step = {
      'name':
          'google/cloud-sdk',
      'args': [
          'bash', '-c',
          f'gcloud auth print-access-token > {access_token_file_path}'
      ]
  }
  steps.append(get_access_token_step)

  upload_testcase_script_path = f'{GCB_WORKSPACE_DIR}/oss-fuzz/infra/build/functions/ood_upload_testcase.py'
  job_name = f'libfuzzer_asan_{project.name}'
  target_name = f'{project.name}_{env_dict["FUZZ_TARGET"]}'
  upload_testcase_step = {
      'name':
          'python:3.8',
      'args': [
          'python3', upload_testcase_script_path, OOD_CRASHES_DIR, job_name,
          target_name, access_token_file_path
      ]
  }
  steps.append(upload_testcase_step)

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
  steps += get_build_fuzzers_steps(config.fuzzing_engine, project, env)
  env_dict = {string.split('=')[0]: string.split('=')[1] for string in env}
  steps += get_gcs_corpus_steps(config.fuzzing_engine, project, env_dict)
  steps += get_build_ood_image_steps(config.fuzzing_engine, project, env_dict)
  steps += get_push_and_run_ood_image_steps(config.fuzzing_engine, project,
                                            env_dict)
  steps += get_extract_crashes_steps(config.fuzzing_engine, project, env_dict)
  steps += get_upload_testcase_steps(project, env_dict)

  return steps


def main():
  """Build and run fuzzbench for OSS-Fuzz projects."""
  return build_project.build_script_main('Does a FuzzBench run.',
                                         get_build_steps, FUZZBENCH_BUILD_TYPE)


if __name__ == '__main__':
  sys.exit(main())
