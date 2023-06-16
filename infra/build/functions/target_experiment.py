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
"""Script to run target experiments on GCB."""

import argparse
import sys

import google.auth

import build_lib
import build_project
import trial_build


def run_experiment(project_name, target_name, args, output_path):
  config = build_project.Config(testing=True,
                                test_image_suffix='',
                                repo=build_project.DEFAULT_OSS_FUZZ_REPO,
                                branch=None,
                                parallel=False,
                                upload=False,
                                experiment=True)

  try:
    project_yaml, dockerfile_contents = (
        build_project.get_project_data(project_name))
  except FileNotFoundError:
    logging.error('Couldn\'t get project data. Skipping %s.', project_name)
    return

  # Override sanitizers and engine because we only care about libFuzzer+ASan
  # for benchmarking purposes.
  build_project.set_yaml_defaults(project_yaml)
  project_yaml['sanitizers'] = ['address']
  project_yaml['fuzzing_engines'] = ['libfuzzer']

  # Don't do bad build checks.
  project_yaml['run_tests'] = False

  steps = build_project.get_build_steps(project_name, project_yaml,
                                        dockerfile_contents, config)

  build = build_project.Build('libfuzzer', 'address', 'x86_64')
  local_output_path = '/workspace/output.log'
  fuzzer_args = ' '.join(args)

  env = build_project.get_env(project_yaml['language'], build)
  env.append('RUN_FUZZER_MODE=batch')

  run_step = {
      'name':
          'gcr.io/oss-fuzz-base/base-runner',
      'env':
          env,
      'args': [
          'bash',
          '-c',
          f'run_fuzzer {target_name} {fuzzer_args} &> {local_output_path} || true',
      ]
  }
  steps.append(build_lib.dockerify_run_step(run_step, build))

  # TODO: Save corpus too.
  steps.append({
      'name': 'gcr.io/cloud-builders/gsutil',
      'args': ['-m', 'cp', local_output_path, output_path]
  })

  credentials, _ = google.auth.default()
  return build_project.run_build(project_name,
                                 steps,
                                 credentials,
                                 'experiment',
                                 experiment=True)


def main():
  parser = argparse.ArgumentParser(sys.argv[0], description='Test projects')
  parser.add_argument('--project', required=True, help='Project name')
  parser.add_argument('--target', required=True, help='Target name')
  parser.add_argument('args',
                      nargs='+',
                      help='Additional arguments to pass to the target')
  parser.add_argument('--output_log', required=True, help='GCS log location.')
  args = parser.parse_args()

  build_id = run_experiment(args.project, args.target, args.args,
                            args.output_log)
  #print('Link:', f'https://pantheon.corp.google.com/cloud-build/builds;region=us-central1/{build_id}?project=oss-fuzz'))
  print(build_id)


if __name__ == '__main__':
  main()
