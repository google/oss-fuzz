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
import logging
import sys

import google.auth

import build_lib
import build_project


def run_experiment(project_name, command, output_path, experiment_name):
  """Runs the experiment specified on GCB."""
  config = build_project.Config(testing=True,
                                test_image_suffix='',
                                repo=build_project.DEFAULT_OSS_FUZZ_REPO,
                                branch=None,
                                parallel=False,
                                upload=False,
                                experiment=True,
                                upload_build_logs=None)

  try:
    project_yaml, dockerfile_contents = (
        build_project.get_project_data(project_name))
  except FileNotFoundError:
    logging.error('Couldn\'t get project data. Skipping %s.', project_name)
    return None

  project = build_project.Project(project_name, project_yaml,
                                  dockerfile_contents)

  # Override sanitizers and engine because we only care about libFuzzer+ASan
  # for benchmarking purposes.
  build_project.set_yaml_defaults(project_yaml)
  project_yaml['sanitizers'] = ['address']
  project_yaml['fuzzing_engines'] = ['libfuzzer']
  project_yaml['architectures'] = ['x86_64']

  # Don't do bad build checks.
  project_yaml['run_tests'] = False

  steps = build_lib.get_project_image_steps(project.name,
                                            project.image,
                                            project.fuzzing_language,
                                            config=config,
                                            architectures=project.architectures,
                                            experiment=config.experiment)

  steps.extend([
      {
          'name': project.image,
          'args': [
              'bash',
              '-c',
              'mkdir /workspace/out',
          ]
      },
      {
          'name':
              project.image,
          'args': [
              'bash',
              '-c',
              f'(cd "/src"; cd {project.workdir}; {command})',
          ]
      },
      {
          'name': 'gcr.io/cloud-builders/gsutil',
          'args': [
              '-m',
              'cp',
              '-r',
              '/workspace/out/*',
              output_path,
          ]
      },
  ])

  credentials, _ = google.auth.default()
  return build_project.run_build(project_name,
                                 steps,
                                 credentials,
                                 'experiment',
                                 experiment=True,
                                 extra_tags=[f'experiment-{experiment_name}'])


def main():
  """Runs run target experiments on GCB."""
  parser = argparse.ArgumentParser(sys.argv[0], description='Test projects')
  parser.add_argument('--project', required=True, help='Project name')
  parser.add_argument('--command',
                      required=True,
                      help='Command to run inside the project image.')
  parser.add_argument('--upload_output',
                      required=True,
                      help='GCS bucket location to upload output to.')
  parser.add_argument('--experiment_name',
                      required=True,
                      help='Experiment name.')
  args = parser.parse_args()

  run_experiment(args.project, args.command, args.upload_output,
                 args.experiment_name)


if __name__ == '__main__':
  main()
