#!/usr/bin/env python3
#
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
"""Utilities for fuzzbench runs on Google Cloud Build."""
import os
import sys

infra_dir = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.append(os.path.join(infra_dir, 'cifuzz'))
import clusterfuzz_deployment
import config_utils


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
  os.environ['CIFUZZ_TEST'] = 'non_falsy_str'
  os.environ['OSS_FUZZ_PROJECT_NAME'] = project_name

  config = config_utils.RunFuzzersConfig()
  deployment = clusterfuzz_deployment.OSSFuzz(config, None)
  latest_build_filename = deployment.get_latest_build_name()
  build_uri = f'gs://clusterfuzz-builds/{project_name}/' + latest_build_filename

  return build_uri, latest_build_filename
