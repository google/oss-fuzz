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
"""  """
import logging
import sys
import uuid

import build_lib


def get_upload_corpus_bucket(project_name, fuzz_target_name):
  """ ."""
  return (f'{project_name}-corpus.clusterfuzz-external.appspot.com/'
          f'libFuzzer/{fuzz_target_name}/')


def get_signed_upload_corpus_urls(project_name, fuzz_target_name, num_uploads):
  """ ."""
  upload_corpus_bucket = get_upload_corpus_bucket(project_name,
                                                  fuzz_target_name)
  base_path = f'{upload_corpus_bucket}{uuid.uuid4().hex}'

  signed_urls = []
  #TODO: Make the following parallel
  for idx in range(num_uploads):
    path = f'{base_path}-{idx}'
    signed_url = build_lib.get_signed_url(path)
    signed_urls.append(signed_url)

  logging.info(signed_url)
  return signed_urls


def main():
  """Build and run locally fuzzbench for OSS-Fuzz projects."""
  project_name = 'skcms'
  fuzz_target_name = 'iccprofile_atf'
  get_signed_upload_corpus_urls(project_name, fuzz_target_name, 3)

  return 0


if __name__ == '__main__':
  sys.exit(main())
