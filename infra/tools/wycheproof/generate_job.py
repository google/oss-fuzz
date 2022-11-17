#!/usr/bin/env python3
# Copyright 2022 Google LLC
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
"""Script for generating an OSS-Fuzz job for a wycheproof project."""
import sys


def main():
  """Usage generate_job.py <project>."""
  project = sys.argv[1]
  print(f'Name: wycheproof_nosanitizer_{project}')
  job_definition = f"""CUSTOM_BINARY = False
BAD_BUILD_CHECK = False
APP_NAME = WycheproofTarget.bash
THREAD_ALIVE_CHECK_INTERVAL = 10
TEST_TIMEOUT = 3600
CRASH_RETRIES = 1
AGGREGATE_COVERAGE = False
TESTCASE_COVERAGE = False
FILE_GITHUB_ISSUE = False
MANAGED = False
MAX_FUZZ_THREADS = 1
RELEASE_BUILD_BUCKET_PATH = gs://clusterfuzz-builds-wycheproof/{project}/{project}-none-([0-9]+).zip
PROJECT_NAME = {project}
SUMMARY_PREFIX = {project}
REVISION_VARS_URL = https://commondatastorage.googleapis.com/clusterfuzz-builds-wycheproof/{project}/{project}-none-%s.srcmap.json
FUZZ_LOGS_BUCKET = {project}-logs.clusterfuzz-external.appspot.com
CORPUS_BUCKET = {project}-corpus.clusterfuzz-external.appspot.com
QUARANTINE_BUCKET = {project}-quarantine.clusterfuzz-external.appspot.com
BACKUP_BUCKET = {project}-backup.clusterfuzz-external.appspot.com
AUTOMATIC_LABELS = Proj-{project},Engine-wycheproof
"""
  print(job_definition)


if __name__ == '__main__':
  main()
