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
import os
import shutil
import subprocess
import json

from distutils.dir_util import copy_tree


def get_stats_filename(fuzzer):
  return os.path.join(os.environ['OUT'], 'fuzzer_stats', f'{fuzzer}.json')

def get_research_corpus_dir():
  return os.getenv('RESEARCH_CORPUS')

def get_coverage(fuzzer, corpus):
  print('get_cov')
  env = os.environ.copy()
  env['CORPUS_DIR'] = corpus
  print('rc', subprocess.run(
      ['coverage', fuzzer], env=env).returncode, flush=True)
  stats_filename = get_stats_filename(fuzzer)
  print(stats_filename, flush=True)
  with open(stats_filename) as fp:
    stats = json.load(fp)['data'][0]
  totals = stats['totals']
  return totals['lines']['percent']

def compare_corpora(fuzzer, corpus1, corpus2):
  coverage1 = get_coverage(fuzzer, corpus1)
  coverage2 = get_coverage(fuzzer, corpus2)
  print(coverage1, coverage2)
  return coverage2 - coverage1

def analyze():
  research_corpus_dir = get_research_corpus_dir()
  for fuzzer in os.listdir(os.path.join(research_corpus_dir, os.getenv('FPROJECT'))):
    print(fuzzer)
    fuzzer_research_corpus = os.path.join(research_corpus_dir, os.getenv('FPROJECT'), fuzzer)
    if not os.path.isdir(fuzzer_research_corpus):
      continue
    real_corpus_dir = '/corpus'

    rcd = os.path.join(fuzzer_research_corpus, f'{fuzzer}-real')
    copy_tree(os.path.join(real_corpus_dir, fuzzer), rcd)
    print('COV DIFFERENCE', compare_corpora(fuzzer, real_corpus_dir, os.path.join(research_corpus_dir, os.getenv('FPROJECT'))))


def main():
  analyze()


if __name__ == '__main__':
  main()
