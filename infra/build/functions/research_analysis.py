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
import json
import os
import shutil
import subprocess
import pathlib

BUCKET = 'gs://oss-fuzz-corpus-research'
CORPORA = BUCKET + '/corpus'

OSS_FUZZ_ROOT = pathlib.Path(__file__).parent.parent.parent.parent


def download_research_corpora(project, output_dir):
  corpora = CORPORA + '/' + project
  command = ['gsutil', 'ls', corpora]
  lines = subprocess.run(command, stdout=subprocess.PIPE).stdout.splitlines()
  corpora = [line.decode().strip('/') for line in lines]
  if not corpora:
    return None

  output_dir = output_dir / project
  if os.path.exists(output_dir):
    subprocess.run([
        'docker', 'run', '-v', f'{output_dir}:{output_dir}',
        'gcr.io/oss-fuzz-base/base-runner', 'rm', '-rf', output_dir
    ])
  for corpus in corpora:
    command = ['gsutil', '-m', 'cp', '-r', corpus, output_dir]
    subprocess.run(command)
  return output_dir


def _env_to_docker_args(env_list):
  """Turns envirnoment variable list into docker arguments."""
  return sum([['-e', v] for v in env_list], [])


def get_run_args(fuzzer, corpus, project):
    env = [
      'FUZZING_ENGINE=libfuzzer',
      'HTTP_PORT=',
      'FUZZING_LANGUAGE=c++',
      'PROJECT=%s' % project,
      'SANITIZER=coverage',
      'ARCHITECTURE=x86_64',
      'COVERAGE_EXTRA_ARGS=',
  ]
  out_dir = OSS_FUZZ_ROOT / 'build' / 'out' / project
  run_args = [
      'docker', 'run', '-v', f'{out_dir}:/out', '-v',
      f'{corpus}:/corpus/{fuzzer}'
  ]
  run_args += _env_to_docker_args(env)
  return run_args

def get_coverage(fuzzer, corpus, project):
  run_args = get_run_args()
  run_args.extend(['gcr.io/oss-fuzz-base/base-runner', 'coverage'])
  print(run_args, flush=True)
  # !!!
  subprocess.run(run_args)
  stats_file = out_dir / 'fuzzer_stats' / f'{fuzzer}.json'
  with open(stats_file) as fp:
    stats = json.load(fp)['data'][0]
  totals = stats['totals']
  return totals['lines']['percent']


def compare_corpora(fuzzer, project, real_corpus, research_corpus):
  real_coverage = get_coverage(fuzzer, real_corpus, project)
  out_dir = OSS_FUZZ_ROOT / 'build' / 'out' / project
  dumps = out_dir / 'dumps'
  dumps_backup = out_dir / 'dumps-backup'
  if os.path.exists(dumps_backup):
    os.remove(dumps_backup)
  shutil.copytree(dumps, dumps_backup)
  research_coverage = get_coverage(fuzzer, research_corpus, project)
  return research_coverage - real_coverage


def analyze_research_corpus(project):
  research_corpus_dir = OSS_FUZZ_ROOT / 'build' / 'research-corpus' / project
  # !!!
  # research_corpus_dir = download_research_corpora(project, research_corpus_dir)
  for fuzzer in os.listdir(research_corpus_dir):
    if not os.path.isdir(research_corpus_dir / fuzzer):
      continue
    real_corpus = OSS_FUZZ_ROOT / 'build' / 'corpus' / project / fuzzer
    fuzzer_research_corpus = research_corpus_dir / fuzzer
    # !!!
    # shutil.copytree(real_corpus, fuzzer_research_corpus / 'actual-corpus')
    print('fuzzer', fuzzer)
    print('cc',
          compare_corpora(fuzzer, project, real_corpus, fuzzer_research_corpus))
