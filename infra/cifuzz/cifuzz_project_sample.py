# Copyright 2020 Google LLC
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
"""This tests all of the OSS-Fuzz projects compatibility with CIFuzz."""
import csv
import os
import sys
import tempfile
import time

import cifuzz
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import utils

OSS_FUZZ_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def main():
  projects = os.listdir(os.path.join(OSS_FUZZ_ROOT, 'projects'))

  with open('cifuzz_sample.csv', 'r', newline='') as csvfile:
    reader = csv.reader(csvfile, delimiter=',')
    field_names = ['project name', 'status', 'build time', '# fuzzers']
    finished_projects = []
    for row in reader:
      finished_projects.append(row[0])

  for project in projects:
    if project in finished_projects:
      print('Project %s already stored.' % (project))
      continue
    try:
      utils.execute(['pkill', '-f', 'fuzzer'])
      with tempfile.TemporaryDirectory() as tmp_dir:
        with open('cifuzz_sample.csv', 'a', newline='') as csvfile:
          writer = csv.DictWriter(csvfile, fieldnames=field_names)

          start_time = time.time()
          out_dir = os.path.join(tmp_dir, 'out')
          build_result = cifuzz.build_fuzzers(project, project, tmp_dir)
          elapsed_time = time.time() - start_time
          build_time = time.strftime("%H:%M:%S", time.gmtime(elapsed_time))
          if not build_result:
            writer.writerow({'project name': project, 'status': 'Failed on build.', 'build time': 'N/A', '# fuzzers': 'N/A'})
            continue
          num_fuzzers = len(utils.get_fuzz_targets(out_dir))
          run_success, _ = cifuzz.run_fuzzers(5, tmp_dir)
          if not run_success:
            status = 'Failed on run.'
          status = 'Success.'
          writer.writerow({'project name': project, 'status': status, 'build time': build_time, '# fuzzers': num_fuzzers})
    except Exception:
      pass

if __name__ == '__main__':
  sys.exit(main())
