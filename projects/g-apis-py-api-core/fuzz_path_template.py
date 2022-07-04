#!/usr/bin/python3
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

import atheris
import sys

with atheris.instrument_imports():
  from google.api_core import path_template

def TestOneInput(data):
  fdp = atheris.FuzzedDataProvider(data)
  targets = [
    "expand",
    "transcode",
    "validate"
  ]
  target = targets[fdp.ConsumeIntInRange(0, len(targets)-1)]
  if target == "expand":
    s1 = fdp.ConsumeString(200)
    s2 = fdp.ConsumeString(200)
    try:
      path_template.expand(s1, s2)
    except ValueError:
      # ValueError is raised
      # https://github.com/googleapis/python-api-core/blob/5b5e77563229687c901d77b5fdecc18168b535e6/google/api_core/path_template.py#L123
      pass
  elif target == "transcode":
    s1 = fdp.ConsumeString(200)
    s2 = fdp.ConsumeString(200)
    s3 = fdp.ConsumeString(200)
    try:
        path_template.transcode([{'uri' : s1, 'body' : s2,'method' : s3}])
    except ValueError:
        # ValueError is raised:
        # https://github.com/googleapis/python-api-core/blob/main/google/api_core/path_template.py#L260
        pass
  elif target == "validate":
    s1 = fdp.ConsumeString(200)
    s2 = fdp.ConsumeString(200)
    path_template.validate(s1, s2)


def main():
  atheris.instrument_all()
  atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
  atheris.Fuzz()

if __name__ == "__main__":
  main()
