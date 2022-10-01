#!/usr/bin/python3

# Copyright 2021 Google LLC
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

import sys

import atheris

with atheris.instrument_imports():
  import yaml


@atheris.instrument_func
def TestOneInput(input_bytes):
  try:
    context = yaml.load(input_bytes, Loader=yaml.FullLoader)
  except yaml.YAMLError:
    return
  except RecursionError:
    return
  # Anything that is loadable should be emitable.
  try:
    listed_context = list(context)
  except:
    return

  try:
    yaml.emit(listed_context)
  except yaml.emitter.EmitterError:
    return
  except RecursionError:
    return

def main():
  atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
  atheris.Fuzz()


if __name__ == "__main__":
  main()
