#!/usr/local/bin/python3
#
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
"""Exploit pytorch lightning with fuzzer's input as a random env variable.

This PoC is extended from a report in GitHub Advisory Database:
https://github.com/advisories/GHSA-r5qj-cvf9-p85h
The original report documents an exploit using a specific environment variable,
we show a way to achieve the same exploit with an arbitrary env variable.
"""

import os
import sys
import atheris

with atheris.instrument_imports():
  from pytorch_lightning import Trainer
  from pytorch_lightning.utilities.argparse import parse_env_variables


def prepare_fuzzing_input(data):
  """Prepare the data needed by the exploit with input data from fuzzers."""
  data = data.replace(b'\0', b'')
  env_name = 'AN_ARBITRARY_ENV_NAME'
  return data, env_name


def exploit_target(env_value, env_name):
  """This target is based on a snippet from the official documentation of
  `parse_env_variables`:
  https://pytorch-lightning.readthedocs.io/en/stable/api/pytorch_lightning.utilities.argparse.html  # pylint: disable=line-too-long
  It might not be the most realistic example,
  but serves as a PoC to show that SystemSan works for Python."""
  os.environb[env_name.encode()] = env_value
  parse_env_variables(Trainer, template=env_name)


def TestOneInput(data):  # pylint: disable=invalid-name
  """Exploit the target only with input data from fuzzers."""
  env_value, env_name = prepare_fuzzing_input(data)
  exploit_target(env_value, env_name)


def main():
  """Fuzz target with atheris."""
  atheris.Setup(sys.argv, TestOneInput)
  atheris.Fuzz()


if __name__ == '__main__':
  main()
