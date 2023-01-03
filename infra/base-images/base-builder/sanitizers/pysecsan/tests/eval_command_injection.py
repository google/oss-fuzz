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
"""Fuzzer targetting command injection of eval."""
# pylint: disable=eval-used

import sys
import atheris
import pysecsan

pysecsan.add_hooks()


def list_files_perhaps(param, magicval):
  """Pass fuzzer data into eval."""
  if len(param) < 3:
    return
  if magicval == 1337:
    try:
      eval("FROMFUZZ")
    except ValueError:
      pass


def test_one_input(data):
  """Fuzzer entrypoint."""
  fdp = atheris.FuzzedDataProvider(data)
  list_files_perhaps(fdp.ConsumeUnicodeNoSurrogates(24),
                     fdp.ConsumeIntInRange(500, 1500))


def main():
  """Set up and start fuzzing."""

  atheris.instrument_all()
  atheris.Setup(sys.argv, test_one_input, enable_python_coverage=True)
  atheris.Fuzz()


if __name__ == '__main__':
  main()
