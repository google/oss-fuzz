#!/usr/bin/python3
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
import sys
import atheris
import parso


def fuzz_dump(data):
  fdp = atheris.FuzzedDataProvider(data)
  try:
    module = parso.parse(fdp.ConsumeUnicodeNoSurrogates(sys.maxsize))
    if module is not None:
        module.dump()
  except RecursionError:
    # Not interesting
    pass


def fuzz_errors(data, version):
  fdp = atheris.FuzzedDataProvider(data)
  try:
    grammar = parso.load_grammar(version = version)
    module = grammar.parse(fdp.ConsumeUnicodeNoSurrogates(sys.maxsize))
    grammar.iter_errors(module)
  except RecursionError:
    # Not interesting
    pass


def TestOneInput(data):
  fuzz_dump(data)
  fuzz_errors(data, '3.6')
  fuzz_errors(data, '3.7')
  fuzz_errors(data, '3.8')
  fuzz_errors(data, '3.9')
  fuzz_errors(data, '3.10')
  fuzz_errors(data, '3.11')
  fuzz_errors(data, '3.12')


def main():
  atheris.instrument_all()
  atheris.Setup(sys.argv, TestOneInput)
  atheris.Fuzz()


if __name__ == "__main__":
  main()
