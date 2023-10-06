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

import pathspec 


def test_raw(data):
  fdp = atheris.FuzzedDataProvider(data)
  lines = []

  for idx in range(fdp.ConsumeIntInRange(2, 10)):
    lines.append(fdp.ConsumeUnicodeNoSurrogates(512))
  try:
    spec = pathspec.PathSpec.from_lines(lines)
  except TypeError:
    return
  spec.match_files([fdp.ConsumeUnicodeNoSurrogates(512)])


def test_git(data):
  fdp = atheris.FuzzedDataProvider(data)
  lines = []
  for idx in range(fdp.ConsumeIntInRange(2, 10)):
    lines.append(fdp.ConsumeUnicodeNoSurrogates(512))

  try:
    spec = pathspec.PathSpec.from_lines('gitwildmatch',lines)
  except pathspec.patterns.gitwildmatch.GitWildMatchPatternError:
    return
  except TypeError:
    return
  spec.match_files([fdp.ConsumeUnicodeNoSurrogates(512)])


def TestOneInput(data):
  test_raw(data)
  test_git(data)


def main():
  atheris.instrument_all()
  atheris.Setup(sys.argv, TestOneInput)
  atheris.Fuzz()


if __name__ == "__main__":
  main()
