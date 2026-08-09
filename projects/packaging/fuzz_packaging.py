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
"""Target several modules in the packaging project."""

import sys
import atheris
from packaging.utils import (canonicalize_version, parse_wheel_filename,
                             parse_sdist_filename, InvalidSdistFilename,
                             InvalidWheelFilename)

from packaging.specifiers import InvalidSpecifier, Specifier
from packaging.version import InvalidVersion


def fuzz_utils(data):
  """Logic to hit routines in src/packaging/utils."""
  fdp = atheris.FuzzedDataProvider(data)
  canonicalize_version(
      fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 1024)))
  try:
    parse_sdist_filename(
        fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 1024)))
  except InvalidSdistFilename:
    pass

  try:
    parse_wheel_filename(
        fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 1024)))
  except InvalidWheelFilename:
    pass


def fuzz_specifier(data):
  """Logic to hit routines in src/packaging/specifiers."""
  fdp = atheris.FuzzedDataProvider(data)
  try:
    spec1 = Specifier(
        fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 1024)))
    spec2 = Specifier(
        fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 1024)))
  except InvalidSpecifier:
    return

  b1 = spec1 == spec2
  b2 = spec1 != spec2
  try:
    b7 = spec1.contains(fdp.ConsumeUnicodeNoSurrogates(24))
  except InvalidVersion:
    pass


def TestOneInput(data):
  """Fuzzer entrypoint, wrapper around fuzz_* routines."""
  fuzz_utils(data)
  fuzz_specifier(data)


def main():
  atheris.instrument_all()
  atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
  atheris.Fuzz()


if __name__ == "__main__":
  main()
