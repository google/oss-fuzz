#!/usr/bin/python3
# Copyright 2026 Google LLC
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
"""Fuzz wheel tags, file name and name utilities, and SPDX license expressions."""

import sys
import atheris

with atheris.instrument_imports():
  from packaging.licenses import (InvalidLicenseExpression,
                                  canonicalize_license_expression)
  from packaging.tags import InvalidTag, Tag, parse_tag
  from packaging.utils import (InvalidName, InvalidSdistFilename,
                               InvalidWheelFilename, canonicalize_name,
                               is_normalized_name, parse_sdist_filename,
                               parse_wheel_filename)


def TestOneInput(data):
  fdp = atheris.FuzzedDataProvider(data)
  choice = fdp.ConsumeIntInRange(0, 3)
  text = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 512))
  if choice == 0:
    try:
      tags = parse_tag(text)
    except (InvalidTag, ValueError):
      return
    for tag in tags:
      assert Tag(tag.interpreter, tag.abi, tag.platform) == tag
      str(tag)
  elif choice == 1:
    try:
      name, version, build, tags = parse_wheel_filename(text)
    except InvalidWheelFilename:
      return
    for tag in tags:
      str(tag)
    try:
      parse_sdist_filename(text)
    except InvalidSdistFilename:
      pass
  elif choice == 2:
    is_normalized_name(text)
    canonicalize_name(text)
    try:
      canonical = canonicalize_name(text, validate=True)
    except InvalidName:
      return
    assert is_normalized_name(canonical)
  else:
    try:
      canonical = canonicalize_license_expression(text)
    except InvalidLicenseExpression:
      return
    assert canonicalize_license_expression(canonical) == canonical

def main():
  atheris.instrument_all()
  atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
  atheris.Fuzz()


if __name__ == "__main__":
  main()
