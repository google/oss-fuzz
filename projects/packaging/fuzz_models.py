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
"""Fuzz the JSON/TOML-shaped models: direct_url.json, pylock.toml and dependency groups."""

import json
import sys
import atheris

with atheris.instrument_imports():
  from packaging.dependency_groups import (DependencyGroupResolver,
                                           resolve_dependency_groups)
  from packaging.direct_url import DirectUrl, DirectUrlValidationError
  from packaging.errors import ExceptionGroup
  from packaging.pylock import Pylock, PylockSelectError, PylockValidationError


def TestOneInput(data):
  fdp = atheris.FuzzedDataProvider(data)
  choice = fdp.ConsumeIntInRange(0, 2)
  try:
    obj = json.loads(fdp.ConsumeUnicodeNoSurrogates(fdp.remaining_bytes()))
  except (ValueError, RecursionError):
    return
  if not isinstance(obj, dict):
    return
  if choice == 0:
    try:
      url = DirectUrl.from_dict(obj)
    except DirectUrlValidationError:
      return
    url.to_dict()
    try:
      url.validate()
    except DirectUrlValidationError:
      pass
  elif choice == 1:
    try:
      lock = Pylock.from_dict(obj)
    except PylockValidationError:
      return
    lock.to_dict()
    try:
      list(lock.select())
    except PylockSelectError:
      pass
  else:
    try:
      resolver = DependencyGroupResolver(obj)
      for group in list(obj)[:4]:
        resolver.resolve(group)
      resolve_dependency_groups(obj, *list(obj)[:2])
    except (ValueError, TypeError, LookupError, ExceptionGroup):
      pass

def main():
  atheris.instrument_all()
  atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
  atheris.Fuzz()


if __name__ == "__main__":
  main()
