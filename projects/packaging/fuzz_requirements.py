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

"""Fuzz PEP 508 requirements and environment markers."""

import sys
import atheris

with atheris.instrument_imports():
  from packaging.markers import (InvalidMarker, Marker, UndefinedComparison,
                                 UndefinedEnvironmentName, default_environment)
  from packaging.requirements import InvalidRequirement, Requirement

ENV_KEYS = sorted(default_environment().keys())


def fuzz_requirement(fdp):
  try:
    req = Requirement(fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 512)))
  except InvalidRequirement:
    return
  str(req)
  repr(req)
  hash(req)
  assert req == Requirement(str(req))
  if req.marker is not None:
    try:
      req.marker.evaluate({"extra": fdp.ConsumeUnicodeNoSurrogates(16)})
    except (UndefinedComparison, UndefinedEnvironmentName):
      pass


def fuzz_marker(fdp):
  try:
    marker = Marker(fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 512)))
  except InvalidMarker:
    return
  str(marker)
  hash(marker)
  assert marker == Marker(str(marker))
  env = {}
  for _ in range(fdp.ConsumeIntInRange(0, 4)):
    env[fdp.PickValueInList(ENV_KEYS)] = fdp.ConsumeUnicodeNoSurrogates(32)
  context = fdp.PickValueInList(["metadata", "lock_file", "requirement"])
  try:
    marker.evaluate(env or None, context)
  except (UndefinedComparison, UndefinedEnvironmentName):
    pass
  try:
    other = Marker(fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 128)))
  except InvalidMarker:
    return
  str(marker & other)
  str(marker | other)


def TestOneInput(data):
  fdp = atheris.FuzzedDataProvider(data)
  if fdp.ConsumeBool():
    fuzz_requirement(fdp)
  else:
    fuzz_marker(fdp)


def main():
  atheris.instrument_all()
  atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
  atheris.Fuzz()


if __name__ == "__main__":
  main()
