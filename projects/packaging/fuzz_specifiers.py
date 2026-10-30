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
"""Fuzz versions, specifier sets and version ranges."""

import sys
import atheris

with atheris.instrument_imports():
  from packaging.specifiers import InvalidSpecifier, SpecifierSet
  from packaging.version import InvalidVersion, Version


def consume_str(fdp, max_len):
  return fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, max_len))


def fuzz_version(fdp):
  try:
    v1 = Version(consume_str(fdp, 64))
    v2 = Version(consume_str(fdp, 64))
  except InvalidVersion:
    return
  assert Version(str(v1)) == v1
  _ = (v1 < v2, v1 <= v2, v1 == v2, hash(v1), v1.public, v1.base_version,
       v1.epoch, v1.release, v1.pre, v1.post, v1.dev, v1.local,
       v1.is_prerelease, v1.is_postrelease, v1.is_devrelease, v1.major,
       v1.minor, v1.micro)


def fuzz_specifier_set(fdp):
  try:
    s1 = SpecifierSet(consume_str(fdp, 128))
    s2 = SpecifierSet(consume_str(fdp, 128))
  except InvalidSpecifier:
    return
  prereleases = fdp.PickValueInList([None, True, False])
  candidates = [consume_str(fdp, 24) for _ in range(fdp.ConsumeIntInRange(0, 6))]
  combined = s1 & s2
  str(combined)
  len(combined)
  list(combined)
  for item in candidates:
    s1.contains(item, prereleases=prereleases)
    item in combined
  list(s1.filter(candidates, prereleases=prereleases))

  r1 = s1.to_range()
  r2 = s2.to_range()
  for op in (r1.intersection, r1.union, r1.difference):
    result = op(r2)
    result.is_empty()
    result.to_specifier_set()
  r1.complement()
  r1.is_subset(r2)
  r1.is_disjoint(r2)
  r1.relation(r2)
  list(r1.filter(candidates))
  for item in candidates:
    try:
      r1.contains(Version(item))
    except InvalidVersion:
      pass


def TestOneInput(data):
  fdp = atheris.FuzzedDataProvider(data)
  if fdp.ConsumeBool():
    fuzz_version(fdp)
  else:
    fuzz_specifier_set(fdp)

def main():
  atheris.instrument_all()
  atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
  atheris.Fuzz()


if __name__ == "__main__":
  main()
