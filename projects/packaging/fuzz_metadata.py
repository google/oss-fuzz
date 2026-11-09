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
"""Fuzz core metadata parsing (METADATA / PKG-INFO files)."""

import sys
import atheris

with atheris.instrument_imports():
  from packaging.errors import ExceptionGroup
  from packaging.metadata import InvalidMetadata, Metadata, parse_email


def TestOneInput(data):
  fdp = atheris.FuzzedDataProvider(data)
  as_bytes = fdp.ConsumeBool()
  payload = fdp.ConsumeBytes(fdp.remaining_bytes())
  if not as_bytes:
    payload = payload.decode("utf-8", "surrogateescape")
  try:
    raw, _ = parse_email(payload)
  except ValueError:
    return
  try:
    meta = Metadata.from_raw(raw, validate=False)
  except (ExceptionGroup, InvalidMetadata):
    meta = None
  if meta is not None:
    # Accessing a field runs its validator lazily.
    for field in ("metadata_version", "name", "version", "requires_dist",
                  "requires_python", "provides_extra", "license_expression",
                  "dynamic", "project_urls", "classifiers"):
      try:
        getattr(meta, field)
      except InvalidMetadata:
        pass
  try:
    Metadata.from_email(payload, validate=True)
  except (ExceptionGroup, InvalidMetadata, ValueError):
    pass

def main():
  atheris.instrument_all()
  atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
  atheris.Fuzz()


if __name__ == "__main__":
  main()
