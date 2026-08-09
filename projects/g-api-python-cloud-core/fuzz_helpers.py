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

import atheris
import sys
import json

# We instrument all functions when initiating atheris
from google.cloud import _helpers

def TestOneInput(data):
  if len(data) < 100:
    return

  fdp = atheris.FuzzedDataProvider(data)
  try:
    loaded_data = json.loads(fdp.ConsumeString(300))
    success = True
  except Exception:
    success = False

  if success:
    try:
      _helpers._ensure_tuple_or_list(loaded_data)
    except TypeError:
      pass

  try:
    _helpers._bytes_to_unicode(data)
  except ValueError:
    pass

  fdp = atheris.FuzzedDataProvider(data)
  try:
    _helpers._time_from_iso8601_time_naive(fdp.ConsumeString(100))
  except ValueError:
    pass

  fdp = atheris.FuzzedDataProvider(data)
  try:
    _helpers._rfc3339_nanos_to_datetime(fdp.ConsumeString(100))
  except ValueError:
    pass

  fdp = atheris.FuzzedDataProvider(data)
  try:
    _helpers._name_from_project_path(
      fdp.ConsumeString(60),
      fdp.ConsumeString(60),
      fdp.ConsumeString(60)
    )
  except ValueError:
    pass

def main():
  atheris.instrument_all()
  atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
  atheris.Fuzz()

if __name__ == "__main__":
  main()
