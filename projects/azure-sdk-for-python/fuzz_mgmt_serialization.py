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
import json
import atheris

from azure.mgmt.dynatrace import _serialization
from azure.mgmt.dynatrace.models import _models_py3
from azure.core.exceptions import (
  DeserializationError,
  SerializationError
)


def TestOneInput(data):
  fdp = atheris.FuzzedDataProvider(data)

  try:
    payload = json.loads(fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 1024)))
  except:
    return
  model = _models_py3.AccountInfo()

  # Overwrite the types, this is easier than creating a new class.
  model._attribute_map = payload

  try:
    serialized_data = model.serialize()
    serialized = True
  except SerializationError:
    serialized = False

  deserializer = _serialization.Deserializer()
  if serialized:
    # Anything serialized should be unserializable
    deserializer._deserialize(model, serialized_data)
  else:
    # Otherwise we deserialize random data and catch exceptions
    try:
      deserializer._deserialize(
        model,
        fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 1024))
      )
    except DeserializationError:
      pass


def main():
  atheris.instrument_all()
  atheris.Setup(sys.argv, TestOneInput)
  atheris.Fuzz()


if __name__ == "__main__":
  main()
