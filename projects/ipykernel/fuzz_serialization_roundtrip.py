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
import ipykernel
from ipykernel.serialize import deserialize_object, serialize_object


def ConsumeRandomLengthBufferList(fdp):
  """Creates a list of buffers of various lengths"""
  buffers = []
  max_range = fdp.ConsumeIntInRange(1, 50)
  for _ in range(1, max_range):
    buffers.append(fdp.ConsumeBytes(fdp.ConsumeIntInRange(0, 200)))
  return buffers


def TestOneInput(data):
  fdp = atheris.FuzzedDataProvider(data)

  try:
    deserialized_obj = deserialize_object(ConsumeRandomLengthBufferList(fdp))
  except Exception:
    return

  # Any deserizlied object should be serializable
  serialize_object(deserialized_obj)


def main():
  atheris.instrument_all()
  atheris.Setup(sys.argv, TestOneInput)
  atheris.Fuzz()


if __name__ == "__main__":
  main()
