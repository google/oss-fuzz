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
from ipykernel.serialize import unpack_apply_message, pack_apply_message


def ConsumeRandomLengthBufferList(fdp):
  """Creates a list of buffers of various lengths"""
  buffers = []
  max_range = fdp.ConsumeIntInRange(3, 50)
  for _ in range(3, max_range):
    buffers.append(fdp.ConsumeBytes(fdp.ConsumeIntInRange(0, 200)))
  return buffers


def TestOneInput(data):
  if len(data) < 48:
    return
  fdp = atheris.FuzzedDataProvider(data)

  try:
    buffers = ConsumeRandomLengthBufferList(fdp)
    f, args, kwargs = unpack_apply_message(buffers)
  except Exception:
    return

  # Anything unpackable, should be packable.
  pack_apply_message(f, args, kwargs)


def main():
  atheris.instrument_all()
  atheris.Setup(sys.argv, TestOneInput)
  atheris.Fuzz()


if __name__ == "__main__":
  main()
