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
import os
import sys
import tempfile

import atheris

import keras
from keras.src.datasets import npz_utils


def TestOneInput(data):
  if len(data) < 4:
    return
  # `load_npz` takes a path, so materialise the input on disk first.
  fd, path = tempfile.mkstemp(suffix=".npz")
  try:
    with os.fdopen(fd, "wb") as f:
      f.write(data)
    # Malformed archives are the normal case here: `load_npz` raises on them
    # and only an actual crash is interesting.
    try:
      npz_utils.load_npz(path)
    except Exception:
      pass
  finally:
    os.unlink(path)


def main():
  atheris.instrument_all()
  atheris.Setup(sys.argv, TestOneInput)
  atheris.Fuzz()


if __name__ == "__main__":
  main()
