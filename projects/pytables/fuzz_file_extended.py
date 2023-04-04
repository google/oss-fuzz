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
#
##########################################################################
"""Fuzzing arbitrary file loading and arbitrary file operations on the
loaded file, in the event of a successful load."""
import sys
import atheris
import tables


def TestOneInput(data):
  fdp = atheris.FuzzedDataProvider(data)
  fname = '/tmp/fuzzfile.h5'
  with open(fname, 'wb') as f:
    f.write(fdp.ConsumeBytes(fdp.ConsumeIntInRange(1, 16384)))
  try:
    table_file = tables.open_file(fname)
  except tables.exceptions.HDF5ExtError:
    return

  try:
    table_file.create_group(
        fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(2, 24)),
        fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(2, 24)))
  except tables.exceptions.NodeError:
    return

  table_file.create_path(
      fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(2, 24)))
  table_file.create_tabe(
      fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(2, 24)),
      fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(2, 24)))
  table_file.create_array(
      fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(2, 24)),
      fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(2, 24)))


def main():
  atheris.instrument_all()
  atheris.Setup(sys.argv, TestOneInput)
  atheris.Fuzz()


if __name__ == "__main__":
  main()
