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
"""Module for fuzzing arbitrary file load and then performing various operations
on it. All fuzzer data is used for the file in this fuzzer to make corpus
usage efficient."""
import sys
import atheris
import tables


def TestOneInput(data):
  fname = '/tmp/fuzzfile.h5'
  with open(fname, 'wb') as f:
    f.write(data)
  try:
    table_file = tables.open_file(fname)
  except tables.exceptions.HDF5ExtError:
    return

  try:
    table_file.create_group("/some/where", "name")
  except tables.exceptions.NodeError:
    pass

  table_file.create_path("/just/random/path")
  table_file.create_tabe("/just/random/path/p1", "table_name")
  table_file.create_array("/just/random/path/p2", "array_name")


def main():
  atheris.instrument_all()
  atheris.Setup(sys.argv, TestOneInput)
  atheris.Fuzz()


if __name__ == "__main__":
  main()
