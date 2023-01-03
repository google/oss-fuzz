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
"""Fuzzer for several modules in gitdb. We keep it in
one fuzzer for ease of development
"""

import sys
import atheris


import zlib
from gitdb import (
  DecompressMemMapReader,
  LooseObjectDB,
  MemoryDB
) 

from gitdb.pack import (
    PackFile
)

from gitdb.exc import ParseError


def fuzz_decompression_map_reader(data):
  """Targets gitdb/stream.py#DecompressMemMapReader"""
  fdp = atheris.FuzzedDataProvider(data)

  zdata = zlib.compress(data)
  test_reader = DecompressMemMapReader(zdata, True)
  try:
    bytes_read = test_reader.read(fdp.ConsumeIntInRange(0, 10000))
  except ValueError:
    # Ignore these as they're uninteresting
    return


def fuzz_loose_obj_db(data):
  """Targets gitdb/db/loose.py"""
  path = "/tmp/loosedb.db"
  with open(path, "wb") as f:
    f.write(data)
  if not os.path.isfile(path):
    return

  ldb = LooseObjectDB(path)
  if ldb.size() != 0:
    mdb = MemoryDB()
    mdb.stream_copy(mdb.sha_iter(), ldb)

    for sha1 in ldb.sha_iter():
      ldb.info(sha1)
      ldb.stream(sha1)


def fuzz_pack_file(data):
  """Targets code in gitdb/pack.py"""

  # Ensure we have enough data for a packet
  if len(data) < 100:
    return
  path = "/tmp/packfile.idx"
  with open(path, "wb") as f:
    f.write(data)
  if not os.path.isfile(path):
    return

  pack_file = PackFile(path)
  try:
    pack_file.version()
  except ParseError:
    return

  if pack_file.size() <= 0:
    return

  for obj in pack_file.stream_iter():
    info = pack_file.info(obj.pack_offset)

def TestOneInput(data):
  fuzz_decompression_map_reader(data)
  fuzz_loose_obj_db(data)
  fuzz_pack_file(data)


def main():
  atheris.instrument_all()
  atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
  atheris.Fuzz()


if __name__ == "__main__":
  main()
