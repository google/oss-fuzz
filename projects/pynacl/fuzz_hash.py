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

import nacl.hash
import nacl.pwhash


def TestOneInput(data):
  fdp = atheris.FuzzedDataProvider(data)

  nacl.hash.sha256(fdp.ConsumeBytes(fdp.ConsumeIntInRange(0, 512)))
  nacl.hash.sha512(fdp.ConsumeBytes(fdp.ConsumeIntInRange(0, 512)))
  nacl.hash.generichash(fdp.ConsumeBytes(fdp.ConsumeIntInRange(0, 512)), key=fdp.ConsumeBytes(32))

  try:
    nacl.pwhash.kdf_scryptsalsa208sha256(
      32,
      fdp.ConsumeBytes(fdp.ConsumeIntInRange(10, 1000)),
      fdp.ConsumeBytes(32),
      2000,
      (2**20)*100
    )
  except ValueError:
    pass

  nacl.pwhash.scryptsalsa208sha256_str(fdp.ConsumeBytes(1024))


def main():
  atheris.instrument_all()
  atheris.Setup(sys.argv, TestOneInput)
  atheris.Fuzz()


if __name__ == "__main__":
  main()
