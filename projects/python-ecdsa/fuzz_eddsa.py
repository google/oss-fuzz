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
import hashlib
import binascii

import ecdsa


def target1(fdp):
  a = ecdsa.ellipticcurve.PointEdwards(ecdsa.eddsa.curve_ed25519,
                                       fdp.ConsumeIntInRange(0, 10),
                                       fdp.ConsumeIntInRange(0, 10),
                                       fdp.ConsumeIntInRange(0, 10),
                                       fdp.ConsumeIntInRange(0, 10))
  z = a.double()


def target2(fdp):
  try:
    key = ecdsa.eddsa.PublicKey(ecdsa.eddsa.generator_ed25519,
                                fdp.ConsumeBytes(fdp.ConsumeIntInRange(0, 512)))
    key.verify(fdp.ConsumeBytes(fdp.ConsumeIntInRange(0, 512)), fdp.ConsumeBytes(fdp.ConsumeIntInRange(0, 512)))
  except ValueError:
    pass
  except ecdsa.errors.MalformedPointError:
    pass


def TestOneInput(data):
  fdp = atheris.FuzzedDataProvider(data)
  targets = [
      target1,
      target2,
  ]
  target = fdp.PickValueInList(targets)
  target(fdp)


def main():
  atheris.instrument_all()
  atheris.Setup(sys.argv, TestOneInput)
  atheris.Fuzz()


if __name__ == "__main__":
  main()
