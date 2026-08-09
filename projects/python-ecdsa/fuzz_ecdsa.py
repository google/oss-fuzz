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
  d = fdp.ConsumeIntInRange(
      1, 9999999999999999999999999999999999999999999999999999999999)
  k = fdp.ConsumeIntInRange(
      1, 9999999999999999999999999999999999999999999999999999999999)
  msg = fdp.ConsumeIntInRange(
      1, 9999999999999999999999999999999999999999999999999999999999)

  Q = d * ecdsa.ecdsa.generator_192
  R = k * ecdsa.ecdsa.generator_192

  pubk = ecdsa.ecdsa.Public_key(ecdsa.ecdsa.generator_192,
                                ecdsa.ecdsa.generator_192 * d)
  privk = ecdsa.ecdsa.Private_key(pubk, d)
  sig = privk.sign(msg, k)
  pubk.verifies(msg, sig)
  pubk.verifies(msg - 1, sig)


def target2(fdp):
  ecdsa._sha3.shake_256(fdp.ConsumeBytes(sys.maxsize),
                        fdp.ConsumeIntInRange(1, 64))


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
