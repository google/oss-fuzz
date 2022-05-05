#!/usr/bin/python3
# Copyright 2022 Google LLC
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

with atheris.instrument_imports():
  from ellipticcurve import Ecdsa, Signature, PublicKey, PrivateKey


@atheris.instrument_func
def TestOneInput(input_bytes):
  fdp = atheris.FuzzedDataProvider(input_bytes)

  privateKey1 = PrivateKey()
  publicKey1 = privateKey1.publicKey()

  privateKeyPem = privateKey1.toPem()
  publicKeyPem = publicKey1.toPem()

  privateKey2 = PrivateKey.fromPem(privateKeyPem)
  publicKey2 = PublicKey.fromPem(publicKeyPem)

  message = fdp.ConsumeUnicode(sys.maxsize)

  signatureBase64 = Ecdsa.sign(message=message,
                               privateKey=privateKey2).toBase64()

  signature = Signature.fromBase64(signatureBase64)
  assert(Ecdsa.verify(message=message, signature=signature, publicKey=publicKey2))


def main():
  atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
  atheris.Fuzz()


if __name__ == "__main__":
  main()
