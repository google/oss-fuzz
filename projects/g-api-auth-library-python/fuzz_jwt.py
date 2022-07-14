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

import atheris
import sys

with atheris.instrument_imports():
  from google.auth import jwt
  from google.auth import crypt

if os.path.isfile("privatekey.pem"):
  with open("privatekey.pem", "rb") as fh:
    PRIVATE_KEY_BYTES = fh.read()
else:
  raise Exception("Could not find private key")

if os.path.isfile("public_cert.pem"):
  with open("public_cert.pem", "rb") as fh:
    PUBLIC_CERT_BYTES = fh.read()
else:
  raise Exception("Could not find public cert")


def test_roundtrip_unverified(data):
  fdp = atheris.FuzzedDataProvider(data)
  raw_data = fdp.ConsumeString(200)
  signer = crypt.RSASigner.from_string(PRIVATE_KEY_BYTES, "1")
  encoded = jwt.encode(signer, raw_data)

  _, decoded_data, _, _ = jwt._unverified_decode(encoded)
  assert(raw_data == decoded_data)

def test_token_decode(data):
  fdp = atheris.FuzzedDataProvider(data)
  try:
    jwt.decode(fdp.ConsumeString(200), certs=PUBLIC_CERT_BYTES)
  except ValueError:  # ValueError is thrown if any failed verification checks
    pass

def TestOneInput(data):
  test_roundtrip_unverified(data)
  test_token_decode(data)

def main():
  atheris.instrument_all()
  atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
  atheris.Fuzz()

if __name__ == "__main__":
  main()
