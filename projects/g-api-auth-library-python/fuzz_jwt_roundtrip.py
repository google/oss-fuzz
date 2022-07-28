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

import os
import sys
import atheris

bundle_dir = getattr(sys, '_MEIPASS', os.path.abspath(os.path.dirname(__file__)))
path_to_public_cert = os.path.abspath(os.path.join(bundle_dir, 'public_cert.pem'))
path_to_private_key = os.path.abspath(os.path.join(bundle_dir, 'privatekey.pem'))

# We instrument all imports below
from google.auth import jwt
from google.auth import crypt

if os.path.isfile(path_to_private_key):
  with open(path_to_private_key, "rb") as fh:
    PRIVATE_KEY_BYTES = fh.read()
else:
  raise Exception("Could not find private key")

if os.path.isfile(path_to_public_cert):
  with open(path_to_public_cert, "rb") as fh:
    PUBLIC_CERT_BYTES = fh.read()
else:
  raise Exception("Could not find public cert")

@atheris.instrument_func
def test_roundtrip_unverified(data):
  fdp = atheris.FuzzedDataProvider(data)
  signer = crypt.RSASigner.from_string(PRIVATE_KEY_BYTES, "1")

  to_header = fdp.ConsumeIntInRange(1, 100)
  if to_header < 50:
    header = None
  else:
    header = {
      "alg" : fdp.ConsumeString(100),
    }
  to_keyid = fdp.ConsumeIntInRange(1, 100)
  raw_data = fdp.ConsumeString(200)

  key_id = fdp.ConsumeString(50) if to_keyid < 50 else None
  encoded = jwt.encode(signer, raw_data, header = header, key_id = key_id)
  try:
    _, decoded_data, _, _ = jwt.decode(encoded, PUBLIC_CERT_BYTES)
  except ValueError as e:
    return


@atheris.instrument_func
def TestOneInput(data):
  test_roundtrip_unverified(data)


def main():
  atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
  atheris.instrument_all()
  atheris.Fuzz()


if __name__ == "__main__":
  main()
