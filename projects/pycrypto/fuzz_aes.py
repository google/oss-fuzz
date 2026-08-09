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
  from Crypto.Cipher import AES


@atheris.instrument_func
def TestOneInput(data):
  if len(data) < 40:
    return
  fdp = atheris.FuzzedDataProvider(data)
  key = fdp.ConsumeBytes(16)
  IV = fdp.ConsumeBytes(16)
  enc_data = fdp.ConsumeBytes(atheris.ALL_REMAINING)

  # All modes: https://github.com/pycrypto/pycrypto/blob/7acba5f3a6ff10f1424c309d0d34d2b713233019/lib/Crypto/Cipher/AES.py#L183
  # minus CTR, ECB, PGP (not supported)
  modes = [
    AES.MODE_CBC,
    AES.MODE_CFB,
    AES.MODE_OFB,
    AES.MODE_OPENPGP,
    AES.MODE_CCM,
    AES.MODE_EAX,
    AES.MODE_SIV,
    AES.MODE_GCM
  ]
  for mode in modes:
    try:
      obj = AES.new(key, mode, IV)
    except ValueError as e:
      if not (
        "Key cannot be the null string" in str(e) or
        "Length of parameter" in str(e)
      ):
        raise e
      return

    try:
      ciphertext = obj.encrypt(enc_data)
    except ValueError as e:
      if not "Input strings must be a multiple of 16 in length" in str(e):
        raise e


def main():
  atheris.instrument_all()
  atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
  atheris.Fuzz()

if __name__ == "__main__":
  main()
