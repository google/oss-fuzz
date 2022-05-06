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
  import rsa

@atheris.instrument_func
def TestOneInput(input_bytes):
  fdp = atheris.FuzzedDataProvider(input_bytes)
  key = fdp.ConsumeIntInRange(16, 9999)
  message = fdp.ConsumeBytes(atheris.ALL_REMAINING)

  try:
    pub, priv = rsa.newkeys(key)
  except ValueError:
    return

  try:
    encrypted = rsa.encrypt(message, pub)
  except OverflowError:
    return

  decrypted = rsa.decrypt(encrypted, priv)
  assert(decrypted == message)

def main():
  atheris.instrument_all()
  atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
  atheris.Fuzz()


if __name__ == "__main__":
  main()
