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


def TestOneInput(data):
  if len(data) < 20:
    return
  fdp = atheris.FuzzedDataProvider(data)
  try:
    obj = AES.new(fdp.ConsumeBytes(16), AES.MODE_CBC, 'This is an IV456')
  except ValueError as e:
    if not "Key cannot be the null string" in str(e):
      raise e
    return

  try:
    ciphertext = obj.encrypt(data)
  except ValueError as e:
    if not "Input strings must be a multiple of 16 in length" in str(e):
      raise e


def main():
  atheris.instrument_all()
  atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
  atheris.Fuzz()

if __name__ == "__main__":
  main()
