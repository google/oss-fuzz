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
  from Crypto.Protocol import AllOrNothing
  from Crypto.Cipher import AES


@atheris.instrument_func
def TestOneInput(data):
  if len(data) < 10:
    return
  for i in range(50):
    a1 = AllOrNothing.AllOrNothing(AES)
    msgblocks = a1.digest(data)
    a2 = AllOrNothing.AllOrNothing(AES)
    round_tripped = a2.undigest(msgblocks)
    assert data == round_tripped


def main():
  atheris.instrument_all()
  atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
  atheris.Fuzz()

if __name__ == "__main__":
  main()
