#!/usr/bin/python3
# Copyright 2024 Google LLC
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
from sigstore.models import Bundle

class NullPolicy:
  def verify(self, cert):
      return

def TestOneInput(data):
  fdp = atheris.FuzzedDataProvider(data)

  try:
    bundle = Bundle.from_json(fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(50, 10000)))  
  except Exception as e:
    return

  try:
   verify_artifact(fdp.ConsumeBytes(fdp.ConsumeIntInRange(50, 10000)), bundle, NullPolicy())
  except InvalidBundle:
    pass


def main():
  atheris.instrument_all()
  atheris.Setup(sys.argv, TestOneInput)
  atheris.Fuzz()


if __name__ == "__main__":
  main()
