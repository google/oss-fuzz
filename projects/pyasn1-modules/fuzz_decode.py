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

import pyasn1
from pyasn1.codec.der import decoder as der_decoder

from pyasn1_modules import pem
from pyasn1_modules import rfc5280
from pyasn1_modules import rfc3161

pyasn1_module_list = [
  rfc5280.AlgorithmIdentifier(),
  rfc3161.TimeStampReq()
]

def TestOneInput(data):
  fdp = atheris.FuzzedDataProvider(data)
  
  try:
    substrate = pem.readBase64fromText(fdp.ConsumeUnicodeNoSurrogates(sys.maxsize))
  except:
    return # readBase64 is just a wrapper around base64 so we avoid issues

  identifier = fdp.PickValueInList(pyasn1_module_list)
  try:
    der_decoder.decode(substrate, asnSpec=identifier)
  except pyasn1.error.PyAsn1Error:
    pass


def main():
  atheris.instrument_all()
  atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
  atheris.Fuzz()


if __name__ == "__main__":
  main()
