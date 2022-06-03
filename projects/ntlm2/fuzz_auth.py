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
    import requests
    from requests.exceptions import InvalidURL 
    from requests_ntlm2 import HttpNtlmAuth

def TestInput(data):
    fdp = atheris.FuzzedDataProvider(data)

    session = requests.Session()

    auth = HttpNtlmAuth(fdp.ConsumeString(50),fdp.ConsumeString(10))
    session.auth = HttpNtlmAuth(fdp.ConsumeString(50),fdp.ConsumeString(10))

    try:
       requests.get('http://%s'%fdp.ConsumeString(100), auth=auth)
       session.get('http://%s'%fdp.ConsumeString(100))
    except InvalidURL as e:
       pass

def main(): 
    atheris.Setup(sys.argv, TestInput, enable_python_coverage=True)
    atheris.instrument_all()
    atheris.Fuzz()

if __name__ == "__main__":
  main()
